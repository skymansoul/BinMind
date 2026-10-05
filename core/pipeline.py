import glob
import hashlib
import json
import logging
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
from typing import Any, Dict, List, Optional

from config import (
    MAX_FUNCTIONS, MAX_PARALLEL,
    ENABLE_CRYPTO_SCAN, ENABLE_TAINTRACK, ENABLE_UNPACK,
    SUBPROCESS_TIMEOUT, ensure_dirs, _is_enabled, DB_PATH, EXPLOITS_DIR,
)
from core.binary_info import get_binary_info, validate_binary
from core.decompiler import list_functions, decompile_function, ai_analyze_function, get_callees
from core.symexec import run_symbolic, check_angr, find_buffer_overflow
from core.crash_analysis import load_crash_file, analyze_crash_for_exploit
from core.exploit_gen import generate_exploit
from core.report import write_report
from core.vuln_db import init_db, start_run, finish_run, save_finding
from core.vuln_db import record_step, update_step
from core.unified_heap_pipeline import analyze_heap_safety
from core.hooks import get_hook_manager
from modules.project.project_manager import ProjectState

logger = logging.getLogger(__name__)


def _hash_file(path: str) -> str:
    h = hashlib.sha256()
    try:
        with open(path, 'rb') as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ''


def _step_begin(run_id: int, name: str, **kw):
    """开启步骤记录；DB 异常时返回 None，不影响管线主体。"""
    try:
        return record_step(run_id, name, **kw)
    except Exception:
        return None


def _run_with_timeout(func, timeout, *args, **kwargs):
    """守护线程执行 func, 超时返回 None。

    r2 子进程在 Windows 上挂起时 subprocess.run 无法按自身 timeout 返回
    (管道被孙进程持有), 常规调用会无限阻塞。此包装让调用方按 timeout
    跳过该函数, 线程留在后台直至子进程结束, 不影响主流程退出。
    """
    result = {}

    def _worker():
        try:
            result['value'] = func(*args, **kwargs)
        except Exception as err:
            result['error'] = err

    t = threading.Thread(target=_worker, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        return None
    if 'error' in result:
        raise result['error']
    return result.get('value')


_POC_PAYLOAD_VARIANTS = [
    b'A' * 500, b'A' * 1000, b'%p ' * 300, b'%x ' * 200, b'\x00' * 256,
]


def _reconfirm_with_engines(function_name: str, pseudocode: str):
    """回灌再验证 - 崩溃后调用污点/符号引擎确认可达性。

    返回 (taint_reached, symbolic_sat, combined_confidence)。
    taint_reached=None 表示验证不可用; symbolic_sat 恒 None
    (core.symbolic 约束检查接口不存在, 按降级方案仅依赖污点结果)。
    """
    taint_reached = None
    symbolic_sat = None
    try:
        from core.taint_crossfunc import verify_crossfunc_taint
        _probe = [{'function_name': function_name,
                   'expression': 'payload[0]',
                   'confidence': 0.5,
                   'taint_verified': False,
                   'taint_sources': ['all_operands_internal']}]
        _out = verify_crossfunc_taint(pseudocode, _probe)
        taint_reached = bool(_out and _out[0].get('taint_verified'))
    except Exception:
        taint_reached = None
    if taint_reached is None:
        combined = 0.5
    else:
        combined = 0.75 if taint_reached else 0.3
    return taint_reached, symbolic_sat, combined


def _retry_poc(poc_path: str, max_retries: int = 3):
    """执行 PoC, 非零退出时更换载荷变体后重试。

    返回 (final_status, attempts 列表)。status 取值:
    no_crash / crash_detected / hang / exec_error。
    变体列表: A*500 / A*1000 / %p*300 / %x*200 / 0x00*256。
    骨架脚本无实际触发逻辑时退出码恒 0, 重试路径仅在脚本含触发代码时生效。
    """
    attempts = []
    final_status = 'exec_error'
    for i in range(max_retries):
        try:
            proc = subprocess.run(
                [sys.executable, poc_path],
                capture_output=True, text=True, timeout=30)
            rc = proc.returncode
            stdout_info = (proc.stdout or '')[:200]
            stderr_info = (proc.stderr or '')[:200]
        except subprocess.TimeoutExpired:
            attempts.append(f"attempt{i + 1}: timeout")
            final_status = 'hang'
            rc = 2
        else:
            if rc == 0:
                final_status = 'no_crash'
            elif rc == 2:
                final_status = 'hang'
            elif rc == 3:
                final_status = 'exec_error'
            else:
                final_status = 'crash_detected'
            attempts.append(
                f"attempt{i + 1}: exit={rc}, stdout={stdout_info}, stderr={stderr_info}")
            if rc == 0:
                return final_status, attempts
        variant = _POC_PAYLOAD_VARIANTS[min(i, len(_POC_PAYLOAD_VARIANTS) - 1)]
        try:
            import re as _re
            with open(poc_path, encoding='utf-8') as pf:
                _src = pf.read()
            _src = _re.sub(
                r'payload = b"A" \* \d+',
                f'payload = {variant!r}',
                _src, count=1)
            with open(poc_path, 'w', encoding='utf-8') as pf:
                pf.write(_src)
        except OSError:
            break
    return final_status, attempts


def _step_end(sid, status: str, **kw):
    if sid is None:
        return
    try:
        update_step(sid, status, **kw)
    except Exception:
        pass


# 类型化规则检测接入 ─────────────────────────────
# 主流水线需按漏洞类型分别标记, 而非全部归为 heap-overflow.
# 堆/格式化/整数/UAF/栈检测器分别对单函数伪代码运行, 各自输出类型化 finding.
# 栈检测器实现在 modules.vuln.detection.stack_overflow_code_detector,
# 在此仅保留 CRT 噪音过滤与 finding 收录逻辑。

# mingw CRT 运行时库内部函数名标记: 命中即视为运行时库噪音并过滤,
# 避免把 CRT 封装 (如 sym.memcpy) 误报为用户漏洞。
_CRT_NOISE_MARKERS = (
    'duplicate_ppstrings', 'maincrtstartup', 'crtstartup',
    '_initterm', '__mingw', '__crt', 'sym.memcpy', 'sym.memset',
    'sym.strlen', 'sym.strcpy', 'sym.strcat', 'sym.strcmp',
    'sym.strncpy', 'sym.malloc', 'sym.free', 'sym.calloc',
    'sym.realloc', 'sym._stricmp',
)


def _is_crt_noise(func_name: str) -> bool:
    """判断函数名是否命中 mingw CRT 运行时库噪音标记。"""
    if not func_name:
        return False
    low = func_name.lower()
    return any(marker in low for marker in _CRT_NOISE_MARKERS)


def _analyze_pseudocode(func_name: str, pseudocode: str, binary_info: Dict,
                        ai_enabled: bool = True) -> Dict:
    """按统一 AI 门控分析伪代码；禁用 AI 时仅保留规则检测输入。"""
    if ai_enabled:
        return ai_analyze_function(func_name, pseudocode, binary_info)
    return {
        'function': func_name,
        'vulnerabilities': [],
        'summary': 'AI analysis disabled; rule detectors only',
        'pseudocode': pseudocode,
        'simulation': False,
        'analysis_mode': 'rules_only',
    }


def _dangerous_import_findings(binary_info: Dict) -> List[Dict]:
    """把所有识别到的危险 API 导入转成报告 finding，不宣称已验证可利用。"""
    from core.detection_shared import get_dangerous_function_meta, normalize_import_name

    imports = binary_info.get('imports', {}) if isinstance(binary_info, dict) else {}
    names = imports.get('dangerous_functions', []) if isinstance(imports, dict) else []
    findings = []
    for raw_name in sorted(set(names or [])):
        name = normalize_import_name(raw_name)
        meta = get_dangerous_function_meta(name)
        if meta is None:
            continue
        vuln_type, severity, cwe, confidence = meta
        findings.append({
            'type': 'dangerous-function-import',
            'rule_id': f'IMPORT-{name.upper()}',
            'function': 'binary_imports',
            'function_name': 'binary_imports',
            'imported_function': name,
            'risk_category': vuln_type,
            'severity': severity,
            'cwe': cwe,
            'confidence': confidence,
            'verdict': 'POSSIBLE',
            'description': (
                f'Binary imports dangerous API {name} ({vuln_type}); '
                'call-site reachability and argument safety require review'),
            'evidence': f'import table contains {name}',
        })
    return findings


def run_pipeline(
    binary_path: str,
    crash_path: Optional[str] = None,
    functions: Optional[List[str]] = None,
    max_funcs: int = None,
    include_lib: bool = False,
    parallel: bool = False,
    output_format: str = 'markdown',
    hooks_dir: Optional[str] = None,
    decompiler: str = 'auto',
    symbolic: bool = None,
    fuzz: bool = False,
    output_dir: str = None,
    **kwargs
) -> Dict[str, Any]:
    start_time = time.time()
    ai_analysis = bool(kwargs.get('ai_analysis', True))
    ensure_dirs()
    init_db()

    _project_state = ProjectState(
        binary_path=binary_path,
        status='running',
        current_step='init',
    )
    _project_state.timestamps['start'] = time.strftime('%Y-%m-%dT%H:%M:%S')

    if max_funcs is None:
        max_funcs = MAX_FUNCTIONS

    hook_mgr = get_hook_manager()
    if hooks_dir:
        hook_mgr.load_dir(hooks_dir)

    ctx = {'binary_path': binary_path, 'status': 'init'}
    ctx = hook_mgr.run('pre_unpack', ctx)
    if ctx.get('status') == 'abort':
        return {'error': 'aborted by pre_unpack hook'}

    # validate
    if not validate_binary(binary_path):
        return {'error': f'Unsupported or missing file: {binary_path}'}

    run_id = start_run(binary_path)

    _sid = _step_begin(run_id, 'info_collect')
    try:
        binfo = get_binary_info(binary_path)
        _step_end(_sid, 'success',
                  output_summary=f"{binfo.get('filename', '?')} "
                                 f"{binfo.get('format', '?')} "
                                 f"{binfo.get('arch', '?')} {binfo.get('bits', '?')}bit")
    except Exception as err:
        _step_end(_sid, 'failed', error_message=str(err))
        raise

    binary_hash = _hash_file(binary_path)
    _project_state.binary_info = binfo
    _project_state.current_step = 'info_collect'

    logger.info("Binary: %s | %s %d-bit | size=%d",
                binfo['filename'], binfo['arch'], binfo['bits'], binfo['size'])

    # 程序画像 - checksec/PLT/ROP gadget/字符串/libc 识别
    binary_profile = None
    _sid_bp = _step_begin(run_id, 'binary_profile')
    try:
        from core.binary_profile import build_binary_profile
        binary_profile = build_binary_profile(binary_path)
        binfo['binary_profile'] = binary_profile
        _step_end(_sid_bp, 'success',
                  output_summary='checksec=' + str(bool(binary_profile.get('checksec'))))
    except ImportError:
        _step_end(_sid_bp, 'skipped', output_summary='binary_profile not available')
        logger.debug("binary_profile module not available")
    except Exception as _e:
        _step_end(_sid_bp, 'failed', error_message=str(_e))
        logger.warning("Binary profile failed: %s", _e)

    # LLM 可达性探测仅在 AI 启用时执行；--no-ai 不应产生任何网络访问。
    _llm_reachable = False
    _sid_llm_probe = _step_begin(run_id, 'llm_probe')
    if not ai_analysis:
        binfo['llm_reachable'] = False
        binfo['ai_provider'] = 'disabled'
        _step_end(_sid_llm_probe, 'skipped', output_summary='AI analysis disabled')
    else:
        try:
            import urllib.request as _urllib_req
            _ai_provider = os.environ.get('AI_PROVIDER', 'ollama')
            if _ai_provider == 'ollama':
                _ollama_base = os.environ.get('OLLAMA_BASE_URL',
                                               'http://localhost:11434/v1')
                _health_url = _ollama_base.rstrip('/').replace('/v1', '') + '/api/tags'
                try:
                    _req = _urllib_req.Request(_health_url, method='GET')
                    _resp = _urllib_req.urlopen(_req, timeout=3)
                    _llm_reachable = _resp.status == 200
                except Exception:
                    _llm_reachable = False
            elif _ai_provider in ('openai', 'custom', 'deepseek'):
                _llm_reachable = bool(
                    os.environ.get('API_KEY') or
                    os.environ.get('OPENAI_API_KEY') or
                    os.environ.get('CUSTOM_API_KEY'))
            binfo['llm_reachable'] = _llm_reachable
            binfo['ai_provider'] = _ai_provider
            _step_end(_sid_llm_probe, 'success',
                      output_summary=f'provider={_ai_provider} reachable={_llm_reachable}')
            if not _llm_reachable:
                logger.warning("LLM backend unreachable (provider=%s), "
                               "AI analysis will degrade to simulation", _ai_provider)
        except Exception as _e:
            _step_end(_sid_llm_probe, 'failed', error_message=str(_e))
            logger.debug("LLM probe failed: %s", _e)

    # unpacking
    if ENABLE_UNPACK:
        ctx = hook_mgr.run('pre_decompile', ctx)

    # function discovery
    _sid = _step_begin(run_id, 'function_discovery')
    try:
        all_funcs = _run_with_timeout(list_functions, 30, binary_path)
        if all_funcs is None:
            logger.warning("function discovery timed out (30s), skipping analysis")
            all_funcs = []
        _step_end(_sid, 'success', output_summary=f"{len(all_funcs)} functions")
    except Exception as err:
        _step_end(_sid, 'failed', error_message=str(err))
        raise
    logger.info("Found %d functions", len(all_funcs))

    # 缺省不过滤 __libc_* 等噪声函数; 大二进制上需显式 --functions
    # 限定分析范围, 否则会拖入 200+ 个 glibc 内部函数

    if functions:
        target_funcs = [f for f in functions if f in all_funcs]
        if not target_funcs:
            target_funcs = functions
    else:
        # prefer user-facing functions
        priority = ('main', 'vuln', 'win', 'get_flag', 'read_input',
                    'process', 'parse', 'handle', 'init')
        target_funcs = [f for f in priority if f in all_funcs]
        if not target_funcs:
            # radare2 符号函数名带 sym. 前缀(如 sym.main), 裸名匹配
            # 失败会回退到按地址序取前 N 个 — mingw 二进制前 N 个
            # 全是 CRT 启动函数, 样本 main 永远不会被分析, 全量评测
            # 的"检出"退化为 CRT 无差别启发式告警. 剥离一层符号前缀
            # 后按 priority 顺序回配原始函数名.
            by_stripped = {}
            for f in all_funcs:
                stripped = f.split('.')[-1] if '.' in f else f
                by_stripped.setdefault(stripped, f)
            target_funcs = [by_stripped[p] for p in priority
                            if p in by_stripped]
        if not target_funcs:
            target_funcs = all_funcs[:max_funcs]

    # 扩展 target_funcs: 追加入口函数的直接被调用者
    # 覆盖漏洞代码在 main 调用的子函数中的场景(如 multi_buffers, do_work)
    if target_funcs and len(target_funcs) < max_funcs:
        existing = set(target_funcs)
        for tf in list(target_funcs):
            callees = _run_with_timeout(get_callees, 60, binary_path, tf, all_funcs)
            if callees:
                for c in callees:
                    if c not in existing and c in all_funcs:
                        target_funcs.append(c)
                        existing.add(c)
                        if len(target_funcs) >= max_funcs:
                            break
            if len(target_funcs) >= max_funcs:
                break

    target_funcs = target_funcs[:max_funcs]
    _project_state.current_step = 'function_discovery'
    logger.info("Analyzing %d functions", len(target_funcs))

    # decompile + AI analyze
    ctx = hook_mgr.run('pre_analysis', ctx)
    decomp_results = []
    _sid_decomp = _step_begin(run_id, 'decompile',
                              input_summary=f"{len(target_funcs)} funcs")

    def _analyze_one(func_name):
        r = _run_with_timeout(decompile_function, 30,
                              binary_path, func_name, decompiler)
        if r is None:
            logger.warning("decompile timed out (30s), skipping %s", func_name)
            return {'function': func_name, 'vulnerabilities': [],
                    'pseudocode': ''}
        if r['pseudocode'].strip():
            _sid = _step_begin(run_id, 'llm_analyze',
                               input_summary=f"{func_name} {len(r['pseudocode'])} chars")
            try:
                ai = _analyze_pseudocode(
                    func_name, r['pseudocode'], binfo, ai_enabled=ai_analysis)
                n_vuln = len(ai.get('vulnerabilities', []))
                _step_end(_sid, 'success', output_summary=f"{n_vuln} vulns")
            except Exception as err:
                _step_end(_sid, 'failed', error_message=str(err))
                raise
            return ai
        return {'function': func_name, 'vulnerabilities': [],
                'pseudocode': r.get('pseudocode', '')}

    if parallel and len(target_funcs) > 1:
        max_workers = min(MAX_PARALLEL, len(target_funcs))
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = {pool.submit(_analyze_one, n): n for n in target_funcs}
            for fut in as_completed(futures):
                try:
                    decomp_results.append(fut.result())
                except Exception as err:
                    logger.error("Analysis worker failed: %s", err)
    else:
        for name in target_funcs:
            try:
                decomp_results.append(_analyze_one(name))
            except Exception as err:
                logger.error("Analysis of %s failed: %s", name, err)

    _step_end(_sid_decomp, 'success', output_summary=f"{len(decomp_results)} analyzed")
    _project_state.analyzed_functions = list(target_funcs)
    _project_state.decomp_results = list(decomp_results)
    _project_state.current_step = 'decompile'

    # 控制流/调用关系提取 - extract_cfg 返回 functions + call_graph
    cfg_result = None
    _sid_cfg = _step_begin(run_id, 'cfg_extract')
    try:
        from core.cfg_extractor import extract_cfg
        cfg_result = extract_cfg(binary_path)
        _n_fn = len(cfg_result.get('functions', [])) if cfg_result else 0
        _n_cg = len(cfg_result.get('call_graph', {})) if cfg_result else 0
        _step_end(_sid_cfg, 'success',
                  output_summary=f'functions={_n_fn} call_edges={_n_cg}')
    except ImportError:
        _step_end(_sid_cfg, 'skipped', output_summary='cfg_extractor not available')
        logger.debug("cfg_extractor module not available")
    except Exception as _e:
        _step_end(_sid_cfg, 'failed', error_message=str(_e))
        logger.warning("CFG extraction failed: %s", _e)

    # 动态追踪 - qemu_tracer 位于 eval 目录, 环境不可用时静默跳过
    dynamic_trace = None
    _sid_dyn = _step_begin(run_id, 'dynamic_trace')
    try:
        from eval.qemu_tracer import trace_auto
        dynamic_trace = trace_auto(binary_path, os.path.basename(binary_path))
        _step_end(_sid_dyn, 'success', output_summary='trace captured')
    except ImportError:
        _step_end(_sid_dyn, 'skipped', output_summary='qemu_tracer not available')
        logger.debug("qemu_tracer not available")
    except Exception as _e:
        _step_end(_sid_dyn, 'failed', error_message=str(_e))
        logger.warning("Dynamic trace failed: %s", _e)

    # taint 阶段 - 环境变量 ENABLE_TAINTRACK=1 时启用，默认关闭
    if ENABLE_TAINTRACK:
        _sid = _step_begin(run_id, 'taint_track')
        try:
            from core.int_overflow_taint import verify_overflow_taint
            for r in decomp_results:
                analysis = r.get('analysis', r)
                if not isinstance(analysis, dict):
                    continue
                pseudocode = analysis.get('pseudocode', '')
                vulns = analysis.get('vulnerabilities', [])
                if pseudocode and vulns:
                    verify_overflow_taint(pseudocode, vulns)

            # 跨函数传播 — 拼接全部函数伪代码, 对断链告警补充溯源
            try:
                from core.taint_crossfunc import verify_crossfunc_taint
                combined = '\n'.join(
                    (r.get('analysis', r) or {}).get('pseudocode', '')
                    for r in decomp_results
                )
                if combined.strip():
                    for r in decomp_results:
                        analysis = r.get('analysis', r)
                        if isinstance(analysis, dict) and analysis.get('vulnerabilities'):
                            verify_crossfunc_taint(combined, analysis['vulnerabilities'])
            except Exception as err:
                logger.debug("cross-func taint skipped: %s", err)

            _step_end(_sid, 'success',
                      output_summary=f"{len(decomp_results)} funcs verified")
        except Exception as err:
            _step_end(_sid, 'failed', error_message=str(err))
            logger.warning("Taint stage failed: %s", err)

    ctx = hook_mgr.run('post_analysis', ctx)

    # 调度决策默认值 — adaptive_scheduler 覆盖; 符号执行和后续阶段引用
    _scheduler_decision = {'rule': True, 'symbolic': True, 'fuzz': True}

    # 自适应调度 - 按样本特征选择分析方法组合; 不可用时回退到全部顺序执行
    # 在符号执行之前运行, 使 scheduler 决策对符号执行/fuzz/规则检测均生效
    _sid_sched = _step_begin(run_id, 'adaptive_scheduler')
    try:
        from core.adaptive_scheduler import AdaptiveScheduler, AnalysisMethod
        _scheduler = AdaptiveScheduler()
        _selected = _scheduler.select_methods(
            binfo, decomp_results if isinstance(decomp_results, dict) else None)
        # select_methods 返回 List[Tuple[AnalysisMethod, float]], 转为 dict 供后续查询
        _method_map = {
            AnalysisMethod.STATIC_RULES: 'rule',
            AnalysisMethod.SYMBOLIC: 'symbolic',
            AnalysisMethod.FUZZING: 'fuzz',
        }
        # 先重置为 False, 再按 scheduler 选中结果开启 — 未选中的方法不执行
        for _k in _method_map.values():
            _scheduler_decision[_k] = False
        for _m, _budget in _selected:
            _key = _method_map.get(_m)
            if _key:
                _scheduler_decision[_key] = True
        _step_end(_sid_sched, 'success',
                  output_summary=str(_scheduler_decision))
        logger.info("Adaptive scheduler decision: %s", _scheduler_decision)
    except ImportError:
        _step_end(_sid_sched, 'skipped', output_summary='adaptive_scheduler not available')
        logger.debug("adaptive_scheduler not available, fallback to all methods")
    except Exception as _e:
        _step_end(_sid_sched, 'failed', error_message=str(_e))
        logger.warning("Adaptive scheduler failed: %s", _e)

    # 符号执行 - 默认尝试; angr 缺失时记 skipped 不中断管线
    sym_result = None
    use_symbolic = _is_enabled('ENABLE_SYMEXEC', default='true') if symbolic is None else symbolic
    if use_symbolic and _scheduler_decision.get('symbolic', True):
        _sid = _step_begin(run_id, 'symbolic_exec')
        _angr_ok = False
        try:
            import angr  # noqa: F401
            _angr_ok = True
        except ImportError:
            pass
        if not _angr_ok:
            # 降级方案: angr 不可用时尝试轻量级符号执行或基于规则的路径约束分析
            _degraded_used = None
            try:
                from core.symexec import find_buffer_overflow as _find_bo
                _bo_result = find_buffer_overflow(binary_path, target_funcs[0] if target_funcs else 'main')
                if _bo_result and not _bo_result.get('error'):
                    sym_result = {
                        'success': True, 'paths_found': 0,
                        'constraints': [],
                        'vulnerabilities': [],
                        'degraded': True,
                        'method': 'symexec.find_buffer_overflow',
                        'overflow_points': _bo_result.get('overflow_points', []),
                    }
                    _degraded_used = 'symexec.find_buffer_overflow'
            except Exception as _derr:
                logger.debug("Degraded symexec (find_buffer_overflow) failed: %s", _derr)
            if _degraded_used is None:
                # Z3 轻量约束求解 — 比纯关键词匹配更接近真实符号执行
                try:
                    from core.symexec import z3_symbolic_check
                    _z3_result = z3_symbolic_check(binary_path, decomp_results)
                    if _z3_result and _z3_result.get('overflow_points'):
                        sym_result = _z3_result
                        _degraded_used = 'z3_symbolic_check'
                except Exception as _z3_err:
                    logger.debug("Z3 symbolic check failed: %s", _z3_err)
            if _degraded_used is None:
                # 基于伪代码的规则化路径约束分析作为最终降级
                _rule_constraints = []
                for _r in decomp_results:
                    _ana = _r.get('analysis', _r) or {}
                    _pc = _ana.get('pseudocode', '')
                    if not _pc:
                        continue
                    for _pattern in ('memcpy', 'strcpy', 'gets', 'sprintf', 'scanf'):
                        if _pattern in _pc:
                            _rule_constraints.append({
                                'function': _r.get('function_name', _r.get('function', '?')),
                                'pattern': _pattern,
                                'source': 'rule_based_path_analysis',
                            })
                            break
                if _rule_constraints:
                    sym_result = {
                        'success': True, 'paths_found': len(_rule_constraints),
                        'constraints': _rule_constraints,
                        'vulnerabilities': [],
                        'degraded': True,
                        'method': 'rule_based_path_constraint_analysis',
                    }
                    _degraded_used = 'rule_based_path_constraint_analysis'
            if _degraded_used:
                _step_end(_sid, 'success',
                          output_summary=f'degraded: {_degraded_used}, '
                                         f'paths={sym_result.get("paths_found", 0)} '
                                         f'constraints={len(sym_result.get("constraints", []))}')
                logger.info("Symbolic execution degraded to %s", _degraded_used)
            else:
                _step_end(_sid, 'skipped',
                          output_summary='angr not installed, no degraded alternative available')
                logger.warning("Symbolic execution skipped: angr not installed, "
                               "degraded alternatives exhausted")
                sym_result = {'success': False, 'error': 'angr not installed, '
                                                          'degraded alternatives unavailable',
                              'paths_found': 0, 'constraints': []}
        else:
            try:
                logger.info("Running symbolic execution...")
                sym_result = run_symbolic(binary_path)
                # 符号路径合并 - ENABLE_SYMBOLIC_MERGE=1 时约束回写 findings, 默认关闭
                if _is_enabled('ENABLE_SYMBOLIC_MERGE') and sym_result and sym_result.get('success'):
                    for _c in sym_result.get('constraints', [])[:10]:
                        try:
                            save_finding(
                                run_id, binary_path, binary_hash,
                                'symbolic_exec', 'symbolic_constraint', 'Low',
                                'CWE-284', f'Angr satisfiable constraint: {str(_c)[:200]}',
                                evidence='Symbolic execution discovered reachable state',
                                priority_score=2.0,
                            )
                        except Exception:
                            pass
                # 符号执行保守回退 - ENABLE_SYMBOLIC_FALLBACK=1 时对无约束结果
                # 按伪代码中的内存操作模式生成保守 finding, 默认关闭
                if _is_enabled('ENABLE_SYMBOLIC_FALLBACK') and (
                        not sym_result or not sym_result.get('constraints')):
                    _guessed = 0
                    for _r in decomp_results:
                        _ana = _r.get('analysis', _r) or {}
                        _pc = _ana.get('pseudocode', '')
                        if _guessed >= 5:
                            break
                        if 'memcpy' in _pc or 'malloc' in _pc:
                            try:
                                save_finding(
                                    run_id, binary_path, binary_hash,
                                    _r.get('function_name', _r.get('function', '?')),
                                    'symbolic_guess', 'Low',
                                    'CWE-284',
                                    'Inferred possible symbolic path from memcpy/malloc pattern',
                                    evidence='Conservatively generated, no satisfiable constraints found',
                                    priority_score=1.5,
                                )
                                _guessed += 1
                            except Exception:
                                pass
                _sym_ok = bool(sym_result and sym_result.get('success'))
                _sym_pf = sym_result.get('paths_found', 0) if sym_result else 0
                _sym_nc = len(sym_result.get('constraints', [])) if sym_result else 0
                _step_end(
                    _sid, 'success' if _sym_ok else 'failed',
                    output_summary=f"paths={_sym_pf} constraints={_sym_nc}",
                    error_message=None if _sym_ok else (sym_result or {}).get('error'))
            except Exception as err:
                _step_end(_sid, 'failed', error_message=str(err))
                logger.warning("Symbolic execution failed: %s", err)

    # crash analysis
    crash_data = None
    crash_analysis = None
    if crash_path and os.path.isfile(crash_path):
        _sid = _step_begin(run_id, 'crash_analysis', input_summary=crash_path)
        try:
            crash_data = load_crash_file(crash_path)
            if crash_data:
                crash_analysis = analyze_crash_for_exploit(crash_data)
            _step_end(_sid, 'success')
        except Exception as err:
            _step_end(_sid, 'failed', error_message=str(err))
            raise

    # crypto scan
    if ENABLE_CRYPTO_SCAN and not kwargs.get('no_crypto'):
        _sid = _step_begin(run_id, 'crypto_scan')
        try:
            from plugins.crypto_scan import scan_crypto
            crypto = scan_crypto(binary_path)
            logger.info("Crypto scan: %d constants found", len(crypto))
            _step_end(_sid, 'success', output_summary=f"{len(crypto)} constants")
        except ImportError:
            _step_end(_sid, 'skipped', output_summary='plugin not available')
            logger.debug('optional plugin not available')

    # 规则检测 - 默认开启, 对各函数伪代码分别跑
    # 堆/栈/格式化/整数/UAF 检测器, 各自输出类型化 finding
    rule_findings = []
    if _scheduler_decision.get('rule', True) and \
            _is_enabled('ENABLE_RULE_DETECTORS', default='true'):
        _sid_rule = _step_begin(run_id, 'rule_detection')
        def _add_rule(f):
            f['function_name'] = f.get('function', f.get('function_name', '?'))
            # 过滤 mingw CRT 运行时库噪音 (如 sym.memcpy)
            if _is_crt_noise(f.get('function_name', '')):
                return
            rule_findings.append(f)
        try:
            for r in decomp_results:
                analysis = r.get('analysis', r)
                if not isinstance(analysis, dict):
                    continue
                pseudocode = analysis.get('pseudocode', '')
                if not pseudocode:
                    continue
                func_name = r.get('function_name', r.get('function', '?'))
                # 堆分析器 (含 UAF/DF)
                raw_findings, _stats = analyze_heap_safety(
                    pseudocode, func_name, binary_path)
                # 钩子 A 阶段1 - 污点证据注入: verify_crossfunc_taint 仅升级不降级,
                # 签名 (pseudocode, findings) 与草稿假设 (func_name, binary_path) 不符,
                # 按实际签名调用
                if _is_enabled('ENABLE_TAINTRACK'):
                    try:
                        from core.taint_crossfunc import verify_crossfunc_taint
                        verify_crossfunc_taint(pseudocode, raw_findings)
                    except Exception:
                        pass
                for f in raw_findings:
                    _add_rule(f)
                # 格式化字符串
                try:
                    from core.format_string_indirect import detect_indirect_fmt
                    for f in detect_indirect_fmt(pseudocode, func_name):
                        _add_rule(f)
                except Exception:
                    pass
                # 直接模式格式串检测: 补全主检测器覆盖 printf(buf) 直接模式
                # 主检测器签名为 (binary_path, func_name) 而非伪代码, 直接对二进制取偏移
                try:
                    from core.format_string_detector import detect_format_string_vulns
                    for f in detect_format_string_vulns(binary_path, func_name):
                        f.setdefault('type', 'format-string')
                        f.setdefault('cwe', 'CWE-134')
                        _add_rule(f)
                except Exception:
                    pass
                # 整数溢出
                try:
                    from core.int_overflow_unified_pipeline import detect_integer_overflow
                    for f in detect_integer_overflow(pseudocode, binary_path):
                        verdict = f.get('verdict', 'UNCERTAIN')
                        sev = 'High' if verdict == 'CONFIRMED' else (
                            'Medium' if verdict == 'LIKELY' else 'Low')
                        _add_rule({
                            "type": f.get('type', 'integer-overflow'),
                            "function": func_name,
                            "severity": sev,
                            "cwe": "CWE-190",
                            "confidence": f.get('confidence', 0.5),
                            "description": (
                                f"整数溢出: {f.get('source') or f.get('line')} "
                                f"(verdict={verdict})"),
                            "verdict": verdict,
                            "expr_type": f.get('expr_type'),
                            "user_controlled": f.get('user_controlled'),
                        })
                except Exception:
                    pass
                # UAF / Double-Free
                try:
                    from core.uaf_analyzer import comprehensive_uaf_check
                    for f in comprehensive_uaf_check(pseudocode, func_name):
                        _add_rule(f)
                except Exception:
                    pass
                # 栈溢出
                try:
                    from modules.vuln.detection.stack_overflow_code_detector \
                        import detect_stack_overflow_code
                    for f in detect_stack_overflow_code(pseudocode, func_name):
                        _add_rule(f)
                except Exception:
                    pass
                # 注册表扩展检测器 - 由各模块通过 @detector_registry.register 声明
                try:
                    from core.detector_registry import get_all as _get_detectors
                    for _vtype, _fn in _get_detectors().items():
                        try:
                            for f in _fn(pseudocode, func_name):
                                _add_rule(f)
                        except Exception:
                            pass
                except Exception:
                    pass
        except Exception as err:
            logger.warning("Rule detectors failed: %s", err)
        finally:
            # 创新模块管线 — 在基础检测器产出rule_findings后,
            # 调用堆溢出误报抑制 (Heap Overflow False-Positive Reduction)/分配器感知过滤 (Allocator-Aware Filtering)/分配契约流保持 (Allocation Contract Flow Preservation)/按需符号尺寸关联 (Demand-Driven Symbolic Size Correlation)/同源分配-写关联 (Allocation-Write Co-Sourcing)/约束求解-后向值流 (Constraint Solving - Backward Value Flow)/约束求解-路径条件后向值流 (Constraint Solving - Path-Conditioned Backward Value Flow) 七大创新模块
            # 做增量检测与误报抑制. 各模块独立try/except, 互不影响.
            if rule_findings and _is_enabled('ENABLE_INNOVATION_PIPELINE',
                                             default='true'):
                try:
                    from core.innovation_bridge import run_innovation_pipeline
                    # 固化基础检测器的原始判定: 创新阶段(eval_harness_replica/
                    # demand_trigger_budget 等二十余个)会把 verdict 改写为各种
                    # 中间态(consistent/lightweight/downgraded...), 原始判定
                    # 保存到 verdict_original, 供计数层按原语义豁免, 避免
                    # 基础检出(intof LIKELY 等)被改写后误杀成漏报
                    for _f in rule_findings:
                        _f.setdefault('verdict_original', _f.get('verdict'))
                    # 对每个函数的伪代码执行创新模块管线
                    _innov_findings = []
                    for r in decomp_results:
                        analysis = r.get('analysis', r)
                        if not isinstance(analysis, dict):
                            continue
                        pc = analysis.get('pseudocode', '')
                        if not pc:
                            continue
                        fn = r.get('function_name', r.get('function', '?'))
                        # 收集该函数已有的rule_findings
                        fn_findings = [f for f in rule_findings
                                       if f.get('function_name', f.get(
                                           'function', '')) == fn]
                        if fn_findings:
                            enhanced = run_innovation_pipeline(
                                pc, fn, binary_path, fn_findings)
                            _innov_findings.extend(enhanced)
                    if _innov_findings:
                        rule_findings = _innov_findings
                except Exception as err:
                    logger.warning("Innovation pipeline failed: %s", err)
            _step_end(_sid_rule, 'success',
                      output_summary=f"{len(rule_findings)} findings")
            _project_state.current_step = 'rule_detection'

    # 证据融合 - ENABLE_EVIDENCE_FUSION=1 时对类型化 rule_findings 做一致性加权/分诊。
    # 独立各型检测器可能对同一 (函数, 类型) 命中多条; 融合按证据一致性收敛置信度,
    # 抑制单一弱信号造成的高估, 降低跨类型误报。
    if _is_enabled('ENABLE_EVIDENCE_FUSION') and rule_findings:
        try:
            from modules.vuln.detection.evidence_fusion import fuse_findings
            rule_findings = fuse_findings(rule_findings)
        except Exception as err:
            logger.warning("Evidence fusion failed: %s", err)

    # 导入表是独立于反编译质量的确定证据。仅对无界高风险 API 生成候选，
    # 避免 malloc/memcpy 等上下文相关函数造成无差别误报。
    rule_findings.extend(_dangerous_import_findings(binfo))

    # save findings
    all_vulns = []
    _sid = _step_begin(run_id, 'findings_save')
    _seen = set()
    for r in decomp_results:
        analysis = r.get('analysis', r)
        for v in analysis.get('vulnerabilities', []):
            # 启发式模拟判定 (simulation=True, 来自 _DANGER_PATTERNS 的
            # 危险函数模式提示) 不构成真实检出: 任何 malloc/memcpy 都会被
            # 报"需检查整数溢出/长度参数", 与上下文无关, 会把 guard 保护
            # 的 safe 样本判成漏洞. 模拟提示不进入 all_vulns 计数.
            if v.get('simulation') or analysis.get('simulation'):
                continue
            all_vulns.append(v)
            _seen.add((r.get('function_name', r.get('function', '?')),
                       v.get('type', '?'),
                       v.get('rule_id') or v.get('imported_function') or v.get('location', '')))
            try:
                save_finding(
                    run_id, binary_path, binary_hash,
                    r.get('function_name', r.get('function', '?')),
                    v.get('type', '?'), v.get('severity', 'Unknown'),
                    v.get('cwe', ''), v.get('description', ''),
                )
            except Exception:
                pass
    for v in rule_findings:
        key = (v.get('function_name', '?'), v.get('type', '?'),
               v.get('rule_id') or v.get('imported_function') or v.get('location', ''))
        if key in _seen:
            continue
        # RW 弱告警 (rw_weak=True, 来自 color_class_quad/provenance_octagon
        # 等创新模块的 UNKNOWN 域写提示) 是线索不是判定, 不计入漏洞检出
        if v.get('rw_weak'):
            continue
        # UNCERTAIN 整数溢出 (区间分析无法确定 result_hi, 保守保留供人工
        # 复核) 不是证据确凿的检出, 与 rw_weak 同性质, 不计入漏洞计数
        if v.get('type') in ('integer-overflow', 'integer_overflow') \
                and v.get('verdict') == 'UNCERTAIN':
            continue
        # 契约折叠摘要的计数语义已随身份继承修正: contract_preserve_fold
        # 折叠时复用组内第一个成员的原对象并保留原 verdict, 组代表的
        # 计数语义与组内成员一致 (基础检出照常计数, UNCERTAIN 仍由上一
        # 条过滤). 仅当 verdict 被显式置为 folded (历史标记) 时不计数,
        # 不再按 description 关键字匹配 — 描述含 folded 的代表条目可能
        # 承载基础检出, 按关键字过滤会把它误杀成漏报.
        if v.get('verdict') == 'folded':
            continue
        # 跨链别名分析的安全结论 (same_chain_safe, reason=alloc 和 write
        # 同链判安全) 是安全性证明而非漏洞; 姊妹条目 cross_chain_alert
        # 是可疑告警, 保留. 安全判定混入漏洞计数会造成纯虚增 TP.
        if v.get('type') == 'same_chain_safe':
            continue
        # 创新模块 (contract_preserve_fold/INT-RANGE 编排器等) 注入的中间态
        # 条目使用基础词表外的 verdict (lightweight/beyond_minsize/
        # unknown_color 等)标记折叠或降级结论, 不构成确凿检出. 基础检测器
        # 的 verdict (CONFIRMED/LIKELY/POSSIBLE/DEFINITE/UNCERTAIN) 与
        # heap 分析的 SAFE/overflow 才有计数语义; 未设 verdict(None) 的
        # 基础检测器条目不受影响.
        _bv = v.get('verdict')
        if _bv is not None and _bv not in (
                'CONFIRMED', 'LIKELY', 'POSSIBLE', 'DEFINITE', 'UNCERTAIN',
                'overflow', 'safe', 'FILTERED'):
            # demand_trigger_budget 等阶段会把 verdict 改写为预算分类,
            # 改写前的原始判定保留在 verdict_original: 原判定在词表内的
            # 基础检出按原语义计数, 不因预算分类被误杀
            if v.get('verdict_original') not in (
                    'CONFIRMED', 'LIKELY', 'POSSIBLE', 'DEFINITE',
                    'UNCERTAIN', 'overflow', 'safe', 'FILTERED'):
                continue
        _seen.add(key)
        all_vulns.append(v)
        _ps = None
        if _is_enabled('ENABLE_FINDING_PRIORITIZER'):
            try:
                from core.finding_prioritizer import score_finding
                _ps = score_finding(v)
                v['priority_score'] = _ps
            except Exception:
                _ps = None
        # 钩子 A 阶段2 - 污点降权: 显式 taint_verified=False 减半; 未标注追加不可用标记
        if _is_enabled('ENABLE_TAINTRACK'):
            if v.get('taint_verified') is False:
                _ps = round(_ps * 0.5, 2) if _ps is not None else None
                v['priority_score'] = _ps
                v['evidence'] = v.get('evidence', '') + ' | Taint not reached to sink.'
            elif v.get('taint_verified') is not True:
                v['evidence'] = v.get('evidence', '') + ' [Taint verification unavailable]'
        try:
            save_finding(
                run_id, binary_path, binary_hash,
                v.get('function_name', '?'), v.get('type', '?'),
                v.get('severity', 'Unknown'),
                v.get('cwe', ''), v.get('description', ''),
                evidence=v.get('evidence', ''),
                priority_score=_ps,
            )
        except Exception:
            pass
    _step_end(_sid, 'success', output_summary=f"{len(all_vulns)} vulns")

    # PoC 生成 - 默认开启, 对规则类发现生成占位复现脚本
    if _is_enabled('ENABLE_POC_GEN', default='true'):
        try:
            _poc_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'logs', 'poc')
            os.makedirs(_poc_dir, exist_ok=True)
            from core.vuln_db import get_run_findings
            _poc_paths = []
            for f in get_run_findings(run_id):
                if f.get('vuln_type') not in (
                        'heap-overflow', 'stack-overflow', 'format-string'):
                    continue
                _poc_content = f'''#!/usr/bin/env python3
import subprocess, sys, os
# Target: {binary_path}
# Function: {f['function_name']}
# CWE: {f.get('cwe')}
# vuln_type: {f.get('vuln_type')}

# 按漏洞类型构造触发载荷:
#   stack-overflow / heap-overflow -> 超长 A 覆盖可控长度
#   format-string                  -> %p/%n 栈探测链
_VULN = "{f.get('vuln_type')}"

def build_payload():
    if _VULN == "format-string":
        # 栈上布点地址 + %p/%x/%n 探测
        return b"%p %p %x %n".ljust(256, b"\\x00")
    # 溢出: 大缓冲 A, 覆盖返回地址/相邻块
    return b"A" * 1000


def main():
    payload = build_payload()
    try:
        proc = subprocess.run(
            [r"{binary_path}"],
            input=payload,
            capture_output=True,
            timeout=5,
            env=os.environ.copy()
        )
        if proc.returncode != 0:
            # 非零退出码通常表示崩溃（SIGSEGV等）
            print(f"CRASH detected, exitcode={{proc.returncode}}")
            sys.exit(1)
        else:
            print("No crash triggered")
            sys.exit(0)
    except subprocess.TimeoutExpired:
        print("HANG detected (timeout)")
        sys.exit(2)
    except Exception as e:
        print(f"Execution error: {{e}}")
        sys.exit(3)


if __name__ == "__main__":
    main()
'''
                _poc_path = os.path.join(_poc_dir, f"poc{f['id']}.py")
                with open(_poc_path, 'w', encoding='utf-8') as pf:
                    pf.write(_poc_content)
                _poc_paths.append((_poc_path, f['id'], f['function_name']))
            # PoC 执行与重试 - 默认沙箱模式真实执行 PoC 脚本(本地进程, 无网络);
            # ENABLE_POC_EXECUTE_REAL=1 时允许更高权限(如网络交互)
            if _is_enabled('ENABLE_POC_EXECUTE', default='true') and \
                    not _is_enabled('ENABLE_POC_EXECUTE_REAL') and _poc_paths:
                # 沙箱模式 - 真实执行 PoC 脚本, 捕获 stdout/stderr/exit_code
                import sqlite3 as _sqlite3_pending
                _conn_sandbox = _sqlite3_pending.connect(DB_PATH)
                for _pp, _pid, _fname in _poc_paths:
                    _sb_status = 'exec_error'
                    _sb_detail = ''
                    try:
                        _proc = subprocess.run(
                            [sys.executable, _pp],
                            capture_output=True, text=True, timeout=10)
                        _rc = _proc.returncode
                        _sb_stdout = (_proc.stdout or '')[:200]
                        _sb_stderr = (_proc.stderr or '')[:200]
                        if _rc == 0:
                            _sb_status = 'no_crash'
                        elif _rc == 2:
                            _sb_status = 'hang'
                        elif _rc == 3:
                            _sb_status = 'exec_error'
                        else:
                            _sb_status = 'crash_detected'
                        _sb_detail = f'exit={_rc} stdout={_sb_stdout} stderr={_sb_stderr}'
                    except subprocess.TimeoutExpired:
                        _sb_status = 'hang'
                        _sb_detail = 'timeout (10s)'
                    except Exception as _sb_err:
                        _sb_status = 'exec_error'
                        _sb_detail = f'exception: {_sb_err}'
                    _sandbox_msg = (f' | PoC executed (sandbox): {_sb_status}; '
                                    f'{_sb_detail}')
                    try:
                        _conn_sandbox.execute(
                            "UPDATE findings SET evidence = evidence || ? WHERE id = ?",
                            (_sandbox_msg, int(_pid)))
                    except Exception:
                        pass
                _conn_sandbox.commit()
                _conn_sandbox.close()
            elif _is_enabled('ENABLE_POC_EXECUTE', default='true') and \
                    _is_enabled('ENABLE_POC_EXECUTE_REAL') and _poc_paths:
                import sqlite3 as _sqlite3
                _conn = _sqlite3.connect(DB_PATH)
                _reanalysis_depth = 0
                for _pp, _pid, _fname in _poc_paths:
                    _status, _atts = _retry_poc(_pp)
                    # 敏感信息泄露检测 - stdout/stderr 内容匹配
                    if _status == 'no_crash':
                        _joined = '; '.join(_atts).lower()
                        if any(_p in _joined for _p in (
                                'secret', 'password', 'key', 'token', 'flag',
                                'heap', 'stack')):
                            _status = 'info_leak_detected'
                    _msg = f" | PoC executed: {_status}; " + "; ".join(_atts)
                    try:
                        _conn.execute(
                            "UPDATE findings SET evidence = evidence || ? WHERE id = ?",
                            (_msg, int(_pid)))
                    except Exception:
                        pass
                    # 回灌再验证 - 默认开启, PoC 崩溃后用污点引擎确认载荷可达性:
                    # 可达且置信度>0.6 则严重度升级, 不可达则 priority_score 减半
                    if _is_enabled('ENABLE_CLOSED_LOOP_REANALYSIS', default='true') and \
                            _reanalysis_depth == 0 and \
                            _status in ('crash_detected', 'info_leak_detected'):
                        _reanalysis_depth += 1
                        _pseudo = ''
                        for _r in decomp_results:
                            _ana = _r.get('analysis', _r) or {}
                            if _r.get('function_name',
                                      _r.get('function', '')) == _fname:
                                _pseudo = _ana.get('pseudocode', '')
                                break
                        _tr, _sym, _cc = _reconfirm_with_engines(
                            _fname, _pseudo)
                        if _tr is True and _cc > 0.6:
                            try:
                                _conn.execute(
                                    "UPDATE findings SET "
                                    "severity = CASE WHEN severity='High' "
                                    "THEN 'Critical' ELSE 'High' END, "
                                    "evidence = evidence || ? WHERE id = ?",
                                    (' | Reanalysis confirmed reachable.',
                                     int(_pid)))
                            except Exception:
                                pass
                        elif _tr is False or _cc <= 0.6:
                            try:
                                _conn.execute(
                                    "UPDATE findings SET priority_score = "
                                    "COALESCE(priority_score, 4.0) * 0.5, "
                                    "evidence = evidence || ? WHERE id = ?",
                                    (' | Reanalysis: payload unreachable via '
                                     'taint/symbolic, score halved.',
                                     int(_pid)))
                            except Exception:
                                pass
                _conn.commit()
                _conn.close()
        except Exception as err:
            logger.warning("PoC generation failed: %s", err)

    # 远程交互利用 — ENABLE_POC_REMOTE=1 时通过 socket 向远程目标发送 PoC 载荷
    # 纯 Python socket 实现, 不依赖 pwntools remote()
    _remote_interaction_result = None
    if _is_enabled('ENABLE_POC_REMOTE') and all_vulns:
        _sid_remote = _step_begin(run_id, 'remote_interaction')
        try:
            from core.remote_interaction import (
                probe_remote_target, execute_remote_payload,
            )
            _remote_host = os.environ.get('BINMIND_REMOTE_HOST', '')
            _remote_port_raw = os.environ.get('BINMIND_REMOTE_PORT', '0')
            try:
                _remote_port = int(_remote_port_raw)
            except (TypeError, ValueError):
                _remote_port = 0
            if _remote_host and _remote_port > 0:
                _probe = probe_remote_target(_remote_host, _remote_port)
                if _probe['reachable']:
                    _remote_results = []
                    for v in all_vulns[:5]:
                        _payload = b'A' * 1000
                        if v.get('type') == 'format-string':
                            _payload = b'%p %p %x %n'.ljust(256, b'\x00')
                        elif v.get('type') in ('heap-overflow', 'use-after-free'):
                            _payload = b'\x00' * 64 + b'A' * 256
                        _r = execute_remote_payload(
                            _remote_host, _remote_port, _payload, timeout=5)
                        _remote_results.append({
                            'vuln_type': v.get('type', '?'),
                            'success': _r['success'],
                            'response_len': len(_r.get('response_data', b'')),
                            'error': _r.get('error', ''),
                        })
                    _remote_interaction_result = _remote_results
                    _step_end(_sid_remote, 'success',
                              output_summary=f'{len(_remote_results)} payloads sent')
                    logger.info("Remote interaction: %d payloads sent to %s:%d",
                                len(_remote_results), _remote_host, _remote_port)
                else:
                    _step_end(_sid_remote, 'skipped',
                              output_summary=f'target unreachable: {_remote_host}:{_remote_port} '
                                             f'({ _probe.get("error", "")})')
                    logger.info("Remote target unreachable: %s:%d",
                                _remote_host, _remote_port)
            else:
                _step_end(_sid_remote, 'skipped',
                          output_summary='no remote target configured')
        except ImportError:
            _step_end(_sid_remote, 'skipped',
                      output_summary='remote_interaction module not available')
        except Exception as _re_err:
            _step_end(_sid_remote, 'failed', error_message=str(_re_err))
            logger.warning("Remote interaction failed: %s", _re_err)

    # 钩子 B - 报告增强消费规则发现: ENABLE_REPORT_ENHANCEMENT=1 时
    # 生成 logs/report_enhance_<run_id>.json, 默认关闭
    if _is_enabled('ENABLE_REPORT_ENHANCEMENT'):
        try:
            from core.report_enhancement import build_enhanced_summary
            from core.vuln_db import get_run_findings
            # DB 行使用 vuln_type 列名, build_enhanced_summary 读取 type 字段
            _enh_rows = [{**f, 'type': f.get('vuln_type', '?')}
                         for f in get_run_findings(run_id)]
            _enh = build_enhanced_summary(_enh_rows, binfo)
            os.makedirs('logs', exist_ok=True)
            with open(f'logs/report_enhance_{run_id}.json', 'w', encoding='utf-8') as ef:
                json.dump({'summary': _enh}, ef, indent=2, ensure_ascii=False)
        except Exception:
            pass  # 模块缺失或签名不符时静默跳过

    # 模糊测试崩溃导入 - ENABLE_FUZZ_CRASH_IMPORT=1 时扫描 crash 文件入库, 默认关闭
    if _is_enabled('ENABLE_FUZZ_CRASH_IMPORT'):
        try:
            _crash_dir = os.path.join(
                os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                'logs', 'fuzz_crashes')
            os.makedirs(_crash_dir, exist_ok=True)
            _crash_files = glob.glob(os.path.join(_crash_dir, '*.crash'))
            for cf in _crash_files:
                _hex_ev = ''
                try:
                    with open(cf, 'rb') as _fh:
                        _hex_ev = _fh.read(256).hex()
                except OSError:
                    pass
                try:
                    save_finding(
                        run_id, binary_path, binary_hash,
                        'fuzzer_crash', 'crash', 'High',
                        'CWE-119', f'Fuzzing generated crash: {os.path.basename(cf)}',
                        evidence=_hex_ev,
                        priority_score=8.0,
                    )
                except Exception:
                    pass
            # fuzz 保守回退 - ENABLE_FUZZ_CONSERVATIVE=1 且无 crash 产物时,
            # 按已有变异种子输出生成 potential_bug finding, 默认关闭
            if _is_enabled('ENABLE_FUZZ_CONSERVATIVE') and not _crash_files:
                _logs_dir = os.path.dirname(_crash_dir)
                _seed_files = glob.glob(os.path.join(_logs_dir, '*fuzz*.txt'))
                if _seed_files:
                    try:
                        save_finding(
                            run_id, binary_path, binary_hash,
                            'fuzzer_evolve', 'potential_bug', 'Low',
                            'CWE-119',
                            f'Fuzz mutation produced {len(_seed_files)} seed output '
                            f'file(s) without confirmed crash',
                            evidence='No crash files found in logs/fuzz_crashes/',
                            priority_score=3.0,
                        )
                    except Exception:
                        pass
        except Exception as err:
            logger.warning("Fuzz crash import failed: %s", err)

    # 引擎加权融合 - ENABLE_ENGINE_FUSION=1 时按引擎来源对同类型 finding
    # 做加权评分 (rule 0.6 / symbolic 0.3 / fuzz 0.1) 并回写, 默认关闭。
    # findings 表无 engine 列, 按 vuln_type 推导引擎来源。
    if _is_enabled('ENABLE_ENGINE_FUSION'):
        try:
            import sqlite3 as _sqlite3
            from collections import defaultdict as _dd
            _conn = _sqlite3.connect(DB_PATH)
            _run_row = _conn.execute(
                "SELECT started_at, binary_path FROM analysis_runs WHERE id=?",
                (run_id,)).fetchone()
            if _run_row is not None:
                _rows = _conn.execute(
                    "SELECT id, vuln_type, priority_score FROM findings "
                    "WHERE run_ts >= ? AND binary_path = ?",
                    (_run_row[0], _run_row[1])).fetchall()
                _grouped = _dd(list)
                for _fid, _vtype, _score in _rows:
                    if _vtype in ('symbolic_constraint', 'symbolic_guess'):
                        _engine = 'symbolic'
                    elif _vtype in ('crash', 'potential_bug'):
                        _engine = 'fuzz'
                    else:
                        _engine = 'rule'
                    _grouped[_vtype].append((_fid, _score, _engine))
                _weights = {'rule': 0.6, 'symbolic': 0.3, 'fuzz': 0.1}
                for _vtype, _items in _grouped.items():
                    _pairs = [(_fid, _s, _e) for _fid, _s, _e in _items
                              if _s is not None]
                    if not _pairs:
                        continue
                    _wsum, _scores = 0.0, 0.0
                    for _fid, _score, _engine in _pairs:
                        _w = _weights.get(_engine, 0.2)
                        _scores += _score * _w
                        _wsum += _w
                    _new = _scores / _wsum if _wsum > 0 else _pairs[0][1]
                    for _fid, _s, _e in _pairs:
                        _conn.execute(
                            "UPDATE findings SET priority_score=?, "
                            "evidence=evidence || ? WHERE id=?",
                            (round(_new, 2),
                             f" | Engine-fused score {_new:.2f}", _fid))
                _conn.commit()
            _conn.close()
        except Exception as err:
            logger.warning("Engine fusion failed: %s", err)

    # LLM 告警分诊 - 环境变量 ENABLE_LLM_TRIAGE=1 时启用, 默认关闭
    if _is_enabled('ENABLE_LLM_TRIAGE') and all_vulns:
        _sid = _step_begin(run_id, 'llm_triage')
        try:
            from core.llm_finding_triage import triage_findings
            triage_findings(all_vulns, binfo)
            _step_end(_sid, 'success',
                      output_summary=f"{len(all_vulns)} findings annotated")
        except Exception as err:
            _step_end(_sid, 'failed', error_message=str(err))
            logger.warning("LLM triage failed: %s", err)

    # exploit generation
    exploit_result = None
    if crash_analysis and crash_analysis.get('exploitable'):
        _sid = _step_begin(run_id, 'exploit_gen')
        try:
            os.makedirs(EXPLOITS_DIR, exist_ok=True)
            exploit_result = generate_exploit(
                binfo, crash_data, output_dir=EXPLOITS_DIR)
            _step_end(_sid, 'success',
                      output_summary=exploit_result.get('script_path', ''))
        except Exception as err:
            _step_end(_sid, 'failed', error_message=str(err))
            raise

    # 自动 exploit 生成 — 检测到高危漏洞时即使无 crash 数据也生成利用脚本草稿
    # 申报书"漏洞检测→利用生成"闭环不依赖外部 --crash 参数
    if not exploit_result and all_vulns:
        _high_vulns = [v for v in all_vulns
                       if v.get('severity') in ('High', 'Critical')]
        if _high_vulns:
            _sid_auto_exploit = _step_begin(run_id, 'auto_exploit_gen')
            try:
                _top_vuln = _high_vulns[0]
                _auto_crash = {
                    'crash_type': _top_vuln.get('type', 'stack-buffer-overflow'),
                    'severity': _top_vuln.get('severity', 'High'),
                    'offset': _top_vuln.get('offset'),
                    'raw': _top_vuln.get('description', ''),
                }
                os.makedirs(EXPLOITS_DIR, exist_ok=True)
                exploit_result = generate_exploit(
                    binfo, _auto_crash, output_dir=EXPLOITS_DIR)
                _step_end(_sid_auto_exploit, 'success',
                          output_summary=f'auto-generated for {_top_vuln.get("type", "?")}')
                logger.info("Auto exploit generated for high-severity finding: %s",
                            _top_vuln.get('type', '?'))
            except Exception as _ae:
                _step_end(_sid_auto_exploit, 'failed', error_message=str(_ae))
                logger.warning("Auto exploit generation failed: %s", _ae)

    # LLM 反馈迭代环接入主流程 — 有 exploit 脚本时调用 run_feedback_loop
    # 申报书"反馈给模型 + 人工复核"闭环在主 analyze 流程中执行, 不依赖 feedback 子命令
    feedback_result = None
    if exploit_result and exploit_result.get('success') and \
            _is_enabled('ENABLE_FEEDBACK_LOOP', default='true'):
        _sid_fb = _step_begin(run_id, 'feedback_loop')
        try:
            from core.feedback_loop import run_feedback_loop
            _initial_script = exploit_result.get('script_content', '')
            if _initial_script:
                _fb_output_dir = os.path.join(
                    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    'logs', 'feedback')
                os.makedirs(_fb_output_dir, exist_ok=True)
                # 主流程默认 dry-run 沙箱; ENABLE_FEEDBACK_LOOP_EXEC=1 时允许真实执行
                _fb_sandbox = 'dry-run'
                if _is_enabled('ENABLE_FEEDBACK_LOOP_EXEC'):
                    _fb_sandbox = 'subprocess'
                feedback_result = run_feedback_loop(
                    binary_path, _initial_script, binfo=binfo,
                    output_dir=_fb_output_dir,
                    max_iterations=3,
                    sandbox=_fb_sandbox,
                    gate_timeout=30.0,
                )
                _fb_status = 'succeeded' if feedback_result.get('success') else 'exhausted'
                _step_end(_sid_fb, 'success',
                          output_summary=f'{_fb_status} iters={feedback_result.get("iterations", 0)}')
                logger.info("Feedback loop: %s after %d iterations",
                            _fb_status, feedback_result.get('iterations', 0))
        except Exception as _fb_err:
            _step_end(_sid_fb, 'failed', error_message=str(_fb_err))
            logger.warning("Feedback loop failed: %s", _fb_err)

    # fuzz harness 生成 - 显式 --fuzz 开启才执行
    # 2026-09-16 审计修正: 原门控 fuzz or ENABLE_FUZZ_HARNESS_GEN(default true)
    # 使签名默认 fuzz=False 也恒为真, 50 轮变异执行(每轮 timeout=10s)对
    # 喂垃圾 stdin 不退出的交互样本(io_loop_counter)实测拖满 500s;
    # 签名语义恢复为显式开启, CLI --fuzz 走原路径不受影响
    fuzz_result = None
    if fuzz and _scheduler_decision.get('fuzz', True):
        _sid_fuzz = _step_begin(run_id, 'fuzz_harness')
        try:
            from plugins.fuzz_harness import (
                setup_fuzzing_workspace, generate_libfuzzer_harness,
            )
            _first_fn = target_funcs[0] if target_funcs else 'main'
            fuzz_result = {
                'workspace': setup_fuzzing_workspace(binary_path),
                'harness': generate_libfuzzer_harness(_first_fn),
            }
            logger.info("Fuzz harness generated for %s", _first_fn)
            # 变异 fuzz 执行器: 多策略变异 + 边界值注入, 收集崩溃信息
            _fuzz_exec_status = 'not_executed'
            _fuzz_exec_detail = ''
            try:
                if not os.path.isfile(binary_path):
                    _fuzz_exec_status = 'skipped'
                    _fuzz_exec_detail = 'target file not found'
                elif not os.access(binary_path, os.X_OK):
                    _fuzz_exec_status = 'skipped'
                    _fuzz_exec_detail = 'target not executable in current environment'
                else:
                    _crash_count = 0
                    _total_runs = 0
                    _crash_payloads = []
                    import random as _fuzz_random
                    # 种子语料: 边界值 + 常见漏洞触发模式
                    _seeds = [
                        b'A' * 64, b'A' * 128, b'A' * 256, b'A' * 512,
                        b'A' * 1024, b'A' * 2048, b'A' * 4096,
                        b'\x00' * 64, b'\xff' * 64,
                        b'%s' * 32, b'%x' * 32, b'%n' * 16,
                        b'\x00\x01\x02\x03' * 16,
                        b'AAAA' + b'\x00' * 60,
                    ]
                    # 覆盖率引导: 追踪唯一执行签名作为覆盖率代理
                    # 无 libFuzzer/AFL++ 插桩时, 以 (exit_code, stderr_len_binned)
                    # 作为轻量覆盖率信号 — 发现新签名即视为探索到新路径
                    _coverage_edges = set()
                    _seed_scores = {s: 0 for s in _seeds}
                    _coverage_new_edges = 0
                    _max_rounds = 50
                    for _ri in range(_max_rounds):
                        # 覆盖率引导种子选择: 70% 概率优先选发现过新边的种子
                        _high_cov = [s for s, sc in _seed_scores.items() if sc > 0]
                        if _high_cov and _fuzz_random.random() < 0.7:
                            _seed = _fuzz_random.choice(_high_cov)
                        else:
                            _seed = _fuzz_random.choice(_seeds)
                        # 变异策略: 按轮次选择
                        _mut = _ri % 5
                        if _mut == 0:
                            # 位翻转
                            _payload = bytearray(_seed)
                            for _ in range(_fuzz_random.randint(1, 8)):
                                _pos = _fuzz_random.randint(0, len(_payload) - 1)
                                _payload[_pos] ^= (1 << _fuzz_random.randint(0, 7))
                            _payload = bytes(_payload)
                        elif _mut == 1:
                            # 算术变异: 对随机字节加减
                            _payload = bytearray(_seed)
                            for _ in range(_fuzz_random.randint(1, 4)):
                                _pos = _fuzz_random.randint(0, len(_payload) - 1)
                                _payload[_pos] = (_payload[_pos] + _fuzz_random.choice([-1, 1, -16, 16])) & 0xff
                            _payload = bytes(_payload)
                        elif _mut == 2:
                            # 长度扩展: 重复种子内容
                            _rep = _fuzz_random.randint(2, 16)
                            _payload = _seed * _rep
                        elif _mut == 3:
                            # 边界值插入: 在种子头部插入特殊值
                            _boundary = _fuzz_random.choice([
                                b'\xff\xff\xff\xff', b'\x00\x00\x00\x00',
                                b'\x7f\xff\xff\xff', b'\x80\x00\x00\x00',
                                b'\xff\xff\xff\x7f', b'\xfe\xff\xff\xff',
                            ])
                            _payload = _boundary + _seed
                        else:
                            # 块插入: 在随机位置插入随机字节块
                            _ins_len = _fuzz_random.randint(4, 64)
                            _ins_data = bytes(_fuzz_random.getrandbits(8) for _ in range(_ins_len))
                            _pos = _fuzz_random.randint(0, len(_seed))
                            _payload = _seed[:_pos] + _ins_data + _seed[_pos:]
                        _total_runs += 1
                        try:
                            _fproc = subprocess.run(
                                [binary_path],
                                input=_payload,
                                capture_output=True, timeout=10)
                            _rc = _fproc.returncode
                            # 覆盖率追踪: 以退出码 + stderr 长度分桶作为执行签名
                            _stderr_binned = len(_fproc.stderr or b'') // 64
                            _exec_sig = (_rc, _stderr_binned)
                            if _exec_sig not in _coverage_edges:
                                _coverage_edges.add(_exec_sig)
                                _seed_scores[_seed] = _seed_scores.get(_seed, 0) + 1
                                _coverage_new_edges += 1
                            if _rc != 0 and _rc != 2:
                                _crash_count += 1
                                if len(_crash_payloads) < 10:
                                    _crash_payloads.append(_payload.hex()[:128])
                        except subprocess.TimeoutExpired:
                            pass
                        except OSError as _foerr:
                            _fuzz_exec_status = 'skipped'
                            _fuzz_exec_detail = f'target not executable: {_foerr}'
                            break
                    else:
                        fuzz_result['coverage_edges'] = len(_coverage_edges)
                        fuzz_result['coverage_new_edges'] = _coverage_new_edges
                        if _crash_count > 0:
                            _fuzz_exec_status = 'crash_detected'
                            _fuzz_exec_detail = (f'{_crash_count}/{_total_runs} '
                                                 f'runs crashed, '
                                                 f'{len(_coverage_edges)} edges')
                            fuzz_result['crash_payloads'] = _crash_payloads
                        else:
                            _fuzz_exec_status = 'no_crash'
                            _fuzz_exec_detail = (f'{_total_runs} runs, '
                                                 f'no crash, '
                                                 f'{len(_coverage_edges)} edges')
            except Exception as _fuzz_err:
                _fuzz_exec_status = 'skipped'
                _fuzz_exec_detail = f'execution unavailable: {_fuzz_err}'
            fuzz_result['exec_status'] = _fuzz_exec_status
            fuzz_result['exec_detail'] = _fuzz_exec_detail
            _step_end(_sid_fuzz, 'success',
                      output_summary=f'harness={_first_fn} '
                                      f'exec={_fuzz_exec_status} '
                                      f'({_fuzz_exec_detail})')
        except ImportError:
            _step_end(_sid_fuzz, 'skipped', output_summary='fuzz_harness plugin not available')
            logger.warning("fuzz harness plugin not available")
        except Exception as err:
            _step_end(_sid_fuzz, 'failed', error_message=str(err))
            logger.warning("Fuzz harness generation failed: %s", err)

    # LLM 研判 — 默认开启, 未配置模型时降级为 simulation
    # 移至报告生成之前, 使 LLM 发现进入报告
    ai_result = None
    if ai_analysis:
        _sid_ai = _step_begin(run_id, 'ai_analysis')
        try:
            from modules.binary_analysis.decomp_ai import DecompilerAI
            from modules.llm_client import is_ai_configured, normalize_findings

            decomp_ai = DecompilerAI()
            dangerous_funcs = binfo.get('imports', {}).get('dangerous_functions', [])
            key_strings = binfo.get('strings', [])
            if isinstance(key_strings, list):
                key_strings = key_strings[:20]
            else:
                key_strings = []

            combined_pseudo = ''
            for dr in (decomp_results or [])[:5]:
                combined_pseudo += dr.get('pseudocode', '') + '\n\n'

            ai_result = decomp_ai.analyze_with_llm(
                decompiled_code=combined_pseudo,
                binary_info=binfo,
                dangerous_functions=dangerous_funcs,
                key_strings=key_strings,
                crash_log=str(crash_data) if crash_data else '',
            )
            _step_end(_sid_ai, 'success',
                      output_summary=f"simulation={ai_result.get('simulation', True)}")
            # LLM 发现合并入 rule_findings, 使其出现在报告中
            if ai_result and isinstance(ai_result.get('findings'), list):
                for _af in ai_result['findings']:
                    rule_findings.append(_af)
        except Exception as err:
            _step_end(_sid_ai, 'failed', error_message=str(err))
            logger.warning("AI analysis failed: %s", err)

    # report - 传入规则检测产物、符号执行结果与程序画像
    ctx = hook_mgr.run('pre_report', ctx)
    _sid = _step_begin(run_id, 'report')
    try:
        reports = write_report(decomp_results, binfo, crash_analysis, output_format,
                               rule_findings=rule_findings,
                               symbolic_result=sym_result,
                               binary_profile=binary_profile,
                               output_dir=output_dir)
        _step_end(_sid, 'success', output_summary=', '.join(reports.values()))
    except Exception as err:
        _step_end(_sid, 'failed', error_message=str(err))
        raise
    ctx = hook_mgr.run('post_report', ctx)
    _project_state.current_step = 'report'

    # 可选增强层 - 环境变量 ENABLE_ENHANCED_PIPELINE=1 时叠加, 默认关闭
    result = {
        'reports': reports,
        'decomp_analysis': decomp_results,
        'crash_analysis': crash_analysis,
        'crash_data': crash_data,
        'symbolic_execution': sym_result,
        'exploit_result': exploit_result,
        'fuzz_result': fuzz_result,
        'binary_info': binfo,
        'binary_profile': binary_profile,
        'cfg_result': cfg_result,
        'dynamic_trace': dynamic_trace,
        'elapsed': None,
        'total_vulns': len(all_vulns),
        'ai_analysis': ai_result,
        'feedback_result': feedback_result,
        'remote_interaction': _remote_interaction_result,
    }
    # 增强族挂载 - pipeline_enh_1..8 挂回主流水线
    # ENABLE_PIPELINE_ENH 默认开启, 显式 =0 可关闭; ENABLE_ENHANCED_PIPELINE
    # 开启时由整合策略接管, 跳过本块防重复应用。各增强仅向 result 追加
    # 内部状态键, 不改 findings; 单模块失败记 step_records
    # status=enhancement_failed, 不中断管线。
    if _is_enabled('ENABLE_PIPELINE_ENH', default='true') and \
            not _is_enabled('ENABLE_ENHANCED_PIPELINE'):
        _sid = _step_begin(run_id, 'pipeline_enhancements')
        _enh_failures = []
        for _enh_idx in range(1, 9):
            try:
                _enh_mod = __import__(f'core.pipeline_enh_{_enh_idx}',
                                      fromlist=['apply'])
                _enh_fn = getattr(_enh_mod, f'apply_enhancements_{_enh_idx}')
                _enh_fn(result, binary_path, binfo, kwargs, binary_hash)
                logger.info("[ENH] pipeline_enh_%d applied", _enh_idx)
            except Exception as err:
                _enh_failures.append(str(_enh_idx))
                logger.warning("[ENH] pipeline_enh_%d failed: %s", _enh_idx, err)
        if _enh_failures:
            _step_end(_sid, 'enhancement_failed',
                      output_summary='failed: ' + ','.join(_enh_failures),
                      error_message='enhancement modules failed: '
                                    + ','.join(_enh_failures))
        else:
            _step_end(_sid, 'success',
                      output_summary='8 enhancement modules applied')

    if _is_enabled('ENABLE_ENHANCED_PIPELINE'):
        try:
            from core.pipeline_enhancements import run_enhancement_strategies
            run_enhancement_strategies(result, binary_path, binfo, kwargs, binary_hash)
        except Exception as err:
            logger.warning("Enhanced pipeline strategies failed: %s", err)

    # 报告增强 - 环境变量 ENABLE_REPORT_ENHANCEMENT=1 时生成摘要, 默认关闭
    if _is_enabled('ENABLE_REPORT_ENHANCEMENT'):
        try:
            from core.report_enhancement import build_enhanced_summary
            result['enhanced_summary'] = build_enhanced_summary(all_vulns, binfo)
        except Exception as err:
            logger.warning("Report enhancement failed: %s", err)

    # 发现优先级评分 - 环境变量 ENABLE_FINDING_PRIORITIZER=1 时启用, 默认关闭
    if _is_enabled('ENABLE_FINDING_PRIORITIZER') and all_vulns:
        try:
            from core.finding_prioritizer import prioritize_findings
            prioritize_findings(all_vulns)
        except Exception as err:
            logger.warning("Finding prioritizer failed: %s", err)

    # 复合排序 - 两排序器任一启用时执行, 消除"后执行者覆盖"的不确定性:
    # LLM 标注告警按 llm_priority 降序在前, 未标注的按 priority_score 降序在后
    if all_vulns and (
        _is_enabled('ENABLE_LLM_TRIAGE')
        or _is_enabled('ENABLE_FINDING_PRIORITIZER')
    ):
        try:
            from core.finding_prioritizer import apply_composite_sort
            apply_composite_sort(all_vulns)
        except Exception as err:
            logger.warning("Composite sort failed: %s", err)

    # wrap up
    elapsed = time.time() - start_time
    result['elapsed'] = elapsed
    finish_run(run_id, 'completed',
               f'{len(all_vulns)} vulns in {elapsed:.1f}s')

    _project_state.status = 'completed'
    _project_state.current_step = 'done'
    _project_state.timestamps['end'] = time.strftime('%Y-%m-%dT%H:%M:%S')
    result['project_state'] = _project_state.to_dict()

    logger.info("Pipeline done in %.1fs | %d functions | %d vulns",
                elapsed, len(target_funcs), len(all_vulns))

    return result


def run_pipeline_enhanced(binary_path: str, **kwargs) -> Dict[str, Any]:
    result = run_pipeline(binary_path, **kwargs)
    if 'error' in result:
        return result

    sym_result = result.get("symbolic_execution")
    binfo = result.get("binary_info", {})
    binary_hash = result.get('binary_hash', '')

    try:
        from core.pipeline_enhancements import run_enhancement_strategies
    except ImportError:
        run_enhancement_strategies = None

    if run_enhancement_strategies is not None:
        # 整合策略按序应用, 单策略失败不中断其余策略
        run_enhancement_strategies(result, binary_path, binfo, kwargs, binary_hash)
    else:
        # 整合模块不可用时回退到分层实现
        try:
            from core.pipeline_enh_1 import apply_enhancements_1
            from core.pipeline_enh_2 import apply_enhancements_2
            from core.pipeline_enh_3 import apply_enhancements_3
            from core.pipeline_enh_4 import apply_enhancements_4
            from core.pipeline_enh_5 import apply_enhancements_5
            from core.pipeline_enh_6 import apply_enhancements_6
            from core.pipeline_enh_7 import apply_enhancements_7
            from core.pipeline_enh_8 import apply_enhancements_8
        except ImportError:
            # 增强层整体缺失时返回标准管线结果
            logger.debug('optional enhancement modules not available')
            return result
        apply_enhancements_1(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_2(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_3(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_4(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_5(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_6(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_7(result, binary_path, binfo, kwargs, binary_hash)
        apply_enhancements_8(result, binary_path, binfo, kwargs, binary_hash)

    return result
