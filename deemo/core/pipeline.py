"""
Central analysis pipeline. Orchestrates binary loading, decompilation,
static analysis, symbolic execution, crash analysis, and reporting.
Each stage can fail independently without killing the whole run.
"""

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
    MAX_FUNCTIONS, MAX_PARALLEL, ENABLE_SYMBOLIC,
    ENABLE_CRYPTO_SCAN, ENABLE_TAINTRACK, ENABLE_UNPACK,
    SUBPROCESS_TIMEOUT, ensure_dirs, _is_enabled, DB_PATH,
)
from core.binary_info import get_binary_info, validate_binary
from core.decompiler import list_functions, decompile_function, ai_analyze_function
from core.symexec import run_symbolic, check_angr, find_buffer_overflow
from core.crash_analysis import load_crash_file, analyze_crash_for_exploit
from core.exploit_gen import generate_exploit
from core.report import write_report
from core.vuln_db import init_db, start_run, finish_run, save_finding
from core.vuln_db import record_step, update_step
from core.unified_heap_pipeline import analyze_heap_safety
from core.hooks import get_hook_manager

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
    """
    Execute the full analysis pipeline on a binary.

    Returns a dict with keys: reports, decomp_analysis, crash_analysis,
    symbolic_execution, exploit_result, similar_vulnerabilities.
    """
    start_time = time.time()
    ensure_dirs()
    init_db()

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

    logger.info("Binary: %s | %s %d-bit | size=%d",
                binfo['filename'], binfo['arch'], binfo['bits'], binfo['size'])

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
            target_funcs = all_funcs[:max_funcs]

    target_funcs = target_funcs[:max_funcs]
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
                ai = ai_analyze_function(func_name, r['pseudocode'], binfo)
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

    # 符号执行 - CLI --symbolic 或环境变量 ENABLE_SYMBOLIC 开启
    # FIX: 2026-08-15 结果回填 - angr 缺失记 skipped, 执行失败记 failed 含原因,
    # 均不再中断管线; 步骤状态按实况记录而非无条件 success
    sym_result = None
    use_symbolic = ENABLE_SYMBOLIC if symbolic is None else symbolic
    if use_symbolic:
        _sid = _step_begin(run_id, 'symbolic_exec')
        if not check_angr():
            _step_end(_sid, 'skipped', output_summary='angr not installed')
            logger.warning("Symbolic execution skipped: angr not installed")
            sym_result = {'success': False, 'error': 'angr not installed',
                          'paths_found': 0, 'constraints': []}
        else:
            try:
                logger.info("Running symbolic execution...")
                sym_result = run_symbolic(binary_path)
                # 符号路径合并 - ENABLE_SYMBOLIC_MERGE=1 时约束回写 findings, 默认关闭
                # FIX: 2026-08-15 约束默认仅记 step 与报告, findings 入库由该开关门控
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

    # 规则检测 - ENABLE_RULE_DETECTORS=1 时对各函数伪代码分别跑
    # 堆/栈/格式化/整数/UAF 检测器, 各自输出类型化 finding, 默认关闭
    rule_findings = []
    if _is_enabled('ENABLE_RULE_DETECTORS'):
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

    # 证据融合 - ENABLE_EVIDENCE_FUSION=1 时对类型化 rule_findings 做一致性加权/分诊。
    # 独立各型检测器可能对同一 (函数, 类型) 命中多条; 融合按证据一致性收敛置信度,
    # 抑制单一弱信号造成的高估, 降低跨类型误报。
    if _is_enabled('ENABLE_EVIDENCE_FUSION') and rule_findings:
        try:
            from modules.vuln.detection.evidence_fusion import fuse_findings
            rule_findings = fuse_findings(rule_findings)
        except Exception as err:
            logger.warning("Evidence fusion failed: %s", err)

    # save findings
    all_vulns = []
    _sid = _step_begin(run_id, 'findings_save')
    _seen = set()
    for r in decomp_results:
        analysis = r.get('analysis', r)
        for v in analysis.get('vulnerabilities', []):
            all_vulns.append(v)
            _seen.add((r.get('function_name', r.get('function', '?')),
                       v.get('type', '?')))
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
        key = (v.get('function_name', '?'), v.get('type', '?'))
        if key in _seen:
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

    # PoC 生成 - 环境变量 ENABLE_POC_GEN=1 时对规则类发现生成占位复现脚本, 默认关闭
    if _is_enabled('ENABLE_POC_GEN'):
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
            # PoC 执行与重试 - ENABLE_POC_EXECUTE=1 时执行并回写 evidence, 默认关闭
            if _is_enabled('ENABLE_POC_EXECUTE') and _poc_paths:
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
                    # 回灌再验证 - 触发条件 (2026-08-15 注释补充, 逻辑未改):
                    #   1) ENABLE_CLOSED_LOOP_REANALYSIS=1 显式开启;
                    #   2) 本次 PoC 执行状态为 crash_detected 或 info_leak_detected;
                    #   3) _reanalysis_depth==0 (单次运行仅触发一次, 防循环)。
                    # 触发后调用 _reconfirm_with_engines 用污点引擎确认载荷可达性:
                    # 可达且置信度>0.6 则严重度升级 (High->Critical/其余->High),
                    # 不可达则 priority_score 减半。
                    # 当前 5-CVE 批次 PoC 执行均为 no_crash, 分支未触发属预期, 非死代码。
                    if _is_enabled('ENABLE_CLOSED_LOOP_REANALYSIS') and \
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
            exploit_result = generate_exploit(binfo, crash_data)
            _step_end(_sid, 'success')
        except Exception as err:
            _step_end(_sid, 'failed', error_message=str(err))
            raise

    # fuzz harness 生成 - 默认关闭，CLI --fuzz 或调用方显式开启
    fuzz_result = None
    if fuzz:
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
        except ImportError:
            logger.warning("fuzz harness plugin not available")
        except Exception as err:
            logger.error("Fuzz harness generation failed: %s", err)

    # report - FIX: 2026-08-15 补序列化规则 finding 与符号执行结果
    # (原调用只传 decomp_results, 规则检测产物与 sym_result 不入报告)
    ctx = hook_mgr.run('pre_report', ctx)
    _sid = _step_begin(run_id, 'report')
    try:
        reports = write_report(decomp_results, binfo, crash_analysis, output_format,
                               rule_findings=rule_findings,
                               symbolic_result=sym_result,
                               output_dir=output_dir)
        _step_end(_sid, 'success', output_summary=', '.join(reports.values()))
    except Exception as err:
        _step_end(_sid, 'failed', error_message=str(err))
        raise
    ctx = hook_mgr.run('post_report', ctx)

    # LLM 研判 — ai_analysis 开启时串入统一适配层
    ai_analysis = kwargs.get('ai_analysis', False)
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
        except Exception as err:
            _step_end(_sid_ai, 'failed', error_message=str(err))
            logger.warning("AI analysis failed: %s", err)

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
        'elapsed': None,
        'total_vulns': len(all_vulns),
        'ai_analysis': ai_result,
    }
    # 增强族挂载 - FIX: 2026-08-15 pipeline_enh_1..8 挂回主流水线
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

    logger.info("Pipeline done in %.1fs | %d functions | %d vulns",
                elapsed, len(target_funcs), len(all_vulns))

    return result


# Optional enhancement layers stacked on top of the standard pipeline.
# Each enhancement uses try/except ImportError: activated when the module
# is present, silently skipped otherwise. Backward-compatible with existing
# deployments — no new module dependencies required.


def run_pipeline_enhanced(binary_path: str, **kwargs) -> Dict[str, Any]:
    """Enhanced pipeline: path diversity management, solver optimization,
    multi-decompiler confidence ensemble, and GNN preprocessing.

    API-compatible with run_pipeline. All enhancement modules are optional;
    ImportError silently degrades to standard pipeline.
    """
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
