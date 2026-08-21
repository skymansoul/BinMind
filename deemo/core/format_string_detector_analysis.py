"""格式化字符串检测深度分析 — 符号执行偏移计算/LLM增强/置信度融合/污点预过滤。"""


import logging
import math
from typing import Any, Dict, List

_log = logging.getLogger(__name__)


def _compute_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """通过符号执行或启发式计算格式化字符串的栈偏移。

    优先使用 angr 符号执行，不可用时回退到启发式估计。
    """
    try:
        import angr

        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        target_func = finding['function']
        for f in cfg.functions.values():
            if f.name == target_func:
                for block in f.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            callee_addr = insn.operands[0].imm
                            callee = cfg.functions.get(callee_addr)
                            if callee and callee.name == finding['format_func']:
                                state = proj.factory.blank_state(addr=insn.address)
                                try:
                                    rdi = state.solver.eval(state.regs.rdi)
                                    rsp = state.solver.eval(state.regs.rsp)
                                    offset = (rdi - rsp) // 8
                                    if 1 <= offset <= 50:
                                        return offset
                                except Exception:
                                    pass
                break
    except ImportError:
        pass
    except Exception as e:
        _log.debug("Symbolic format offset computation failed: %s", e)

    return _heuristic_format_offset(binary_path, finding)


def _heuristic_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """启发式估计格式化字符串偏移。

    x86_64: 前6个参数通过寄存器传递, 栈上从第7个开始.
    i386: 所有参数通过栈传递, 格式化字符串在 esp+4 处.
    """
    try:
        from core.binary_info import get_binary_info
        binfo = get_binary_info(binary_path)
        arch = binfo.get('arch', 'x86-64')
        bits = binfo.get('bits', 64)

        if bits == 32 or '86' in arch:
            return 1

        return 6
    except Exception:
        return -1


def _llm_enhance_findings(
    findings: List[Dict[str, Any]],
    binary_path: str,
) -> List[Dict[str, Any]]:
    """调用 LLM 对静态检测结果进行深度分析。"""
    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            return findings

        from core.ai_backends import query_llm

        for finding in findings[:3]:
            system_prompt = (
                "You are an expert binary exploitation analyst specializing in "
                "format string vulnerabilities. Evaluate the exploitability of "
                "the given finding concisely."
            )
            user_prompt = (
                f"Format string finding:\n"
                f"Function: {finding['function']}\n"
                f"Dangerous call: {finding['format_func']}({finding['format_arg']})\n"
                f"Estimated offset: {finding.get('offset', -1)}\n\n"
                f"Provide: 1) Is this exploitable? 2) What is the most likely "
                f"attack vector? 3) Key constraints. Keep it under 200 words."
            )
            try:
                response = query_llm(
                    system=system_prompt,
                    user=user_prompt,
                    temperature=0.2,
                    max_tokens=256,
                )
                finding['llm_analysis'] = response.strip()
                finding['confidence'] = min(1.0, finding['confidence'] + 0.15)
            except Exception as e:
                _log.debug("LLM format string analysis failed: %s", e)

    except (ImportError, Exception) as e:
        _log.debug("LLM enhancement unavailable: %s", e)

    findings = _fuse_confidence(findings)
    return findings


def _fuse_confidence(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """贝叶斯加权融合多层检测置信度。

    各层视为独立证据源, 用对数似然比(log-odds)累加而非直接加减置信度。
    """
    weights = {'asm': 0.6, 'static': 0.5, 'taint': 0.7,
               'defuse': 0.65, 'symbolic': 0.8}

    for f in findings:
        log_odds = 0.0
        count = 0
        base_conf = f.get('confidence', 0.5)
        if base_conf > 0 and base_conf < 1:
            log_odds += math.log(base_conf / (1.0 - base_conf))
            count += 1

        if f.get('taint_source', '').startswith('safe'):
            log_odds -= 1.5
        elif f.get('taint_source'):
            log_odds += weights['taint']
        if f.get('def_use_trace', '').startswith('safe'):
            log_odds -= 1.0
        elif f.get('def_use_trace'):
            log_odds += weights['defuse']
        if f.get('offset', -1) >= 0:
            log_odds += weights['symbolic']

        if count > 0:
            fused = 1.0 / (1.0 + math.exp(-log_odds))
            f['confidence'] = round(max(0.05, min(0.98, fused)), 3)
            f['fused'] = True
    return findings


def detect_with_taint_prefilter(
    binary_path: str,
    func_name: str = "",
    use_llm: bool = False,
) -> List[Dict[str, Any]]:
    """带污点预过滤的格式化字符串检测。

    先运行 taint_propagator 识别确实可达污点源的 sink,
    再对此子集运行完整的 3-level 检测。
    """
    from core.format_string_detector import detect_format_string_vulns
    findings = detect_format_string_vulns(binary_path, func_name, use_llm)
    if not findings:
        return findings

    from core.taint_propagator import TaintPropagator
    tp = TaintPropagator()

    try:
        import subprocess
        from config import R2_PATH
        out = subprocess.check_output(
            [R2_PATH, '-q', '-c', f's {func_name}; pdc', binary_path],
            timeout=15, stderr=subprocess.DEVNULL,
        )
        pseudocode = out.decode('utf-8', errors='replace')
        taint_paths = tp.propagate(pseudocode, func_name)
    except Exception:
        return findings

    tainted_sinks = set()
    for tp_path in taint_paths:
        if tp_path.sink_type == 'FORMAT':
            tainted_sinks.add(tp_path.sink_func)

    for f in findings:
        fmt_func = f.get('format_func', '')
        if fmt_func not in tainted_sinks:
            f['confidence'] = round(f.get('confidence', 0.5) * 0.6, 4)
            f['taint_filtered'] = True
        else:
            f['taint_verified'] = True
            f['taint_source'] = next(
                (tp.source_func for tp in taint_paths
                 if tp.sink_func == fmt_func), '',
            )

    return findings
