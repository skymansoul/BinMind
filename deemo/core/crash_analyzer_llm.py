"""
LLM-powered deep crash analysis: semantic root cause analysis of fuzzing/symbolic
execution crash results.

Complements crash_analysis.py keyword matching:
  crash_analysis.py: fast classification (SIGSEGV -> stack/heap -> exploitable)
  crash_analyzer_llm.py: deep reasoning (decompiled code + registers + stack trace)

Input modes: raw crash text (ASAN/GDB/coredump), structured crash data
(registers + backtrace + fault instruction), or context-enhanced (with
decompiled code of the crashing function).

Output: structured root cause report with vulnerability type, trigger chain,
exploit direction, and confidence. Called after crash_analysis to augment results.

References:
  - Xu et al., 2024, USENIX Security, "VulnRepair"
  - Pearce et al., 2022, IEEE S&P, "Asleep at the Keyboard?"
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# LLM 系统提示 —— 要求结构化 JSON 输出
_CRASH_ANALYSIS_SYSTEM = """You are a senior binary exploitation researcher.
Analyze the crash information and provide a structured root cause analysis.

Output MUST be valid JSON with these keys:
  - crash_type: one of [stack-overflow, heap-overflow, use-after-free,
                 double-free, format-string, integer-overflow, null-deref,
                 type-confusion, other]
  - root_cause: specific explanation of what went wrong (2-3 sentences)
  - trigger_chain: step-by-step description of how the crash was triggered
  - exploitability: one of [confirmed, likely, possible, unlikely, none]
  - exploit_primitive: what capability the crash gives the attacker
  - recommended_approach: brief suggestion for exploitation direction
  - cwe: the most specific CWE number
  - confidence: 0.0 to 1.0"""


def analyze_crash_with_llm(
    crash_data: Dict[str, Any],
    binary_path: Optional[str] = None,
    decompiled_context: Optional[str] = None,
    binfo: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    调用 LLM 对崩溃进行深度分析。

    与 crash_analysis.py 的 analyze_crash_for_exploit 返回格式兼容，
    额外增加了 root_cause、trigger_chain 和 confidence 字段。

    Args:
        crash_data:         崩溃数据（raw 文本或结构化 dict）
        binary_path:        崩溃来源的二进制路径（用于获取反编译上下文）
        decompiled_context: 崩溃所在函数的反编译代码（可选）
        binfo:              二进制信息

    Returns:
        增强的崩溃分析 dict，包含 LLM 的深度分析字段。
        若 LLM 不可用则降级为关键词分析结果。
    """
    result: Dict[str, Any] = {
        'crash_type': crash_data.get('crash_type', 'unknown'),
        'severity': crash_data.get('severity', 'Medium'),
        'exploitable': crash_data.get('exploitable', False),
        'root_cause': '',
        'trigger_chain': '',
        'exploitability': 'unknown',
        'exploit_primitive': '',
        'recommended_approach': '',
        'cwe': '',
        'confidence': 0.0,
        'source': 'heuristic',
    }

    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            return _fallback_heuristic_analysis(crash_data)
    except ImportError:
        return _fallback_heuristic_analysis(crash_data)

    crash_text = _build_crash_context(crash_data, binary_path, decompiled_context, binfo)

    try:
        from core.ai_backends import query_llm

        response = query_llm(
            system=_CRASH_ANALYSIS_SYSTEM,
            user=crash_text,
            temperature=0.2,
            max_tokens=1024,
        )

        llm_result = _parse_llm_crash_response(response)
        if llm_result:
            result.update(llm_result)
            result['source'] = 'llm'

            if result['exploitability'] in ('confirmed', 'likely'):
                result['exploitable'] = True
            elif result['exploitability'] == 'none':
                result['exploitable'] = False

            result['severity'] = _infer_severity_from_llm(result)

    except Exception as e:
        _log.debug("LLM crash analysis failed, using heuristic: %s", e)
        fallback = _fallback_heuristic_analysis(crash_data)
        result.update(fallback)

    return result


def _build_crash_context(
    crash_data: Dict[str, Any],
    binary_path: Optional[str],
    decompiled_context: Optional[str],
    binfo: Optional[Dict[str, Any]],
) -> str:
    """Assemble crash context from binary info, registers, stack trace, and decompiled code."""
    parts = []

    if binfo:
        parts.append(
            f"Binary: {binfo.get('filename', '?')} "
            f"({binfo.get('arch', '?')} {binfo.get('bits', 64)}-bit)"
        )
    elif binary_path:
        parts.append(f"Binary: {binary_path}")

    if crash_data.get('crash_type'):
        parts.append(f"Crash type: {crash_data['crash_type']}")
    if crash_data.get('severity'):
        parts.append(f"Severity: {crash_data['severity']}")

    registers = crash_data.get('registers', {})
    if registers:
        reg_lines = [f"  {k}: {v}" for k, v in list(registers.items())[:12]]
        parts.append('Registers:\n' + '\n'.join(reg_lines))

    stack_trace = crash_data.get('stack_trace', [])
    if isinstance(stack_trace, list) and stack_trace:
        parts.append('Stack trace:\n' + '\n'.join(f'  {s}' for s in stack_trace[:10]))

    if crash_data.get('fault_instruction'):
        parts.append(f"Faulting instruction: {crash_data['fault_instruction']}")

    if decompiled_context:
        parts.append(
            f"Decompiled code at crash point:\n```c\n{decompiled_context[:3000]}\n```"
        )
    elif binary_path and crash_data.get('addresses'):
        try:
            from core.decompiler import decompile_function
            for addr in crash_data['addresses'][:3]:
                try:
                    decomp = decompile_function(binary_path, str(addr))
                    if decomp.get('pseudocode'):
                        parts.append(
                            f"Decompiled code near {addr}:\n```c\n"
                            f"{decomp['pseudocode'][:2000]}\n```"
                        )
                        break
                except Exception:
                    continue
        except Exception:
            pass

    raw = crash_data.get('raw', '')
    if raw:
        parts.append(f"Raw crash output:\n```\n{raw[:2000]}\n```")

    return '\n\n'.join(parts)


def _parse_llm_crash_response(response: str) -> Optional[Dict[str, Any]]:
    """Parse JSON from LLM response, trying direct parse, code block, and fallback patterns."""
    if not response:
        return None

    try:
        return json.loads(response)
    except json.JSONDecodeError:
        pass

    json_match = re.search(r'```(?:json)?\s*\n?(\{[\s\S]*?\})\n?```', response)
    if json_match:
        try:
            return json.loads(json_match.group(1))
        except json.JSONDecodeError:
            pass

    json_match = re.search(r'\{[\s\S]*?"crash_type"[\s\S]*?\}', response)
    if json_match:
        try:
            return json.loads(json_match.group(0))
        except json.JSONDecodeError:
            pass

    return None


def _infer_severity_from_llm(result: Dict[str, Any]) -> str:
    """Map LLM exploitability verdict and crash type to severity level."""
    exploitability = result.get('exploitability', 'unknown')
    crash_type = result.get('crash_type', 'other')

    severity_map = {
        'confirmed': 'Critical',
        'likely': 'High',
        'possible': 'Medium',
        'unlikely': 'Low',
        'none': 'Low',
    }

    if exploitability in severity_map:
        return severity_map[exploitability]

    type_severity = {
        'stack-overflow': 'High',
        'heap-overflow': 'Critical',
        'use-after-free': 'Critical',
        'double-free': 'Critical',
        'format-string': 'High',
        'integer-overflow': 'Medium',
        'null-deref': 'Low',
        'type-confusion': 'High',
    }
    return type_severity.get(crash_type, 'Medium')


def _fallback_heuristic_analysis(crash_data: Dict[str, Any]) -> Dict[str, Any]:
    """Heuristic fallback when LLM is unavailable."""
    from core.crash_analysis import analyze_crash_for_exploit

    heuristic = analyze_crash_for_exploit(crash_data)
    crash_type = crash_data.get('crash_type', 'unknown')

    root_cause_map = {
        'stack-buffer-overflow': (
            'Stack buffer overflow caused by unchecked write to a fixed-size '
            'local buffer. The saved return address on the stack was overwritten.'
        ),
        'heap-buffer-overflow': (
            'Heap buffer overflow caused by writing beyond allocated chunk '
            'boundaries. Adjacent heap metadata or user data was corrupted.'
        ),
        'use-after-free': (
            'Use-after-free: a pointer to a freed heap chunk was dereferenced. '
            'The freed memory may have been reallocated to another consumer.'
        ),
        'SIGSEGV': (
            'Segmentation fault — the program attempted to access an invalid '
            'memory address. Check if the faulting address is user-controllable.'
        ),
    }

    return {
        'crash_type': crash_type,
        'severity': crash_data.get('severity', 'Medium'),
        'exploitable': heuristic.get('exploitable', False),
        'root_cause': root_cause_map.get(crash_type, f'Crash of type {crash_type} — requires manual analysis'),
        'trigger_chain': '(LLM unavailable — heuristic analysis only)',
        'exploitability': 'possible' if heuristic.get('exploitable') else 'unlikely',
        'exploit_primitive': ', '.join(heuristic.get('primitives', ['unknown'])),
        'recommended_approach': '; '.join(heuristic.get('notes', ['manual analysis needed'])),
        'cwe': '',
        'confidence': 0.3,
        'source': 'heuristic',
    }


def batch_analyze_crashes(
    crashes: List[Dict[str, Any]],
    binary_path: str,
    parallel: bool = False,
) -> List[Dict[str, Any]]:
    """
    Batch analyze multiple crashes, ordered by severity (most critical first).

    Args:
        crashes: list of crash data dicts
        binary_path: source binary
        parallel: use ThreadPoolExecutor when True and crash count > 1

    Returns:
        Analysis results sorted by severity
    """
    results = []

    if parallel and len(crashes) > 1:
        from concurrent.futures import ThreadPoolExecutor, as_completed
        with ThreadPoolExecutor(max_workers=min(4, len(crashes))) as pool:
            futures = {
                pool.submit(analyze_crash_with_llm, c, binary_path): i
                for i, c in enumerate(crashes)
            }
            for fut in as_completed(futures):
                try:
                    results.append(fut.result())
                except Exception as e:
                    _log.warning("Parallel crash analysis task failed: %s", e)
    else:
        for crash in crashes:
            try:
                result = analyze_crash_with_llm(crash, binary_path)
                results.append(result)
            except Exception as e:
                _log.warning("Crash analysis failed: %s", e)

    sev_order = {'Critical': 0, 'High': 1, 'Medium': 2, 'Low': 3}
    results.sort(key=lambda r: sev_order.get(r.get('severity', 'Low'), 99))

    return results
