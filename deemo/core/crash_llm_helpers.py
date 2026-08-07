"""
LLM 崩溃分析的辅助函数集。

"""


import json
import logging
import re
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)


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
