# 栈溢出分析器入口 — 从symbolic/static/canary/strategy/pattern_fallback拆分.
# 主编排函数保留在此, 辅助函数散到子模块.
# 创建: 2026-05-24 (拆分)


import logging
import os
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)

from .stack_overflow_symbolic import symbolic_overflow_analysis, compute_padding_from_state
from .stack_overflow_static import static_overflow_analysis, DIRTY_CALLS
from .stack_overflow_canary import detect_canary_in_function
from .stack_overflow_strategy import recommend_strategy, build_exploit_params
from .stack_overflow_pattern_fallback import analyze_with_pattern_fallback

# 兼容别名 — 保持原有_前缀调用方可用
_symbolic_overflow_analysis = symbolic_overflow_analysis
_static_overflow_analysis = static_overflow_analysis
_detect_canary_in_function = detect_canary_in_function
_recommend_strategy = recommend_strategy
_build_exploit_params = build_exploit_params


def analyze_stack_overflow(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """对指定函数进行栈溢出自动化分析."""
    result: Dict[str, Any] = {
        'overflowable': False,
        'padding': 0,
        'has_canary': False,
        'canary_leak_path': '',
        'strategy': 'unknown',
        'exploit_params': {},
        'insights': [],
    }

    if not os.path.isfile(binary_path):
        result['error'] = f'file not found: {binary_path}'
        return result

    sym_result = symbolic_overflow_analysis(binary_path, func_name)
    if sym_result.get('overflowable'):
        result.update(sym_result)

    if not result['overflowable']:
        static_result = static_overflow_analysis(binary_path, func_name, binfo)
        result.update(static_result)
        if static_result.get('insights'):
            result['insights'].extend(static_result['insights'])

    if not result['overflowable']:
        try:
            from core.asm_detector import detect_from_assembly
            asm_findings = detect_from_assembly(binary_path, func_name)
            for af in asm_findings:
                if af.get('type') == 'stack-overflow':
                    result['overflowable'] = True
                    result['padding'] = af.get('buffer_size_estimate', 0)
                    result['insights'].append(
                        f"Assembly-level: {af.get('description', '')}"
                    )
        except ImportError:
            pass
        except Exception as e:
            _log.debug("Assembly SO detection failed: %s", e)

    result['has_canary'] = detect_canary_in_function(binary_path, func_name)
    result['strategy'] = recommend_strategy(result, binfo, libc_info)
    result['exploit_params'] = build_exploit_params(result, binfo, libc_info)

    return result


__all__ = [
    "analyze_stack_overflow", "analyze_with_pattern_fallback",
    "symbolic_overflow_analysis", "compute_padding_from_state",
    "static_overflow_analysis", "detect_canary_in_function",
    "recommend_strategy", "build_exploit_params",
    "DIRTY_CALLS",
]
