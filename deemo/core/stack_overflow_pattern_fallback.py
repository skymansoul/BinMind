"""
栈溢出模式回退分析 —— angr 失败时使用 r2 + 汇编级模式匹配。

"""


import logging
from typing import Any, Dict, Optional

_log = logging.getLogger(__name__)


def analyze_with_pattern_fallback(
    binary_path: str,
    func_name: str,
    binfo: Optional[Dict[str, Any]] = None,
    libc_info: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """
    angr 优先, 失败时用 pattern_fallback 做汇编级模式匹配。

    返回格式与 analyze_stack_overflow 完全兼容。
    """
    # 延迟导入避免循环依赖
    from core.stack_overflow_analyzer import analyze_stack_overflow

    result = analyze_stack_overflow(binary_path, func_name, binfo, libc_info)

    # angr 成功 → 直接返回
    if result.get('overflowable') and not result.get('error'):
        result['method'] = 'angr'
        return result

    # angr 失败/超时/无结果 → 回退到 pattern_fallback
    import subprocess, json
    from config import R2_PATH
    from core.pattern_fallback import match_patterns

    try:
        out = subprocess.check_output(
            [R2_PATH, '-q', '-c', f's {func_name}; pdbj', binary_path],
            timeout=15, stderr=subprocess.DEVNULL,
        )
        disasm = json.loads(out)
        text = '\n'.join(op.get('disasm', '') for op in disasm.get('ops', []))
    except Exception:
        result['method'] = 'angr_failed'
        return result

    matches = match_patterns(text)
    so_matches = [m for m in matches if m.vuln_type == 'stack_overflow']

    if so_matches:
        best = so_matches[0]
        result['overflowable'] = True
        result['padding'] = 0  # 模式匹配无法计算精确 padding
        result['has_canary'] = False
        result['strategy'] = 'pattern_fallback'
        result['method'] = 'pattern_fallback'
        result['pattern_confidence'] = best.confidence
        result['pattern_desc'] = best.pattern_desc
    else:
        result['method'] = 'pattern_fallback_no_match'

    return result
