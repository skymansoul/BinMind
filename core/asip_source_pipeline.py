"""
ASIP 源码级管线: 将 ASIP 误报削减集成到源码级检测流程。
核心误报源为 widen 过激进与 alloc-write 粗粒度配对, 本模块提供 guard 提示收窄区间 (asip_refine_intervals)、
路径条件感知过滤 (asip_filter_by_path) 与一键增强入口 (asip_source_enhance)。
"""

from typing import Dict, List, Optional, Tuple

from modules.patching.src.asip_hinted_widen import (
    WideningHint, extract_hints_from_text, widen_with_hints,
)


def asip_refine_intervals(
    source: str,
    var_bounds: Dict[str, Tuple[Optional[int], Optional[int]]],
    target_vars: List[str] = None,
) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
    """用源码中的 guard 条件收窄区间域变量边界。扫描 if(x<=N) 模式, 以 N 作为 x 的 upper_bound hint, 当前上界为 None (即 +∞) 时用 hint 收窄。"""
    if target_vars is None:
        target_vars = list(var_bounds.keys())

    hints = extract_hints_from_text(source, target_vars)
    if not hints:
        return var_bounds

    refined = {}
    for var, (lo, hi) in var_bounds.items():
        var_hints = [h for h in hints if h.var == var]
        new_lo, new_hi = lo, hi
        for h in var_hints:
            if hi is None and h.upper_bound is not None:
                new_hi = h.upper_bound
            if lo is None and h.lower_bound is not None:
                new_lo = h.lower_bound
        refined[var] = (new_lo, new_hi)
    return refined


def asip_filter_by_path(
    source: str,
    candidates: List,
) -> List:
    """路径条件感知过滤, 复用路径条件对象生命周期 (Path-Conditioned Object Lifecycle) 约束提取器。对 约束求解 (Constraint Solving) 判定 VULN 的候选检查 alloc 路径与 write 路径是否互斥, 仅处理源码级候选。"""
    from analysis.uaf_path_lifecycle_constraints import (
        extract_path_conditions, check_path_mutex,
    )
    lines = source.split('\n')
    kept = []
    for c in candidates:
        alloc_line = _extract_alloc_line(c)
        write_line = _extract_write_line(c)
        if alloc_line < 0 or write_line < 0:
            kept.append(c)
            continue

        alloc_idx = max(0, alloc_line - 1)
        write_idx = max(0, write_line - 1)
        if alloc_idx >= len(lines) or write_idx >= len(lines):
            kept.append(c)
            continue

        alloc_conds = extract_path_conditions(lines, alloc_idx)
        write_conds = extract_path_conditions(lines, write_idx)

        if alloc_conds and write_conds:
            is_mutex, _ = check_path_mutex(alloc_conds, write_conds)
            if is_mutex:
                continue  # 路径互斥, 过滤

        kept.append(c)
    return kept


def asip_source_enhance(
    source: str,
    candidates: List,
    var_bounds: Dict[str, Tuple[Optional[int], Optional[int]]] = None,
) -> Tuple[List, Dict]:
    """一键增强: 受提示拓宽 + 路径条件过滤.

    返回 (filtered_candidates, refined_bounds).
    """
    if var_bounds is None:
        var_bounds = {}

    refined = asip_refine_intervals(source, var_bounds)
    filtered = asip_filter_by_path(source, candidates)
    return filtered, refined


def _extract_alloc_line(candidate) -> int:
    if hasattr(candidate, 'alloc_site'):
        site = candidate.alloc_site
        if hasattr(site, 'pc'):
            return site.pc + 1  # 0-indexed 转 1-indexed
        if hasattr(site, 'line'):
            return site.line
    return -1


def _extract_write_line(candidate) -> int:
    if hasattr(candidate, 'overflow_store'):
        store = candidate.overflow_store
        if hasattr(store, 'pc'):
            return store.pc + 1
        if hasattr(store, 'line'):
            return store.line
    return -1


__all__ = [
    'asip_refine_intervals', 'asip_filter_by_path',
    'asip_source_enhance',
]
