"""
ASIP源码级管线 — 将ASIP误报削减集成到源码级检测流程.

源码级检测(GAPSBV-CJ)的误报根因与汇编级不同:
  1. 源码级无需间接约束传播(变量名直接可见)
  2. 源码级核心误报源: widen过激进 + alloc-write粗粒度配对
  3. 源码级增强: 受提示拓宽 + 路径条件感知过滤(复用PCOL思路)

本模块实现:
  1. asip_refine_intervals: 用guard hints收窄区间域变量边界
  2. asip_filter_by_path: 路径条件感知过滤(对CJ VULN判定)
  3. asip_source_enhance: 一键增强入口
"""

import re
from typing import Dict, List, Optional, Tuple

from modules.patching.src.asip_hinted_widen import (
    WideningHint, extract_hints_from_text, widen_with_hints,
)


def asip_refine_intervals(
    source: str,
    var_bounds: Dict[str, Tuple[Optional[int], Optional[int]]],
    target_vars: List[str] = None,
) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
    """用源码中的guard条件收窄区间域变量边界.

    扫描if(x<=N)模式, 将N作为x的upper_bound hint.
    若当前x的上界为None(即+∞), 用hint收窄.
    """
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
    """路径条件感知过滤: 复用PCOL约束提取器.

    对CJ判定VULN的候选, 检查alloc路径与write路径是否互斥.
    仅处理源码级候选, 不修改汇编级候选.
    """
    from analysis.uaf_pcol_constraints import (
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
                continue  # 路径互斥 → 过滤

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
            return site.pc + 1  # 0-indexed → 1-indexed
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
