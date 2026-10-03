# heap_fp_reducer.py - 堆溢出误报压缩器, 三趟过滤: 污点→区间抽象→路径可行性。
# 污点趟与路径趟仅降级置信度, 区间趟可确定性剔除; 作为管线末端的非侵入式后处理过滤器。

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FilterResult:
    """过滤结果统计, 用于衡量方法有效性。"""
    candidates_before: int
    candidates_after: int
    removed_by_taint: int       # 污点趟降级/移除数
    removed_by_interval: int    # 区间趟安全移除数
    removed_by_path: int        # 路径趟不可行移除数
    fp_reduction_ratio: float   # 误报缩减比例 = 移除数/总数


def apply_fp_filters(
    candidates: List[Any],
    disasm_lines: List[str] = None,
) -> Tuple[List[Any], FilterResult]:
    """对候选列表执行三趟误报过滤, 返回 (过滤后候选, 过滤统计)。

    candidates: 堆溢出候选列表; disasm_lines: 反汇编行 (供趟2/3使用)。
    """
    before = len(candidates)
    removed_taint = 0
    removed_interval = 0
    removed_path = 0

    if not candidates:
        return [], FilterResult(0, 0, 0, 0, 0, 0.0)

    filtered = []
    for c in candidates:
        keep = True
        alloc_size = _get_alloc_size(c)
        store_offset = _get_store_offset(c)

        # 趟1: 污点过滤
        if _check_taint(c):
            # 仅降级不移除: 动态大小降低置信度而非确定性
            if hasattr(c, 'confidence'):
                c.confidence = max(0.1, c.confidence * 0.4)
            removed_taint += 1
            # 仍保留在过滤列表中 (低置信度)

        # 趟2: 区间抽象 — 确定性安全判定
        if (alloc_size > 0 and store_offset >= 0 and
                store_offset < alloc_size):
            # 偏移完全落在分配内 → 安全, 移除
            removed_interval += 1
            keep = False
        elif (alloc_size > 0 and store_offset > alloc_size * 10 and
                hasattr(c, 'confidence')):
            # 偏移远超分配 (10倍以上) → 视为真阳性
            c.confidence = min(1.0, getattr(c, 'confidence', 0.5) + 0.2)

        # 趟3: 路径可行性 — 仅对高置信度候选执行
        if keep and disasm_lines and hasattr(c, 'alloc_site') and hasattr(c, 'overflow_store'):
            try:
                from core.path_feasibility import check_path_feasibility
                alloc_idx = getattr(c.alloc_site, 'pc', -1)
                store_idx = getattr(c.overflow_store, 'pc', -1)
                if alloc_idx >= 0 and store_idx >= 0:
                    verdict = check_path_feasibility(
                        disasm_lines, alloc_idx, store_idx)
                    if not verdict.feasible:
                        removed_path += 1
                        keep = False
            except ImportError:
                pass

        if keep:
            filtered.append(c)

    after = len(filtered)
    total_removed = before - after
    ratio = total_removed / max(before, 1)

    return filtered, FilterResult(
        candidates_before=before,
        candidates_after=after,
        removed_by_taint=removed_taint,
        removed_by_interval=removed_interval,
        removed_by_path=removed_path,
        fp_reduction_ratio=round(ratio, 3),
    )


def _get_alloc_size(candidate: Any) -> int:
    if hasattr(candidate, 'alloc_site'):
        return getattr(candidate.alloc_site, 'size_arg', -1)
    return -1


def _get_store_offset(candidate: Any) -> int:
    if hasattr(candidate, 'overflow_store'):
        return getattr(candidate.overflow_store, 'offset', -1)
    return -1


def _check_taint(candidate: Any) -> bool:
    """检查候选分配大小是否被污点化 (动态大小)。"""
    if hasattr(candidate, 'alloc_site'):
        alloc = candidate.alloc_site
        if hasattr(alloc, 'size_is_dynamic') and alloc.size_is_dynamic:
            return True
    return False


__all__ = ["FilterResult", "apply_fp_filters"]
