# Heap overflow false positive reducer.
# Three-pass pipeline: taint -> interval abstraction -> path feasibility.
#
# Pass 1 (taint): malloc(n) with user-controlled n -> dynamic size, downgrade confidence.
# Pass 2 (interval): store offset interval entirely within allocation -> safe, remove.
# Pass 3 (path): alloc and store not on the same feasible path -> unreachable, remove.
#
# Each pass runs independently, ordered by determinism. Pass 2 can definitively
# rule out false positives (offset interval within bounds). Passes 1 and 3 only
# downgrade confidence (taint/path conditions are uncertain without symbolic execution).
#
# Non-invasive: operates as a post-processing filter at the end of the detection pipeline.

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FilterResult:
    """Filter result statistics for measuring method effectiveness."""
    candidates_before: int
    candidates_after: int
    removed_by_taint: int       # Pass 1 downgrades/removals
    removed_by_interval: int    # Pass 2 safe removals
    removed_by_path: int        # Pass 3 infeasible removals
    fp_reduction_ratio: float   # FP reduction ratio = removed/total


def apply_fp_filters(
    candidates: List[Any],
    disasm_lines: List[str] = None,
) -> Tuple[List[Any], FilterResult]:
    """Apply the three-pass false positive filter to a candidate list.

    Args:
        candidates: HeapOverflowCandidate list (from detect_heap_overflow)
        disasm_lines: disassembly lines (optional, for Pass 2 and 3)

    Returns:
        (filtered candidates, filter statistics)
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

        # Pass 1: taint filtering
        if _check_taint(c):
            # Downgrade but don't remove: dynamic sizes reduce confidence, not certainty
            if hasattr(c, 'confidence'):
                c.confidence = max(0.1, c.confidence * 0.4)
            removed_taint += 1
            # Still kept in the filtered list (low confidence)

        # Pass 2: interval abstraction - precise safety determination
        if (alloc_size > 0 and store_offset >= 0 and
                store_offset < alloc_size):
            # offset fully within allocation -> safe, remove
            removed_interval += 1
            keep = False
        elif (alloc_size > 0 and store_offset > alloc_size * 10 and
                hasattr(c, 'confidence')):
            # offset far exceeds allocation (10x+) -> likely true positive
            c.confidence = min(1.0, getattr(c, 'confidence', 0.5) + 0.2)

        # Pass 3: path feasibility - only for high-confidence candidates
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
    """Check if the candidate allocation size is tainted (dynamic size)."""
    if hasattr(candidate, 'alloc_site'):
        alloc = candidate.alloc_site
        if hasattr(alloc, 'size_is_dynamic') and alloc.size_is_dynamic:
            return True
    return False


__all__ = ["FilterResult", "apply_fp_filters"]
