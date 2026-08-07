"""
Heap overflow verification — allocator-aware interval comparison + relational check.

 modularity constraint.

Contains:
  - verify_overflow(): alloc-vs-write interval comparison with dual boundary logic
  - apply_relational_check(): write_size = alloc_size * k (k > 1) pattern detection
"""

from __future__ import annotations

import re as _re
from typing import Dict, List, Optional, Tuple

from core.forward_interval_prop import Interval, AllocSite, WriteSite
from core.allocator_model import (
    AllocatorType, effective_chunk_size,
)
from core.loop_bound_widening import LoopInfo

def verify_overflow(
    alloc: AllocSite,
    write: WriteSite,
    alloc_iv: Interval,
    write_iv: Interval,
    arch_bits: int,
    allocator: AllocatorType,
    loop_info: Optional[LoopInfo],
    is_loop_write: bool = False,
) -> Tuple[str, float, float, int, int, int]:
    """Verify whether alloc_iv can safely contain write_iv.

    Returns (verdict, confidence, fp_likelihood, effective_boundary,
             overflow_min, overflow_max).
    """
    # Both intervals unknown → truly uncertain
    if alloc_iv.is_top and write_iv.is_top:
        return 'UNCERTAIN', 0.20, 0.50, 0, 0, 0

    # Alloc concrete but write variable → plausible overflow (CVE pattern)
    if write_iv.is_top and not alloc_iv.is_top:
        alloc_hi = alloc_iv.hi if alloc_iv.hi < 2**63 - 1 else alloc_iv.lo
        if alloc_hi > 0:
            eff_chunk = effective_chunk_size(alloc_hi, allocator, arch_bits)
            return 'CONFIRMED', 0.60, 0.35, eff_chunk, 0, 0
        return 'UNCERTAIN', 0.35, 0.50, 0, 0, 0

    # Write concrete but alloc variable
    if alloc_iv.is_top and not write_iv.is_top:
        return 'UNCERTAIN', 0.40, 0.40, 0, 0, 0

    alloc_hi = alloc_iv.hi if alloc_iv.hi < 2**63 - 1 else alloc_iv.lo
    if alloc_hi <= 0:
        return 'UNCERTAIN', 0.25, 0.50, 0, 0, 0

    write_lo = write_iv.lo if write_iv.lo >= 0 else 0
    write_hi = write_iv.hi if write_iv.hi < 2**63 - 1 else write_lo

    eff_chunk = effective_chunk_size(alloc_hi, allocator, arch_bits)

    # Decision boundary: eff_chunk for physical safety,
    # raw alloc for loop-synthesized writes (offset baked into size)
    boundary = alloc_hi if is_loop_write else eff_chunk

    ov_min = write_lo - boundary if write_lo > boundary else 0
    ov_max = write_hi - boundary if write_hi > boundary else 0

    if write_lo > boundary:
        confidence = 0.85 + (0.10 if loop_info and not loop_info.is_dynamic
                             else 0.0)
        return 'CONFIRMED', min(confidence, 0.95), 0.05, \
            boundary, ov_min, ov_max
    elif write_hi > boundary and write_lo <= boundary:
        overshoot = write_hi - boundary
        if overshoot <= 8:
            return 'FILTERED', 0.25, 0.80, boundary, 0, overshoot
        else:
            return 'UNCERTAIN', 0.45, 0.40, boundary, 0, overshoot
    else:
        return 'FILTERED', 0.10, 0.95, boundary, 0, 0

def apply_relational_check(
    ir_lines: List[str],
    candidates: List,
) -> List:
    """Detect write_size = alloc_size * k (k > 1) patterns.

    Even when both intervals are TOP, this relational constraint proves
    overflow: write = M * alloc → write > alloc by construction.
    e.g., CVE-2024-21762: decoded_len = body_len * 2, memcpy uses decoded_len
    """
    # Extract alloc result → size variable mapping
    alloc_sz_of: Dict[str, str] = {}
    for line in ir_lines:
        am = _re.search(
            r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*'
            r'(?:malloc|calloc|realloc)\s*\(\s*(\w[\w.]*)\s*[^)]*\)',
            line)
        if am:
            alloc_sz_of[am.group(1)] = am.group(2)

    # Extract size relations: result = base * factor
    relations: Dict[str, Tuple[str, int]] = {}
    for line in ir_lines:
        rm = _re.search(
            r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*\*\s*(\d+)\s*;', line)
        if rm:
            relations[rm.group(1)] = (rm.group(2), int(rm.group(3)))

    for cand in candidates:
        if cand.verdict == 'CONFIRMED':
            continue

        alloc_res = cand.alloc_site.var_name
        alloc_sz = alloc_sz_of.get(alloc_res, '')
        if not alloc_sz:
            continue

        wl = cand.write_site.loc
        if wl >= len(ir_lines):
            continue
        wline = ir_lines[wl]
        wm = _re.search(
            r'(?:memcpy|memmove|strncpy|strcpy|sprintf)\s*\(\s*'
            r'\w[\w.]*\s*,\s*[^,]*,\s*(\w[\w.]*)\s*\)', wline)
        if not wm:
            continue
        write_sz = wm.group(1)

        if write_sz in relations:
            base, factor = relations[write_sz]
            if base == alloc_sz and factor > 1:
                cand.verdict = 'CONFIRMED'
                cand.confidence = max(cand.confidence, 0.72)
                cand.fp_likelihood = min(cand.fp_likelihood, 0.20)
                cand.overflow_bytes_min = factor - 1

    return candidates

__all__ = ['verify_overflow', 'apply_relational_check']
