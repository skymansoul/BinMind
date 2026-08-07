"""UAF时序路径辅助 — double-free检测(含别名间).

"""

import re
from typing import Dict, List, Set, Tuple

from analysis.uaf_temporal_path_types import (
    PtrState, TemporalVerdict, TemporalResult)
from analysis.uaf_temporal_scanner import TemporalScanner

_RETURN_RE = re.compile(r'\b(return|exit|_exit|abort)\b')


def detect_double_frees(
        frees: List[Tuple[int, int, str]],
        dead_lines: Set[int],
        aliases: List[Tuple[int, str, str]],
        alloc_lines: Dict[str, List[int]],
        lines: List[str]) -> List[TemporalResult]:
    """同变量double-free + 别名间double-free检测.

    过滤恒假条件块内的free, 并考虑return截断和中间realloc.
    """
    results: List[TemporalResult] = []
    scanner = TemporalScanner()

    raw_freed: Dict[str, List[Tuple[int, int]]] = {}
    for fl, fcol, fvar in frees:
        if fl in dead_lines:
            continue
        raw_freed.setdefault(fvar, []).append((fl, fcol))

    # 别名等价闭包用于跨变量double-free检测
    alias_groups = scanner.build_alias_closure(aliases)
    var_to_group: Dict[str, Set[str]] = {}
    for members in alias_groups.values():
        for m in members:
            var_to_group[m] = members

    # 同变量double-free: 同一变量出现两次free
    for fvar, positions in raw_freed.items():
        if len(positions) >= 2:
            for j in range(1, len(positions)):
                fl1, fc1 = positions[0]
                fl2, fc2 = positions[j]
                if fl2 <= fl1 or (fl2 == fl1 and fc2 <= fc1):
                    continue
                reallocs = alloc_lines.get(fvar, [])
                if any(fl1 < al < fl2 for al in reallocs):
                    continue
                if any(_RETURN_RE.search(lines[k])
                       for k in range(fl1, fl2)
                       if 0 <= k - 1 < len(lines)):
                    continue
                results.append(TemporalResult(
                    verdict=TemporalVerdict.DOUBLE_FREE,
                    ptr_var=fvar, free_line=fl1, use_line=fl2,
                    safe_paths=0, uaf_paths=1, total_paths=1,
                    reason=f"double-free: {fvar} freed at L{fl1} and L{fl2}"))

    # 别名间double-free: free(buf) + free(alias) 其中alias=buf
    checked = set()
    for fvar1, positions1 in raw_freed.items():
        group = var_to_group.get(fvar1, {fvar1})
        for fvar2 in group:
            if fvar2 == fvar1 or fvar2 not in raw_freed:
                continue
            pair_key = (min(fvar1, fvar2), max(fvar1, fvar2))
            if pair_key in checked:
                continue
            checked.add(pair_key)
            for p1 in positions1:
                for p2 in raw_freed[fvar2]:
                    fl1, fl2 = p1[0], p2[0]
                    if fl2 <= fl1:
                        continue
                    if any(_RETURN_RE.search(lines[k])
                           for k in range(fl1 - 1, min(fl2, len(lines)))
                           if 0 <= k < len(lines)):
                        continue
                    all_allocs = (alloc_lines.get(fvar1, [])
                                  + alloc_lines.get(fvar2, []))
                    if any(fl1 < al < fl2 for al in all_allocs):
                        continue
                    results.append(TemporalResult(
                        verdict=TemporalVerdict.DOUBLE_FREE,
                        ptr_var=fvar1, free_line=fl1, use_line=fl2,
                        safe_paths=0, uaf_paths=1, total_paths=1,
                        reason=f"double-free via alias: {fvar1}@L{fl1} "
                               f"and {fvar2}@L{fl2}"))
                    break
    return results


__all__ = ['detect_double_frees']
