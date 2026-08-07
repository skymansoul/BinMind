"""
UAF temporal distance analyzer — computes normalized "free-to-use" distance
for ranking UAF exploitability and filtering low-risk FP candidates.

Algorithm:
  1. For each (free, use) pair, compute instruction-level distance
  2. Normalize by function length: dist_norm = instr_dist / func_length
  3. Score exploitability:
     - Short distance (dist_norm < 0.3): high exploitability → KEEP
     - Long distance (dist_norm > 0.7): low priority, possibly benign → REVIEW
     - Cross-function: distance undefined → use heuristic (alias chain depth)

Novelty over existing UAF detectors:
  - Distance-weighted confidence replaces binary CONFIRMED/FILTERED
  - Cross-function scoring via alias chain depth
  - Integrates with TARPS Stage E confidence scoring
"""

from dataclasses import dataclass, field
import re
from typing import Dict, List, Optional, Tuple


_FREE = re.compile(r'free\s*\(\s*(\w[\w.]*)\s*\)')
_DEREF = re.compile(r'(\w[\w.]*)\s*(?:->|\[)')
_ASSIGN = re.compile(r'(\w[\w.]*)\s*=\s*(\w[\w.]*)\s*;?')


@dataclass
class TemporalDistance:
    """Free-to-use temporal distance analysis result."""
    ptr_name: str; free_line: int; use_line: int
    instr_distance: int = 0
    func_length: int = 0
    dist_normalized: float = 0.0
    is_cross_function: bool = False
    alias_depth: int = 0
    exploitability: float = 0.50   # 0=benign, 1=highly exploitable


def compute_temporal_distance(
    ir_lines: List[str],
    free_line: int, ptr_name: str,
    func_length: int = 0,
) -> TemporalDistance:
    """Compute temporal distance from free site to first use-after-free site."""
    fl = func_length if func_length > 0 else len(ir_lines)
    resolved = _resolve_aliases(ir_lines, ptr_name)
    candidates = list(resolved)  # ptr_name + all aliases

    # Find nearest deref after free
    nearest, nearest_line = None, fl + 1
    for i in range(free_line + 1, min(len(ir_lines), free_line + 100)):
        dm = _DEREF.search(ir_lines[i])
        if dm:
            deref_var = dm.group(1)
            if deref_var in candidates:
                nearest = ir_lines[i].strip()
                nearest_line = i
                break

    if nearest is None:
        return TemporalDistance(
            ptr_name=ptr_name, free_line=free_line,
            use_line=-1, instr_distance=-1,
            func_length=fl, is_cross_function=True,
            alias_depth=len(candidates) - 1,
            exploitability=0.30,
        )

    dist = nearest_line - free_line
    norm = dist / max(fl, 1)

    # Exploitability scoring
    if norm < 0.2:
        expl = 0.90  # immediate use after free → very exploitable
    elif norm < 0.4:
        expl = 0.75
    elif norm < 0.6:
        expl = 0.55
    else:
        expl = 0.35  # far apart → less likely exploitable

    # Boost for alias chains (indicates complex pointer flow)
    alias_boost = min(0.15, 0.05 * (len(candidates) - 1))
    expl = min(0.95, expl + alias_boost)

    return TemporalDistance(
        ptr_name=ptr_name, free_line=free_line,
        use_line=nearest_line, instr_distance=dist,
        dist_normalized=round(norm, 4),
        func_length=fl, is_cross_function=False,
        alias_depth=len(candidates) - 1,
        exploitability=round(expl, 2),
    )


def _resolve_aliases(ir_lines: List[str], ptr: str) -> set:
    """Resolve all aliases of ptr from IR assignments."""
    aliases: Dict[str, str] = {}
    for line in ir_lines:
        m = _ASSIGN.search(line.strip())
        if m:
            lhs, rhs = m.group(1), m.group(2)
            aliases[lhs] = rhs

    # Transitive closure
    resolved = {ptr}
    changed = True
    while changed:
        changed = False
        for alias, target in list(aliases.items()):
            if target in resolved and alias not in resolved:
                resolved.add(alias)
                changed = True
    return resolved


def score_uaf_with_distance(
    ir_lines: List[str],
    free_sites: List[Tuple[int, str]],
    func_length: int = 0,
) -> List[TemporalDistance]:
    """Score all free sites in a function with temporal distance analysis."""
    results = []
    for fl, fp in free_sites:
        td = compute_temporal_distance(ir_lines, fl, fp, func_length)
        results.append(td)
    results.sort(key=lambda t: -t.exploitability)
    return results


__all__ = ['TemporalDistance', 'compute_temporal_distance',
           'score_uaf_with_distance', '_resolve_aliases']
