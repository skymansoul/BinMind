"""FP root cause classifier for heap overflow detection, systematically categorizes
false positive sources to guide algorithmic improvement.

Root cause taxonomy (5 categories):
  R1 — Missing guard correlation: write guarded by if-check but not correlated
  R2 — Alignment over-approximation: allocator padding absorbs small overshoot
  R3 — Alias resolution failure: write targets different buffer than alloc
  R4 — Dead path: write on path that never executes (dominated by return/goto)
  R5 — Symbolic size explosion: user-controlled alloc size → interval TOP

Each category maps to a specific algorithmic fix module.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class FpCause:
    """One classified FP root cause."""
    category: str         # R1-R5
    severity: str         # HIGH | MEDIUM | LOW
    sample_id: str
    description: str
    fixable_by: str       # which module addresses this
    confidence: float     # 0-1 how certain this is the root cause

@dataclass
class FpAnalysis:
    """Aggregate FP root cause analysis for a dataset."""
    total_candidates: int; total_fp: int
    causes: List[FpCause] = field(default_factory=list)
    category_counts: Dict[str, int] = field(default_factory=dict)
    fix_priority: List[str] = field(default_factory=list)


_GUARD = re.compile(r'if\s*\(\s*(\w[\w.]*)\s*(<|<=|>|>=|==)\s*(\d+|0x[0-9a-fA-F]+)\s*\)')
_RETURN = re.compile(r'\b(?:return|goto|exit|break)\b')
_MALLOC = re.compile(r'malloc\s*\(([^)]+)\)')
_MEMCPY = re.compile(r'(?:memcpy|strcpy|memmove|strncpy)\s*\(([^)]+)\)')


class FpRootCauseAnalyzer:
    """Analyze FP root causes for heap overflow candidates."""

    def analyze_sample(self, ir: List[str], alloc_var: str = 'buf',
                       write_line: int = -1, alloc_size: int = 0,
                       write_size: int = 0, sample_id: str = '') -> FpAnalysis:
        """Analyze a single sample for FP root causes."""
        # Detect candidates from IR
        allocs = self._find_allocs(ir)
        writes = self._find_writes(ir)
        total = len(allocs) * len(writes) if writes else 0

        causes: List[FpCause] = []
        cats: Dict[str, int] = {}

        for wi, wl in enumerate(writes):
            for ai, (al_var, al_line, al_size) in enumerate(allocs):
                # R1: Guard correlation
                guards_before = self._find_guards_before(ir, wl)
                if guards_before and not self._guard_dominates_write(ir, guards_before, wl):
                    causes.append(FpCause(
                        category='R1', severity='HIGH', sample_id=sample_id,
                        description=f'Guard at L{guards_before[0][0]} not correlated with write at L{wl}',
                        fixable_by='guard_correlator.py', confidence=0.80))

                # R5: Symbolic size
                if al_size <= 0:
                    causes.append(FpCause(
                        category='R5', severity='HIGH', sample_id=sample_id,
                        description=f'Alloc size at L{al_line} is symbolic/TOP',
                        fixable_by='taint_propagator.py + value_flow_slicer.py', confidence=0.90))

                # R2: Small overshoot
                if al_size > 0 and write_size > al_size and write_size - al_size <= 8:
                    causes.append(FpCause(
                        category='R2', severity='LOW', sample_id=sample_id,
                        description=f'Write({write_size}B) exceeds alloc({al_size}B) by {write_size - al_size}B — alignment may absorb',
                        fixable_by='allocator_model.py', confidence=0.60))

        for c in causes:
            cats[c.category] = cats.get(c.category, 0) + 1

        # Priority: most frequent + most severe first
        priority = sorted(cats.keys(),
                         key=lambda k: (-cats[k], k == 'R1' or k == 'R5'))

        return FpAnalysis(total_candidates=total,
                         total_fp=len(causes),
                         causes=causes,
                         category_counts=cats,
                         fix_priority=priority)

    def _find_allocs(self, ir: List[str]) -> List[Tuple[str, int, int]]:
        """Find all heap allocations: (var, line, size_const or -1)."""
        results = []
        for i, line in enumerate(ir):
            m = re.search(r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*malloc\s*\(\s*([^)]+)\s*\)', line)
            if m:
                try:
                    sz = int(m.group(2).strip(), 0)
                except ValueError:
                    sz = -1
                results.append((m.group(1), i, sz))
        return results

    def _find_writes(self, ir: List[str]) -> List[int]:
        """Find line indices of heap write operations."""
        return [i for i, line in enumerate(ir)
                if _MEMCPY.search(line)]

    def _find_guards_before(self, ir: List[str], before: int) -> List[Tuple[int, str, str, int]]:
        """Find guard conditions before a line."""
        guards = []
        for i in range(max(0, before - 30), before):
            m = _GUARD.search(ir[i])
            if m:
                try:
                    guards.append((i, m.group(1), m.group(2), int(m.group(3), 0)))
                except ValueError: pass
        return guards

    def _guard_dominates_write(self, ir: List[str],
                               guards: List[Tuple], write_line: int) -> bool:
        """Check if any guard dominates the write line."""
        for gl, _, _, _ in guards:
            if gl >= write_line:
                continue
            # Check if write is within scope
            depth, started = 0, False
            for j in range(gl, min(len(ir), write_line + 1)):
                if '{' in ir[j]: depth += 1; started = True
                if '}' in ir[j]:
                    depth -= 1
                    if depth <= 0 and started and j < write_line:
                        break
            else:
                if started and depth > 0:
                    return True
        return False


def classify_fp_sample(ir_lines: List[str], sample_id: str = '') -> FpAnalysis:
    """Convenience: classify FP root causes for one sample."""
    ana = FpRootCauseAnalyzer()
    return ana.analyze_sample(ir_lines, sample_id=sample_id)


__all__ = ['FpCause', 'FpAnalysis', 'FpRootCauseAnalyzer', 'classify_fp_sample']
