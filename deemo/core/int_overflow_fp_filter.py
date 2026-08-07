"""
Integer overflow FP filter — three-stage false positive suppression for
integer overflow leading to heap buffer overflow (CWE-190/CWE-191/CWE-680).

Stage G (Guard): overflow-check guard detection — if (n > MAX/size) return
Stage T (Type): type-widening analysis — size_t arithmetic eliminates wraps
Stage C (Constant): constant folding — compile-time expressions are safe

Ensemble: weighted majority vote across G+T+C stages.
  Unanimous SUPPRESS → FILTERED; 2:1 → SUPPRESS; split → REVIEW.

Rationale: existing int_overflow_detector marks all multiply-in-alloc as
suspicious. Most are guarded or use size_t arithmetic → FP.
"""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# patterns ─────────────────────────────────────────────────────────────

_OVERFLOW_GUARD = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*[><=!]+\s*(\d+|0x[0-9a-fA-F]+)\s*/\s*sizeof')
_SAFE_MAX = re.compile(
    r'if\s*\(\s*(\w[\w.]*)\s*>\s*(?:SIZE_MAX|UINT_MAX|INT_MAX|0x[7F]+\s*)\s*/\s*')
_SIZET_VAR = re.compile(r'\b(?:size_t|uint64_t|uint32_t|unsigned\s+long\s+long)\s+(\w[\w.]*)')
_MUL_IN_ALLOC = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\([^)]*\))?\s*malloc\s*\(\s*(\w[\w.]*)\s*\*\s*(\w[\w.]*|sizeof\([^)]+\))\s*\)')
_CONST_MUL = re.compile(r'malloc\s*\(\s*(\d+)\s*\*\s*(\d+|sizeof\([^)]+\))\s*\)')


# datatypes ────────────────────────────────────────────────────────────

@dataclass
class IntOverflowCandidate:
    """Integer overflow candidate at a malloc site."""
    line: int; line_text: str; alloc_var: str = ''
    mul_left: str = ''; mul_right: str = ''
    verdict: str = 'UNCERTAIN'
    confidence: float = 0.50; fp_likelihood: float = 0.50

@dataclass
class IoDecision:
    """FP filter decision for one integer overflow candidate."""
    candidate: IntOverflowCandidate
    guard_detected: bool = False; guard_detail: str = ''
    sizet_typed: bool = False; sizet_detail: str = ''
    constant_folded: bool = False
    verdict: str = 'REVIEW'; score: float = 0.50


# engine ───────────────────────────────────────────────────────────────

class IntOverflowFpFilter:
    """Three-stage integer overflow FP filter."""

    def __init__(self):
        self.stats: Dict[str, Any] = {}

    def filter(
        self, ir_lines: List[str],
        candidates: List[IntOverflowCandidate],
    ) -> List[IoDecision]:
        """Run Stage G+T+C on each candidate, return ensemble decisions."""
        decisions = []
        for cand in candidates:
            dec = IoDecision(candidate=cand)

            # Stage G: overflow guard
            dec.guard_detected, dec.guard_detail = self._stage_guard(
                ir_lines, cand)

            # Stage T: type widening
            dec.sizet_typed, dec.sizet_detail = self._stage_type(
                ir_lines, cand)

            # Stage C: constant folding
            dec.constant_folded = self._stage_constant(cand)

            # Ensemble: weighted vote
            dec.verdict, dec.score = self._decide(dec)
            decisions.append(dec)

        self.stats = {
            'total': len(candidates),
            'suppressed': sum(1 for d in decisions if d.verdict == 'SUPPRESS'),
            'review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
        }
        return decisions

    # Stage G: guard detection ─────────────────────────────────────

    def _stage_guard(
        self, ir_lines: List[str], cand: IntOverflowCandidate,
    ) -> Tuple[bool, str]:
        """Detect overflow-check guards that bound multiplication operands."""
        for i in range(max(0, cand.line - 20), cand.line):
            line = ir_lines[i]
            m = _OVERFLOW_GUARD.search(line)
            if m:
                var = m.group(1)
                if var == cand.mul_left or var == cand.mul_right:
                    return True, f'L{i}: if({var} > MAX/sizeof) guard'
            sm = _SAFE_MAX.search(line)
            if sm:
                return True, f'L{i}: if({sm.group(1)} > MAX) guard'
        return False, ''

    # Stage T: type widening ───────────────────────────────────────

    def _stage_type(
        self, ir_lines: List[str], cand: IntOverflowCandidate,
    ) -> Tuple[bool, str]:
        """Check if operands use size_t — no 32-bit truncation."""
        for i in range(max(0, cand.line - 30), cand.line + 1):
            line = ir_lines[i]
            for m in _SIZET_VAR.finditer(line):
                v = m.group(1)
                if v == cand.mul_left or v == cand.mul_right:
                    return True, f'L{i}: {v} is {m.group(0).split()[0]}'
        # Check sizeof — always size_t
        if 'sizeof' in cand.mul_right or 'sizeof' in cand.mul_left:
            return True, 'sizeof operand → size_t arithmetic'
        return False, ''

    # Stage C: constant folding ────────────────────────────────────

    @staticmethod
    def _stage_constant(cand: IntOverflowCandidate) -> bool:
        """Check if multiplication is constant-foldable."""
        return bool(_CONST_MUL.search(cand.line_text))

    # decision ─────────────────────────────────────────────────────

    @staticmethod
    def _decide(dec: IoDecision) -> Tuple[str, float]:
        """Weighted vote: G(0.40) + T(0.35) + C(0.25)."""
        score = 0.0
        if dec.guard_detected:
            score += 0.40
        if dec.sizet_typed:
            score += 0.35
        if dec.constant_folded:
            score += 0.25

        if score >= 0.60:
            return 'SUPPRESS', score
        elif score <= 0.25:
            return 'KEEP', score
        return 'REVIEW', score


# extraction ───────────────────────────────────────────────────────────

def extract_int_overflow_candidates(
    ir_lines: List[str],
) -> List[IntOverflowCandidate]:
    """Extract integer overflow candidates from IR lines."""
    candidates = []
    for i, line in enumerate(ir_lines):
        m = _MUL_IN_ALLOC.search(line)
        if m:
            cand = IntOverflowCandidate(
                line=i, line_text=line.strip(),
                alloc_var=m.group(1),
                mul_left=m.group(2).strip(),
                mul_right=m.group(3).strip(),
            )
            # Skip if left/right are both constants
            try:
                int(m.group(2).strip(), 0)
                int(m.group(3).strip().replace('sizeof(int)', '4')
                       .replace('sizeof(char)', '1')
                       .replace('sizeof(char*)', '8'))
                # Both constants — not an overflow risk (Stage C handles)
                cand.constant_folded = True
            except (ValueError, AttributeError):
                pass
            candidates.append(cand)
    return candidates


def filter_int_overflow(
    ir_lines: List[str],
) -> Tuple[List[IoDecision], Dict[str, Any]]:
    """Convenience: extract + filter integer overflow candidates."""
    cands = extract_int_overflow_candidates(ir_lines)
    engine = IntOverflowFpFilter()
    decisions = engine.filter(ir_lines, cands)
    return decisions, engine.stats


__all__ = [
    'IntOverflowCandidate', 'IoDecision', 'IntOverflowFpFilter',
    'extract_int_overflow_candidates', 'filter_int_overflow',
]
