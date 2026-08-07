"""
Heap overflow detector with ensemble FP filter — wraps the GAPSBV 5-stage
pipeline and post-processes candidates through the 3-engine ensemble filter
(VFS + Guard Correlation + Taint Propagation) to suppress false positives.

This is the recommended entry point for heap overflow detection.
  Original pipeline → EnhancedHeapOverflowDetector (Stages 1-5)
  Ensemble filter   → EnsembleFpFilter (3-engine committee vote)

Integration: candidates from Stage 5 pass through the ensemble; any
candidate voted SUPPRESS by ≥2 engines (or unanimously) is reclassified
from CONFIRMED/UNCERTAIN → FILTERED.

Ref: ensemble_fp_filter.py, heap_overflow_enhanced.py
"""

from __future__ import annotations
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from core.heap_overflow_enhanced import (
    EnhancedHeapOverflowDetector, EnhancedHeapCandidate,
    detect_heap_overflow_enhanced,
)
from core.ensemble_fp_filter import (
    EnsembleFpFilter, EnsembleDecision,
)


# helpers ──────────────────────────────────────────────────────────────

import re as _re
_WRITE_ARGS = _re.compile(
    r'(?:memcpy|memmove|strncpy|strcpy|sprintf)\s*\(\s*[^,]+,\s*[^,]+,\s*(\w[\w.]*)')

def _extract_size_var(ir: list, wl: int) -> str:
    """Extract the size argument variable from a heap write IR line."""
    if wl < len(ir):
        m = _WRITE_ARGS.search(ir[wl])
        if m:
            return m.group(1)
    return 'len'

def _best_alloc_size(c) -> int:
    """Best-effort alloc size: effective > refined > raw."""
    if c.effective_alloc > 0:
        return c.effective_alloc
    lo = c.refined_alloc_iv.lo
    return lo if lo > 0 and lo < 2**60 else 0


# integrated detector ──────────────────────────────────────────────────

class HeapEnsembleDetector:
    """GAPSBV 5-stage pipeline + 3-engine ensemble FP filter.

    Usage:
      det = HeapEnsembleDetector(platform='x86_64')
      results = det.detect(ir_lines)
      for r in results:
          print(r.summary())
    """

    def __init__(self, platform: str = 'x86_64',
                 enable_ensemble: bool = True):
        self._pipeline = EnhancedHeapOverflowDetector(platform=platform)
        self._ensemble = EnsembleFpFilter() if enable_ensemble else None
        self.stats: Dict[str, Any] = {}

    def detect(
        self, ir_lines: List[str],
        binary_path: str = '', arch_bits: int = 64,
    ) -> Tuple[List[EnhancedHeapCandidate], List[EnsembleDecision], Dict]:
        """Run detection pipeline + optional ensemble filtering.

        Returns: (candidates, ensemble_decisions, stats)
        """
        # Stage 1-5: existing GAPSBV pipeline
        candidates = self._pipeline.detect(ir_lines, binary_path, arch_bits)
        pipeline_stats = dict(self._pipeline.stats)
        ensemble_decisions: List[EnsembleDecision] = []

        if not self._ensemble or not candidates:
            self.stats = {**pipeline_stats,
                'ensemble_enabled': self._ensemble is not None,
                'ensemble_suppressed': 0}
            return candidates, ensemble_decisions, self.stats

        # Convert candidates to ensemble input format
        cand_dicts = []
        for c in candidates:
            size_var = _extract_size_var(ir_lines, c.write_site.loc)
            cand_dicts.append({
                'line': c.write_site.loc,
                'alloc_var': c.alloc_site.var_name,
                'alloc_size': _best_alloc_size(c),
                'size_var': size_var,
                'write_func': 'memcpy',
            })

        # Stage 6: ensemble FP filtering
        decisions = self._ensemble.filter(ir_lines, cand_dicts)
        ensemble_decisions = decisions

        # Re-classify candidates based on ensemble decisions
        for i, dec in enumerate(decisions):
            if i >= len(candidates):
                break
            if dec.verdict == 'SUPPRESS':
                cand = candidates[i]
                # Only suppress non-definite overflows
                if cand.verdict in ('UNCERTAIN',):
                    cand.verdict = 'FILTERED'
                    cand.fp_likelihood = max(cand.fp_likelihood, 0.85)
                elif cand.verdict == 'CONFIRMED' and cand.confidence < 0.85:
                    # Borderline: downgrade to UNCERTAIN
                    cand.verdict = 'UNCERTAIN'
                    cand.confidence = max(cand.confidence - 0.15, 0.30)
                    cand.fp_likelihood = min(cand.fp_likelihood + 0.30, 0.95)

        suppressed = sum(1 for d in decisions if d.verdict == 'SUPPRESS')
        self.stats = {
            **pipeline_stats,
            'ensemble_enabled': True,
            'ensemble_total': len(decisions),
            'ensemble_suppressed': suppressed,
            'ensemble_review': sum(1 for d in decisions if d.verdict == 'REVIEW'),
            'ensemble_kept': sum(1 for d in decisions if d.verdict == 'KEEP'),
            'ensemble_elapsed_ms': self._ensemble.stats.get('elapsed_ms', 0),
        }
        return candidates, ensemble_decisions, self.stats

    def print_ensemble_report(
        self, candidates: List[EnhancedHeapCandidate],
        decisions: List[EnsembleDecision],
    ) -> str:
        """Generate a human-readable ensemble report."""
        lines = ['Ensemble FP Filter Report',
                 f"{'='*70}",
                 f"{'Line':5s} {'Write':35s} {'Pipeline':12s} "
                 f"{'Ensemble':12s} {'Score':7s}"]
        lines.append('-' * 70)
        for i, (c, d) in enumerate(zip(candidates, decisions)):
            if i >= len(decisions):
                break
            lines.append(
                f"{d.write_line:<5d} {d.write_text[:34]:35s} "
                f"{c.verdict:12s} {d.verdict:12s} {d.ensemble_score:.3f}")
        lines.append('-' * 70)
        lines.append(f"Total: {len(candidates)} candidates, "
                     f"{self.stats.get('ensemble_suppressed', 0)} suppressed")
        return '\n'.join(lines)


def detect_with_ensemble(
    ir_lines: List[str], binary_path: str = '', arch_bits: int = 64,
) -> Tuple[List[EnhancedHeapCandidate], List[EnsembleDecision], Dict]:
    """Convenience: detect heap overflows with ensemble FP filtering."""
    det = HeapEnsembleDetector()
    return det.detect(ir_lines, binary_path, arch_bits)


__all__ = ['HeapEnsembleDetector', 'detect_with_ensemble']
