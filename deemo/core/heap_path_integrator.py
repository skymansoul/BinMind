"""
Path-sensitive integrator for heap overflow ensemble — bridges
cfg_path_splitter with the 3-engine ensemble filter to prevent
merged-path guard correlation from suppressing real overflows.

Problem: When a function has both guarded and unguarded write paths
(e.g., heap_fp_05), the merged-path guard correlation sees a guard
and votes SUPPRESS — losing a real overflow on the unguarded path.

Solution: Before ensemble voting, check if the write site is in a
multi-path region. If so, invoke CfgPathSplitter to decompose into
individual paths. Vote on each path independently:
  - If ANY path shows overflow → KEEP (preserve TP)
  - Only if ALL paths are safe → SUPPRESS (safe FP reduction)

Novelty: This is "path-aware committee voting" — unlike standard
ensemble methods that vote on the merged analysis, we fork the
analysis at branch points and vote per-path before re-aggregating.
"""

from dataclasses import dataclass, field
import re
from typing import Any, Dict, List, Optional, Tuple

from core.cfg_path_splitter import (
    CfgPathSplitter, PathSplitResult, PathState,
)


@dataclass
class PathIntegratorResult:
    """Integration result for a single write site."""
    write_line: int
    path_result: Optional[PathSplitResult] = None
    is_multi_path: bool = False
    # Original ensemble votes (pre-split)
    original_verdict: str = 'KEEP'
    # Path-aware verdict
    path_verdict: str = 'KEEP'
    # Final: path-aware overrides ensemble if paths disagree
    final_verdict: str = 'KEEP'
    confidence: float = 0.50
    detail: str = ''


class HeapPathIntegrator:
    """Path-sensitive integrator for heap ensemble detection.

    Usage:
      integrator = HeapPathIntegrator()
      result = integrator.integrate(ir_lines, write_line,
                                     ensemble_verdict, ensemble_confidence)
    """

    def __init__(self, max_paths: int = 64):
        self._splitter = CfgPathSplitter(max_paths=max_paths)
        self.stats: Dict[str, int] = {}

    def integrate(
        self,
        ir_lines: List[str],
        write_line: int,
        ensemble_verdict: str = 'KEEP',
        ensemble_confidence: float = 0.50,
    ) -> PathIntegratorResult:
        """Run path-sensitive analysis and merge with ensemble verdict.

        Strategy:
          1. Run path splitter at write_line
          2. If single path: trust ensemble (no merging ambiguity)
          3. If multi-path with safe paths: ensemble may be wrong → REVIEW
          4. If multi-path all overflow: confirm ensemble KEEP
        """
        result = PathIntegratorResult(
            write_line=write_line,
            original_verdict=ensemble_verdict,
        )

        path = self._splitter.analyze(ir_lines, write_line)
        result.path_result = path

        if path.total_paths <= 1:
            # Single path: no merging ambiguity, trust ensemble
            result.is_multi_path = False
            result.path_verdict = ensemble_verdict
            result.final_verdict = ensemble_verdict
            result.confidence = ensemble_confidence
            result.detail = 'single_path'
            return result

        result.is_multi_path = True

        # Multi-path: evaluate per-path safety
        if path.overflow_paths > 0 and path.safe_paths == 0:
            # All paths overflow → confirmed vulnerability
            result.path_verdict = 'KEEP'
            result.confidence = min(0.90, ensemble_confidence + 0.15)
            result.detail = f'{path.overflow_paths} overflow paths, 0 safe'
        elif path.overflow_paths > 0 and path.safe_paths > 0:
            # Some safe, some overflow → REVIEW (real bug on some path)
            # Don't suppress — there IS an overflow path
            result.path_verdict = 'KEEP'
            result.confidence = max(0.55, ensemble_confidence - 0.10)
            result.detail = (f'{path.safe_paths} safe + '
                           f'{path.overflow_paths} overflow paths')
        elif path.overflow_paths == 0 and path.safe_paths > 0:
            # All paths safe → definite FP, suppress
            result.path_verdict = 'SUPPRESS'
            result.confidence = 0.85
            result.detail = f'all {path.safe_paths} paths safe'
        else:
            # Dead paths only → can't decide, trust ensemble
            result.path_verdict = ensemble_verdict
            result.confidence = ensemble_confidence
            result.detail = f'{path.dead_paths} dead paths, no live paths'

        # Final: path-aware overrides ensemble when paths disagree
        # Conservative: if path says SUPPRESS and ensemble says KEEP → REVIEW
        if (result.path_verdict == 'SUPPRESS' and
                ensemble_verdict == 'KEEP'):
            result.final_verdict = 'REVIEW'
            result.confidence = 0.45
            result.detail += '; ensemble/path conflict→REVIEW'
        elif (result.path_verdict == 'KEEP' and
              ensemble_verdict == 'SUPPRESS'):
            # Path analysis found an overflow path, don't suppress
            result.final_verdict = 'REVIEW'
            result.confidence = 0.55
            result.detail += '; path found overflow despite ensemble SUPPRESS'
        else:
            result.final_verdict = result.path_verdict

        return result

    def integrate_all(
        self,
        ir_lines: List[str],
        candidates: List[Dict],
        decisions: List[Any],
    ) -> Tuple[List[PathIntegratorResult], Dict[str, int]]:
        """Integrate path analysis across all candidates.

        Args:
            ir_lines: IR lines from source_ir_extractor
            candidates: candidate dicts with 'line', 'alloc_var', etc.
            decisions: ensemble decisions with .verdict attribute

        Returns:
            (integration_results, stats)
        """
        results = []
        suppressed = kept = review = 0

        for i, (cand, dec) in enumerate(zip(candidates, decisions)):
            write_line = cand.get('line', 0)
            ensemble_v = getattr(dec, 'verdict', 'KEEP')
            ensemble_c = getattr(dec, 'ensemble_score', 0.50)

            ir = self.integrate(
                ir_lines, write_line, ensemble_v, ensemble_c)

            if ir.final_verdict == 'SUPPRESS':
                suppressed += 1
            elif ir.final_verdict == 'KEEP':
                kept += 1
            else:
                review += 1

            results.append(ir)

        self.stats = {
            'total': len(results),
            'multi_path': sum(1 for r in results if r.is_multi_path),
            'suppressed': suppressed,
            'kept': kept,
            'review': review,
            'path_overrides': sum(
                1 for r in results
                if r.original_verdict != r.final_verdict),
        }
        return results, self.stats


def integrate_path_analysis(
    ir_lines: List[str],
    candidates: List[Dict],
    decisions: List[Any],
) -> Tuple[List[PathIntegratorResult], Dict[str, int]]:
    """Convenience: run path-aware integration on ensemble results."""
    integrator = HeapPathIntegrator()
    return integrator.integrate_all(ir_lines, candidates, decisions)


__all__ = [
    'PathIntegratorResult', 'HeapPathIntegrator',
    'integrate_path_analysis',
]
