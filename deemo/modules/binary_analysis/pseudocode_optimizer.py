import logging
import re
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from collections import defaultdict

logger = logging.getLogger(__name__)


@dataclass
class OptimizationResult:
    func_name: str
    lines_before: int
    lines_after: int
    dead_code_removed: int = 0
    constants_folded: int = 0
    casts_removed: int = 0
    branches_simplified: int = 0
    reduction_percent: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'func_name': self.func_name,
            'lines_before': self.lines_before,
            'lines_after': self.lines_after,
            'dead_code_removed': self.dead_code_removed,
            'constants_folded': self.constants_folded,
            'reduction': f'{self.reduction_percent:.1f}%'
        }


class PseudocodeOptimizer:
    """Decompiled code optimizer."""

    CONSTANT_FOLD_PATTERNS = [
        (r'\(\s*(-?\d+)\s*\)', r'\1'),
        (r'\(\s*\(\s*(?:unsigned\s+)?int\d+_t\s*\)\s*(-?\d+)\s*\)', r'\1'),
        (r'\(\s*\(\s*(?:unsigned\s+)?char\s*\)\s*(\d+)\s*\)', r'\1'),
    ]

    DEAD_CODE_PATTERNS = [
        r'if\s*\(\s*0\s*\)\s*\{[^}]*\}',
        r'if\s*\(\s*1\s*\)\s*\{\s*\}',
        r'while\s*\(\s*0\s*\)\s*\{[^}]*\}',
    ]

    def __init__(self):
        self._optimizations: List[OptimizationResult] = []
        self._total_dead = 0
        self._total_constants = 0
        self._total_casts = 0

    def optimize(self, code: str, func_name: str = "") -> OptimizationResult:
        lines_before = len(code.strip().split('\n'))
        optimized = code

        for pattern, replacement in self.CONSTANT_FOLD_PATTERNS:
            matches = len(re.findall(pattern, optimized))
            if matches:
                self._total_constants += matches
                optimized = re.sub(pattern, replacement, optimized)

        for pattern in self.DEAD_CODE_PATTERNS:
            matches = len(re.findall(pattern, optimized))
            if matches:
                self._total_dead += matches
                optimized = re.sub(pattern, '', optimized)

        cast_pattern = r'\(\s*(?:int|unsigned int|uint32_t|uint64_t|char|short)\s*\)\s*\(\s*((?:int|unsigned int|uint32_t|uint64_t|char|short)\s*\)\s*\w+\s*\))'
        cast_matches = len(re.findall(cast_pattern, optimized))
        if cast_matches:
            self._total_casts += cast_matches

        optimized = re.sub(r'\n\s*\n\s*\n', '\n\n', optimized)

        lines_after = len(optimized.strip().split('\n'))
        reduction = (1 - lines_after / max(1, lines_before)) * 100

        result = OptimizationResult(
            func_name=func_name,
            lines_before=lines_before,
            lines_after=lines_after,
            dead_code_removed=cast_matches + sum(
                len(re.findall(p, optimized)) for p in self.DEAD_CODE_PATTERNS),
            constants_folded=self._total_constants,
            casts_removed=cast_matches,
            reduction_percent=round(reduction, 1))
        self._optimizations.append(result)
        return result

    def analyze(self, code_snippets: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        if code_snippets:
            for snippet in code_snippets:
                self.optimize(
                    snippet.get('code', ''),
                    snippet.get('func_name', 'unknown'))

        total_before = sum(o.lines_before for o in self._optimizations)
        total_after = sum(o.lines_after for o in self._optimizations)

        return {
            'success': True,
            'total_functions': len(self._optimizations),
            'total_lines_before': total_before,
            'total_lines_after': total_after,
            'overall_reduction': f'{(1 - total_after / max(1, total_before)) * 100:.1f}%',
            'optimizations': [o.to_dict() for o in self._optimizations[:20]],
            'stats': {
                'dead_code_eliminated': self._total_dead,
                'constants_folded': self._total_constants,
                'casts_removed': self._total_casts,
            }
        }


def optimize_pseudocode(code_snippets: List[Dict[str, Any]],
                         **kwargs) -> Dict[str, Any]:
    optimizer = PseudocodeOptimizer()
    return optimizer.analyze(code_snippets=code_snippets)


__all__ = ["PseudocodeOptimizer", "OptimizationResult", "optimize_pseudocode"]
