# core/false_path_filter.py
# Filters false positives by checking path condition feasibility.
# Uses IntervalAbstractor to detect contradictory constraints.
# Conservative: when in doubt, keep the finding (no false negatives).
import re
from typing import List, Set
from core.interval_abstractor import IntervalAbstractor

class FalsePathFilter:
    _COND_PAT = re.compile(r'(?:if|while|for)\s*\(([^)]+)\)')
    def __init__(self):
        self.abstractor = IntervalAbstractor()
    def filter(self, pseudocode: str, vuln_lines: Set[int]) -> List[int]:
        if not pseudocode or not vuln_lines:
            return list(vuln_lines)
        lines = pseudocode.splitlines()
        filtered = []
        conds = self._extract_conditions(lines)
        for vline in vuln_lines:
            path_conds = [c for c in conds if c['line'] < vline]
            if self._is_path_feasible(path_conds):
                filtered.append(vline)
        return filtered
    def _extract_conditions(self, lines: List[str]) -> List[dict]:
        conds = []
        for i, line in enumerate(lines):
            m = self._COND_PAT.search(line.strip())
            if m:
                expr = m.group(1).strip()
                simple = self._simplify(expr)
                if simple:
                    conds.append({'line': i, 'simple': simple})
        return conds
    @staticmethod
    def _simplify(expr: str) -> str:
        m = re.match(r'(\w+)\s*(>=?|<=?|==)\s*(-?\d+(?:\.\d+)?)', expr.strip())
        return expr.strip() if m else ''
    def _is_path_feasible(self, conds: List[dict]) -> bool:
        self.abstractor = IntervalAbstractor()
        for c in conds:
            if c['simple'] and not self.abstractor.is_feasible(c['simple']):
                return False
        return True

__all__ = ['FalsePathFilter']
