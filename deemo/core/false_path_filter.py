# false_path_filter.py — 路径可行性过滤, 用 IntervalAbstractor 检测矛盾约束。
# 保守策略: 无法判定时保留结果, 不产生漏报。
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
