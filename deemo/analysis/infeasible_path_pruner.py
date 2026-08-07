"""
不可行路径剪枝器 — 纯区间代数约束一致性检测 (无SMT).

原理:
  对每个变量的所有约束区间取交集, 任一交集为空 → 路径不可行.
  与 BINSEC/S2E 的 SMT 求解区分: O(n) 确定性计算, 不需要 Z3.

算法:
  1. 收集 Tier 1/2 产生的所有变量约束
  2. 为每个变量计算约束区间的交集
  3. 若交集为空 → 路径不可行, 报告不可行 (该路径上的候选可过滤)

补充功能:
  - guard 模式检测: if(var > N) var = N → 在 true 分支上, var∈[N+1,∞); 在赋值后 var'∈[N,N]
  - 矛盾检测: 若存在 var < 16 ∧ var > 256 → 矛盾 → 不可行
"""


import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from .symbolic_range import PathCondition, LinearInequality

_log = logging.getLogger(__name__)


@dataclass
class PruneResult:
    """剪枝结果."""
    is_feasible: bool           # 路径是否可行
    reason: str
    contradictory_vars: List[str] = field(default_factory=list)
    resolved_bounds: Dict[str, Tuple[int, int]] = field(default_factory=dict)


class InfeasiblePathPruner:
    """区间代数不可行路径检测器.

    输入: PathCondition 列表 (来自 Tier 1 分支敏感传播)
    输出: 每个路径的可行性判定

    复杂度: O(v * c) 其中 v=变量数, c=约束数.
    """

    def check(self, pc: PathCondition) -> PruneResult:
        """对单个 PathCondition 做可行性检测."""
        if not pc:
            return PruneResult(True, "空路径条件, 默认可行")

        # 收集每个变量的约束边界
        bounds: Dict[str, List[Tuple[int, int, bool]]] = {}
        for ie in pc.inequalities:
            # 只处理单变量约束 (多变量需要更复杂的区间代数)
            if len(ie.coefs) != 1:
                continue
            (var, coef), = ie.coefs.items()
            if coef == 0:
                continue

            # 归一化: coef * var + constant <= 0
            if coef > 0:
                # var <= -constant/coef
                upper = -ie.constant // coef
                bounds.setdefault(var, []).append(
                    (-10**9, upper, ie.strict))
            else:
                # var >= -constant/coef (因为 coef<0, 除以负数翻转不等号)
                lower = -(ie.constant // coef) if ie.constant % coef == 0 else -(ie.constant // coef)
                if coef < 0:
                    lower = -(ie.constant // coef) if ie.constant % coef == 0 else -(ie.constant // coef) + 1
                bounds.setdefault(var, []).append(
                    (lower, 10**9, ie.strict))

        # 区间交集计算
        resolved = {}
        contradictory = []
        for var, bs in bounds.items():
            lo = -10**9
            hi = 10**9
            for l, h, strict in bs:
                lo = max(lo, l)
                hi = min(hi, h)
            if lo > hi:
                contradictory.append(var)
            else:
                resolved[var] = (lo, hi)

        if contradictory:
            return PruneResult(
                False,
                f"变量矛盾: {contradictory}",
                contradictory_vars=contradictory,
                resolved_bounds=resolved)

        return PruneResult(True, "所有约束一致",
                           resolved_bounds=resolved)

    def check_multi(self, pcs: List[PathCondition]) -> List[PruneResult]:
        """批量检测."""
        return [self.check(pc) for pc in pcs]

    def find_contradictions(self, constraints: List[LinearInequality]
                            ) -> List[Tuple[str, int, int]]:
        """在约束列表中找出所有矛盾点.

        Returns: [(var, lo, hi), ...] 每个矛盾变量及其冲突区间.
        """
        pcs = [PathCondition(tuple(constraints))]
        results = self.check_multi(pcs)
        conflicts = []
        for r in results:
            if not r.is_feasible:
                for var in r.contradictory_vars:
                    lo, hi = r.resolved_bounds.get(var, (0, 0))
                    conflicts.append((var, lo, hi))
        return conflicts


class GuardPatternDetector:
    """守卫模式检测: 识别安全截断模式.

    模式:
      if (size > MAX) size = MAX;        → size∈[0, MAX] after sanitize
      if (size < 0)   size = 0;          → size∈[0, ∞) after sanitize
      n = min(n, limit);                 → n∈[0, limit]
      n = max(n, 0);                     → n∈[0, ∞)
    """

    # 守卫模式正则
    _GUARD_PATTERNS = [
        (r'if\s*\((\w+)\s*>\s*(\d+)\)\s*\1\s*=\s*\2', 'upper'),
        (r'if\s*\((\w+)\s*>=\s*(\d+)\)\s*\1\s*=\s*\2', 'upper'),
        (r'(\w+)\s*=\s*min\((\w+),\s*(\d+)\)', 'upper_var'),
        (r'(\w+)\s*=\s*max\((\w+),\s*(\d+)\)', 'lower_var'),
    ]

    def detect(self, text: str) -> Optional[Tuple[str, str, int]]:
        """检测单行文本中的守卫模式.

        Returns: (var, 'upper'|'lower', bound) 或 None.
        """
        import re
        tl = text.strip()

        # if (var > N) var = N;
        m = re.match(r'if\s*\((\w+)\s*>\s*(\d+)\)\s*(\w+)\s*=\s*\2', tl)
        if m and m.group(1) == m.group(3):
            return (m.group(1), 'upper', int(m.group(2)))

        # if (var >= N) var = N;
        m = re.match(r'if\s*\((\w+)\s*>=\s*(\d+)\)\s*(\w+)\s*=\s*\2', tl)
        if m and m.group(1) == m.group(3):
            return (m.group(1), 'upper', int(m.group(2)))

        # var = min(var, N)
        m = re.match(r'(\w+)\s*=\s*min\s*\((\w+)\s*,\s*(\d+)\)', tl)
        if m and m.group(1) == m.group(2):
            return (m.group(1), 'upper', int(m.group(3)))

        # var = max(var, N)
        m = re.match(r'(\w+)\s*=\s*max\s*\((\w+)\s*,\s*(\d+)\)', tl)
        if m and m.group(1) == m.group(2):
            return (m.group(1), 'lower', int(m.group(3)))

        return None

    def scan_function(self, insns: List[Tuple[int, str]]
                      ) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
        """扫描整个函数找所有守卫模式, 返回变量→(lo,hi)映射."""
        bounds: Dict[str, List[Tuple[str, int]]] = {}
        for addr, text in insns:
            result = self.detect(text)
            if result:
                var, kind, val = result
                bounds.setdefault(var, []).append((kind, val))

        resolved = {}
        for var, bs in bounds.items():
            lo = max((b[1] for b in bs if b[0] == 'lower'), default=None)
            hi = min((b[1] for b in bs if b[0] == 'upper'), default=None)
            resolved[var] = (lo, hi)

        return resolved
