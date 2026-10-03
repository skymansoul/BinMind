"""
仿射区间引擎 — AffineInterval 和 PathCondition 数据结构及操作.

仿射区间: base + Σ coef_i * sym_i, 比简单区间 [lo,hi] 更精确.
  例: malloc(n*4+8) → base=8, coefs={n:4}
  simple interval: n∈[0,256] → alloc_size∈[8,1032]
  affine interval: 保留 n 的符号值, 在不等式检查时做线性推理

PathCondition: 线性不等式的合取集合.
  例: {n<=256, n>0, offset<=n*4}
  支持 fork() 分支、is_contradiction() 矛盾检测、refine_bounds() 区间精化.
"""


import logging
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


@dataclass
class AffineInterval:
    """仿射区间: base + Σ coef_i * symbol_i.

    表示一个带有符号系数的整数表达式值范围.
    symbol_vars 是符号名 (如 'n', 'size', 'count').
    lo/hi 是当前已知的数值边界 (保守过近似).
    """

    base: int = 0
    coefs: Dict[str, int] = field(default_factory=dict)
    lo: Optional[int] = None  # 已知下界
    hi: Optional[int] = None  # 已知上界

    def is_constant(self) -> bool:
        return not self.coefs

    def constant_value(self) -> Optional[int]:
        """纯常量时返回值, 否则 None."""
        if self.is_constant():
            return self.base
        return None

    def may_exceed(self, other: "AffineInterval") -> bool:
        """保守判定: 本区间是否可能严格大于 other."""
        if self.lo is None or other.hi is None:
            return True  # 无界 → 可能
        return self.lo > other.hi

    def definitely_within(self, other: "AffineInterval") -> bool:
        """保守判定: 本区间是否确定不超过 other."""
        if self.hi is None or other.lo is None:
            return False  # 无界 → 不确定
        return self.hi <= other.lo

    def add_constant(self, c: int) -> "AffineInterval":
        return AffineInterval(
            base=self.base + c,
            coefs=dict(self.coefs),
            lo=self.lo + c if self.lo is not None else None,
            hi=self.hi + c if self.hi is not None else None,
        )

    def mul_constant(self, c: int) -> "AffineInterval":
        if c == 0:
            return AffineInterval(base=0, coefs={}, lo=0, hi=0)
        new_coefs = {k: v * c for k, v in self.coefs.items()}
        new_lo = self.lo * c if self.lo is not None else None
        new_hi = self.hi * c if self.hi is not None else None
        if c < 0 and new_lo is not None and new_hi is not None:
            new_lo, new_hi = new_hi, new_lo
        return AffineInterval(
            base=self.base * c, coefs=new_coefs, lo=new_lo, hi=new_hi)

    def refine_lo(self, val: int) -> "AffineInterval":
        """单调精化下界 (只紧不松)."""
        new_lo = max(self.lo, val) if self.lo is not None else val
        return AffineInterval(self.base, dict(self.coefs), new_lo, self.hi)

    def refine_hi(self, val: int) -> "AffineInterval":
        """单调精化上界 (只紧不松)."""
        new_hi = min(self.hi, val) if self.hi is not None else val
        return AffineInterval(self.base, dict(self.coefs), self.lo, new_hi)

    def dominates(self, other: "AffineInterval") -> bool:
        """严格支配: 本区间在所有可能值上 ≥ other."""
        if self.lo is None or other.hi is None:
            return False
        return self.lo >= other.hi

    def __repr__(self) -> str:
        terms = [f"{c}*{s}" for s, c in self.coefs.items()]
        expr = " + ".join([str(self.base)] + terms) if terms else str(self.base)
        return f"Affine({expr}, [{self.lo}, {self.hi}])"


@dataclass
class LinearInequality:
    """线性不等式: Σ coef_i * var_i + constant <= 0.

    归一化形式, 方便合并和检查矛盾.
    """

    coefs: Dict[str, int] = field(default_factory=dict)
    constant: int = 0
    strict: bool = False  # True → < 0 (严格不等式)

    def negate(self) -> "LinearInequality":
        """取反: Σ c*v + k <= 0 → -(Σ c*v + k) < 0 (或 <= 0)."""
        return LinearInequality(
            coefs={k: -v for k, v in self.coefs.items()},
            constant=-self.constant,
            strict=not self.strict,
        )

    def substitute(self, var: str, expr: AffineInterval) -> "LinearInequality":
        """将 var 替换为仿射表达式."""
        if var not in self.coefs:
            return self
        mul = self.coefs[var]
        new_coefs = {k: v for k, v in self.coefs.items() if k != var}
        new_constant = self.constant + mul * expr.base
        for s, c in expr.coefs.items():
            new_coefs[s] = new_coefs.get(s, 0) + mul * c
        return LinearInequality(new_coefs, new_constant, self.strict)

    def __repr__(self) -> str:
        terms = [f"{c}*{s}" for s, c in sorted(self.coefs.items())]
        op = "<" if self.strict else "<="
        return f"{' + '.join(terms) if terms else '0'} + {self.constant} {op} 0"


@dataclass
class PathCondition:
    """路径条件: 线性不等式的合取.

    支持:
      - fork(): 为 if/else 分支创建独立副本
      - is_contradiction(): 区间代数检测矛盾 (无SMT)
      - bound_of(): 查询变量在当前路径条件下的界限
    """

    inequalities: Tuple[LinearInequality, ...] = ()

    def fork(self) -> "PathCondition":
        """创建当前条件的副本, 用于独立分支传播."""
        return PathCondition(self.inequalities)

    def add_constraint(self, ie: LinearInequality) -> "PathCondition":
        return PathCondition(self.inequalities + (ie,))

    def add_bound(self, var: str, lo: Optional[int] = None,
                  hi: Optional[int] = None) -> "PathCondition":
        """便捷方法: 添加变量边界约束."""
        pc = self
        if lo is not None:
            ie = LinearInequality({var: -1}, constant=lo, strict=False)
            pc = pc.add_constraint(ie)
        if hi is not None:
            ie = LinearInequality({var: 1}, constant=-hi, strict=False)
            pc = pc.add_constraint(ie)
        return pc

    def is_contradiction(self) -> bool:
        """区间代数矛盾检测 — O(n^2) 最坏, 无SMT.

        对每个符号变量, 收集所有不等式给出的上下界.
        若存在 var 使得 lo > hi, 则为矛盾 (不可行路径).
        """
        bounds: Dict[str, List[Tuple[int, int, bool]]] = {}
        for ie in self.inequalities:
            for var, coef in ie.coefs.items():
                if coef == 0:
                    continue
                # 归一化: coef * var + rest <= 0 → var 的界
                if coef > 0:
                    # var <= -(rest) / coef
                    upper = -ie.constant // coef
                    bounds.setdefault(var, []).append(
                        (-10**9, upper, ie.strict))
                else:
                    # var >= -(rest) / coef (因为 coef<0)
                    lower = -ie.constant // coef
                    bounds.setdefault(var, []).append(
                        (lower, 10**9, ie.strict))

        for var, bs in bounds.items():
            lo = max((b[0] for b in bs), default=-10**9)
            hi = min((b[1] for b in bs), default=10**9)
            if lo > hi:
                return True
        return False

    def bound_of(self, var: str) -> Tuple[Optional[int], Optional[int]]:
        """返回变量在当前路径条件下的 [lo, hi]."""
        lo, hi = None, None
        for ie in self.inequalities:
            coef = ie.coefs.get(var, 0)
            if coef == 0 or len(ie.coefs) > 1:
                continue
            if coef > 0:
                bound = -ie.constant // coef
                hi = bound if hi is None else min(hi, bound)
            else:
                bound = -ie.constant // coef
                lo = bound if lo is None else max(lo, bound)
        return lo, hi

    def __bool__(self) -> bool:
        return len(self.inequalities) > 0

    def __repr__(self) -> str:
        return f"PC({list(self.inequalities)})"


def affine_const(val: int) -> AffineInterval:
    """常量仿射区间."""
    return AffineInterval(base=val, coefs={}, lo=val, hi=val)


def affine_var(name: str, lo: Optional[int] = None,
               hi: Optional[int] = None) -> AffineInterval:
    """符号变量仿射区间."""
    return AffineInterval(base=0, coefs={name: 1}, lo=lo, hi=hi)


def affine_unbounded() -> AffineInterval:
    """无界仿射区间."""
    return AffineInterval(base=0, coefs={}, lo=None, hi=None)
