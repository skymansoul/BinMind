"""
符号化区间抽象 — 替代简单[min,max]区间, 引入符号偏移和路径条件。
AffineInterval 表示 base + coef*var (如 malloc(n*4+8) → base=8, coef=4, sym='n'),
PathCondition 追踪分支约束 (如 if(n<256) → n∈[0,255]) 以细化符号范围。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple

class RangeClass(Enum):
    """区间分类: 精确常量 / 仿射表达式 / 完全未知"""
    CONSTANT = "constant"     # 确定常量值
    AFFINE = "affine"         # base + coef * sym
    TOP = "top"               # ⊤ 未知

@dataclass
class AffineInterval:
    """仿射区间: [lo, hi] 但 lo/hi 可以是符号表达式。

    内部表示: base + sum(coef_i * sym_i)
    当所有 coef=0 时退化为常量区间。
    """
    base: int = 0
    coef: Dict[str, int] = field(default_factory=dict)  # 符号名 → 系数
    lo: int = -1        # 数值下界 (-1 = 未知)
    hi: int = 2**31 - 1  # 数值上界

    @staticmethod
    def constant(v: int) -> "AffineInterval":
        return AffineInterval(base=v, lo=v, hi=v)

    @staticmethod
    def symbolic(name: str, lo: int = -1, hi: int = 2**31 - 1) -> "AffineInterval":
        return AffineInterval(coef={name: 1}, lo=lo, hi=hi)

    @staticmethod
    def top() -> "AffineInterval":
        return AffineInterval(base=0, lo=-1, hi=2**31 - 1)

    @property
    def rclass(self) -> RangeClass:
        if self.coef:
            return RangeClass.AFFINE
        if self.lo == self.hi and self.lo >= 0:
            return RangeClass.CONSTANT
        if self.lo < 0 and self.hi >= 2**31 - 1:
            return RangeClass.TOP
        return RangeClass.CONSTANT

    @property
    def is_top(self) -> bool:
        return self.rclass == RangeClass.TOP

    @property
    def const_val(self) -> Optional[int]:
        """若为常量, 返回值; 否则 None。"""
        if self.rclass == RangeClass.CONSTANT and self.lo == self.hi:
            return self.lo
        return None

    def refine_lo(self, new_lo: int) -> "AffineInterval":
        """用路径条件收紧下界。"""
        lo = max(self.lo, new_lo) if self.lo >= 0 else new_lo
        return AffineInterval(base=self.base, coef=dict(self.coef), lo=lo, hi=self.hi)

    def refine_hi(self, new_hi: int) -> "AffineInterval":
        """用路径条件收紧上界。"""
        hi = min(self.hi, new_hi) if self.hi < 2**31 - 1 else new_hi
        return AffineInterval(base=self.base, coef=dict(self.coef), lo=self.lo, hi=hi)

    def dominates(self, other: "AffineInterval") -> bool:
        """本区间确定性地大于 other——即 self.lo > other.hi。"""
        if self.lo >= 0 and other.hi < 2**31 - 1 and self.lo > other.hi:
            return True
        if self.const_val is not None and other.const_val is not None:
            return self.const_val > other.const_val
        return False

    def may_exceed(self, other: "AffineInterval") -> bool:
        """本区间可能超出 other 的上界但非确定。保守原则: 仅可证明安全时返回False。"""
        if self.dominates(other):
            return False
        # 双方均为常量 → 直接比较
        if self.const_val is not None and other.const_val is not None:
            return self.const_val > other.const_val
        # 双方上界均有限 → 比较hi
        if self.hi < 2**31 - 1 and other.hi < 2**31 - 1:
            return self.hi > other.hi
        # 至少一方上界为TOP → 保守: 不可证明安全时返回True
        # 仅当 write.max ≤ alloc.min (已知下界) 时可判定安全
        if self.hi < 2**31 - 1 and other.lo >= 0 and self.hi <= other.lo:
            return False
        return True  # 保守: 判定为潜在溢出

    def __add__(self, other: "AffineInterval") -> "AffineInterval":
        combined = dict(self.coef)
        for k, v in other.coef.items():
            combined[k] = combined.get(k, 0) + v
        lo = (self.lo + other.lo if self.lo >= 0 and other.lo >= 0 else -1)
        hi = min(self.hi + other.hi, 2**31 - 1)
        return AffineInterval(base=self.base + other.base, coef=combined, lo=lo, hi=hi)

    def __mul__(self, const: int) -> "AffineInterval":
        """仅支持标量乘法（区间乘区间过于保守）。"""
        combined = {k: v * const for k, v in self.coef.items()}
        lo = self.lo * const if self.lo >= 0 else -1
        hi = min(self.hi * const, 2**31 - 1) if const > 0 else 2**31 - 1
        if const < 0:
            lo, hi = min(self.hi * const, 2**31 - 1), self.lo * const if self.lo >= 0 else -1
        return AffineInterval(base=self.base * const, coef=combined, lo=lo, hi=hi)

    def __repr__(self) -> str:
        parts = [f"base={self.base}"] if self.base != 0 else []
        for sym, c in self.coef.items():
            parts.append(f"{c}*{sym}" if c != 1 else sym)
        expr = "+".join(parts) if parts else "0"
        lo_s = str(self.lo) if self.lo >= 0 else "?"
        hi_s = str(self.hi) if self.hi < 2**31 - 1 else "?"
        return f"[{lo_s},{hi_s}]({expr})"

@dataclass
class PathCondition:
    """路径条件: 从函数入口到当前点的分支约束集合。

    存储为 (变量, 操作符, 常量) 三元组。仅追踪与堆操作相关的变量。
    """
    constraints: List[Tuple[str, str, int]] = field(default_factory=list)

    def add_le(self, var: str, bound: int):
        self.constraints.append((var, "<=", bound))

    def add_ge(self, var: str, bound: int):
        self.constraints.append((var, ">=", bound))

    def add_eq(self, var: str, bound: int):
        self.constraints.append((var, "==", bound))

    def add_range(self, var: str, lo: int, hi: int):
        if lo >= 0:
            self.constraints.append((var, ">=", lo))
        if hi < 2**31 - 1:
            self.constraints.append((var, "<=", hi))

    def refine_interval(self, var: str, ai: AffineInterval) -> AffineInterval:
        """用路径约束中关于 var 的条件细化区间。"""
        result = ai
        for cv, op, bv in self.constraints:
            if cv == var or (cv in ai.coef):
                if op == "<=":
                    result = result.refine_hi(bv)
                elif op == ">=":
                    result = result.refine_lo(bv)
                elif op == "==":
                    result = result.refine_lo(bv)
                    result = result.refine_hi(bv)
        return result

    def clone(self) -> "PathCondition":
        return PathCondition(list(self.constraints))

    def __repr__(self) -> str:
        return " ∧ ".join(f"{v}{op}{b}" for v, op, b in self.constraints)
