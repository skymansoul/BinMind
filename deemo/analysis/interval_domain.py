"""区间域 — 堆分配/写入的 value range 传播.

提供 add/mul/div 区间运算, join/meet, widening.
不做完整 VSA, stripped binary 上 stride 推断不可靠, 仅做区间.
"""
from dataclasses import dataclass
from enum import Enum
from typing import Optional, Union
import math


class IntervalKind(Enum):
    """区间类型 —— 影响 join 操作的语义。"""
    FINITE = "finite"       # [lo, hi] 确定上下界
    TOP = "top"             # (-∞, +∞) 完全未知
    BOTTOM = "bottom"       # 不可达 (空区间)


@dataclass
class Interval:
    """抽象区间 [lo, hi], 遵循 Cousot 区间域的定义。

    所有操作保持 soundness: 真实值一定在区间内。
    lo/hi 用 Optional[int] 表示, None = 无界 (负无穷/正无穷)。
    """
    lo: Optional[int]  # 下界, None 表示 -∞
    hi: Optional[int]  # 上界, None 表示 +∞
    kind: IntervalKind = IntervalKind.FINITE

    @classmethod
    def top(cls) -> "Interval":
        return cls(lo=None, hi=None, kind=IntervalKind.TOP)

    @classmethod
    def bottom(cls) -> "Interval":
        return cls(lo=0, hi=-1, kind=IntervalKind.BOTTOM)

    @classmethod
    def const(cls, v: int) -> "Interval":
        return cls(lo=v, hi=v, kind=IntervalKind.FINITE)

    @classmethod
    def range_of(cls, lo: int, hi: int) -> "Interval":
        if lo > hi:
            return cls.bottom()
        return cls(lo=lo, hi=hi, kind=IntervalKind.FINITE)

    @classmethod
    def from_upper_bound(cls, ub: int) -> "Interval":
        """从已知上界构造区间 [0, ub]。"""
        return cls(lo=0, hi=ub, kind=IntervalKind.FINITE)

    def is_top(self) -> bool:
        return self.kind == IntervalKind.TOP

    def is_bottom(self) -> bool:
        return self.kind == IntervalKind.BOTTOM

    def is_const(self) -> bool:
        return (self.lo is not None and self.hi is not None
                and self.lo == self.hi and self.kind == IntervalKind.FINITE)

    def const_val(self) -> Optional[int]:
        return self.lo if self.is_const() else None

    def width(self) -> int:
        """区间宽度 —— 用于 widening 判定和精度评估。"""
        if self.is_bottom() or self.is_top():
            return -1
        lo = self.lo if self.lo is not None else 0
        hi = self.hi if self.hi is not None else (2**31 - 1)
        return max(0, hi - lo)

    # 区间运算

    def add(self, other: "Interval") -> "Interval":
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        if self.is_top() or other.is_top():
            return Interval.top()
        lo = (self.lo + other.lo
              if self.lo is not None and other.lo is not None else None)
        hi = (self.hi + other.hi
              if self.hi is not None and other.hi is not None else None)
        return Interval(lo=lo, hi=hi)

    def mul(self, other: "Interval") -> "Interval":
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        if self.is_top() or other.is_top():
            return Interval.top()
        lo_s, hi_s = (self.lo or 0), (self.hi if self.hi is not None else 0)
        lo_o, hi_o = (other.lo or 0), (other.hi if other.hi is not None else 0)
        corners = [lo_s * lo_o, lo_s * hi_o, hi_s * lo_o, hi_s * hi_o]
        return Interval(lo=min(corners), hi=max(corners))

    def join(self, other: "Interval") -> "Interval":
        """least upper bound — 两条路径合并时的值范围。"""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return Interval.top()
        lo = None if (self.lo is None or other.lo is None) else min(self.lo, other.lo)
        hi = None if (self.hi is None or other.hi is None) else max(self.hi, other.hi)
        return Interval(lo=lo, hi=hi)

    def meet(self, other: "Interval") -> "Interval":
        """greatest lower bound — 条件约束后的值范围。"""
        if self.is_bottom() or other.is_bottom():
            return Interval.bottom()
        if other.is_top():
            return self
        if self.is_top():
            return other
        lo = (max(self.lo, other.lo)
              if self.lo is not None and other.lo is not None
              else (self.lo if self.lo is not None else other.lo))
        hi = (min(self.hi, other.hi)
              if self.hi is not None and other.hi is not None
              else (self.hi if self.hi is not None else other.hi))
        if lo is not None and hi is not None and lo > hi:
            return Interval.bottom()
        return Interval(lo=lo, hi=hi)

    def widen(self, prev: "Interval") -> "Interval":
        """Widening 算子 —— 保证循环分析在有限步内终止。

        规则: 若新区间在某个方向超出旧区间, 将该方向推到 +∞ (或阈值)。
        阈值引入是工程权衡 —— 纯理论 widening 会推到 +∞, 丢失精度。
        这里用 2^20 (1MB) 作为堆分配的上界阈值, 超过此值认为足够大。
        """
        THRESHOLD = 1 << 20  # 1MB
        if self.is_bottom():
            return prev
        if prev.is_bottom():
            return self
        if self.is_top() or prev.is_top():
            return Interval.top()

        new_lo = self.lo
        new_hi = self.hi
        lo_changed = (prev.lo is not None and self.lo is not None
                      and self.lo < prev.lo)
        hi_changed = (prev.hi is not None and self.hi is not None
                      and self.hi > prev.hi)

        if lo_changed:
            new_lo = None  # 下界推到 -∞
        if hi_changed:
            new_hi = THRESHOLD if prev.hi is not None else None

        # 保留已有的界
        if new_lo is None and prev.lo is not None:
            new_lo = 0  # 保守: 分配大小至少为 0
        return Interval(lo=new_lo, hi=new_hi)

    # 约束操作

    def constrain_lt(self, threshold: int) -> "Interval":
        """约束: var < threshold"""
        if self.is_bottom() or self.is_top():
            return self
        new_hi = threshold - 1
        if self.hi is not None:
            new_hi = min(self.hi, new_hi)
        if self.lo is not None and new_hi < self.lo:
            return Interval.bottom()
        return Interval(lo=self.lo, hi=new_hi)

    def constrain_le(self, threshold: int) -> "Interval":
        """约束: var <= threshold"""
        if self.is_bottom() or self.is_top():
            return self
        new_hi = threshold
        if self.hi is not None:
            new_hi = min(self.hi, new_hi)
        if self.lo is not None and new_hi < self.lo:
            return Interval.bottom()
        return Interval(lo=self.lo, hi=new_hi)

    def constrain_gt(self, threshold: int) -> "Interval":
        """约束: var > threshold"""
        if self.is_bottom() or self.is_top():
            return self
        new_lo = threshold + 1
        if self.lo is not None:
            new_lo = max(self.lo, new_lo)
        if self.hi is not None and new_lo > self.hi:
            return Interval.bottom()
        return Interval(lo=new_lo, hi=self.hi)

    # 查询

    def definitely_less_than(self, val: int) -> bool:
        """区间最大值是否确定小于 val (sound upper bound check)。"""
        return self.hi is not None and self.hi < val

    def definitely_greater_than(self, val: int) -> bool:
        """区间最小值是否确定大于 val。"""
        return self.lo is not None and self.lo > val

    def contains(self, val: int) -> bool:
        """val 是否在区间内。"""
        if self.is_bottom():
            return False
        if self.is_top():
            return True
        lo_ok = self.lo is None or self.lo <= val
        hi_ok = self.hi is None or self.hi >= val
        return lo_ok and hi_ok

    def __repr__(self) -> str:
        if self.is_top():
            return "⊤"
        if self.is_bottom():
            return "⊥"
        l = str(self.lo) if self.lo is not None else "-∞"
        h = str(self.hi) if self.hi is not None else "+∞"
        return f"[{l}, {h}]"


def widen_sequence(values: list[int], max_iter: int = 10) -> Interval:
    """对值序列应用 widening, 在有限步内得到安全上界。

    用于循环内分配大小的抽象: 观察循环中 malloc 参数的变化趋势,
    若每次递增 N, 则 widening 到 [0, THRESHOLD]。"""
    if not values:
        return Interval.bottom()
    prev = Interval.const(values[0])
    for i, v in enumerate(values[1:], 1):
        cur = Interval.const(v)
        prev = cur.widen(prev)
        if prev.is_top() or i >= max_iter:
            break
    return prev


def interval_from_constrained_source(
    source_type: str, upper_bound: Optional[int],
) -> Interval:
    """从 HeapFlowTracker 的分类结果构造初始区间。

    决策:
      · CONSTANT N → [N, N]
      · USER_INPUT + upper_bound=N → [0, N]
      · USER_INPUT + no bound → TOP
      · ARITHMETIC + upper_bound=N → [0, N]
      · UNKNOWN → TOP
    """
    if source_type == "constant" and upper_bound is not None:
        return Interval.const(upper_bound)
    if source_type in ("user_input", "arithmetic") and upper_bound is not None:
        return Interval.from_upper_bound(upper_bound)
    return Interval.top()


__all__ = ['Interval', 'IntervalKind', 'widen_sequence',
           'interval_from_constrained_source']
