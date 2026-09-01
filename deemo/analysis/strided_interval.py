"""
Strided Interval Domain — 带步长的区间抽象域.

理论来源:
  Balakrishnan & Reps, "WYSINWYX: What You See Is Not What You eXecute"
  — 证明 strided interval 对二进制分析是 Galois connection 完备的抽象域.

为何需要 stride:
  简单区间 [lo, hi] 无法表达 malloc(k * sizeof(T)) 的分配模式.
  sizeof(T)=4 时, 分配大小在 {0, 4, 8, 12, ...}中取值,
  但 [0, 4096] 包含了所有中间值, 导致大量误报.
  Strided interval s[lo, hi] = {x | lo <= x <= hi, (x - lo) mod s == 0}
  精确表征了步长约束.

与 Cod 的区别:
  Cod 做 heap disjointness 需要源码级指针分析——对二进制不适用.
  本模块的 stride 建模用于 malloc 大小推断, 不依赖指针分析结果.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple
import math


@dataclass(frozen=True)
class StridedInterval:
    """带步长的整数区间: s[lo, hi] = {x | lo <= x <= hi, (x - lo) % s == 0}.

    特殊值:
      s=0 表示单点 (lo=hi)
      hi=-1 表示无上界 (unbounded) — 用于输入依赖的分配大小
    """

    lo: int = 0
    hi: int = 0
    stride: int = 1  # 步长; 0 退化为单点

    def __post_init__(self):
        if self.stride == 0:
            object.__setattr__(self, 'stride', 1)
            object.__setattr__(self, 'hi', self.lo)

    def is_unbounded(self) -> bool:
        return self.hi < 0

    def is_bottom(self) -> bool:
        """Bottom = 空集 (不包含任何值)."""
        return not self.is_unbounded() and self.lo > self.hi

    def contains(self, value: int) -> bool:
        if self.is_unbounded():
            return value >= self.lo and (value - self.lo) % self.stride == 0
        if value < self.lo or value > self.hi:
            return False
        return (value - self.lo) % self.stride == 0

    def cardinality(self) -> int:
        """集合元素个数 (0 表示空; -1 表示无限/unbounded)."""
        if self.is_bottom():
            return 0
        if self.is_unbounded():
            return -1
        return (self.hi - self.lo) // self.stride + 1

    # 抽象域操作

    def widen(self, other: StridedInterval) -> StridedInterval:
        """Widening — 加速不动点收敛. 上界增长时跳到 unbounded."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_lo = min(self.lo, other.lo)
        new_stride = math.gcd(self.stride, other.stride)
        # 上界差异因子: 若新上界 > 旧上界*2, 跳到 unbounded (widening threshold)
        if self.is_unbounded() or other.is_unbounded():
            return StridedInterval(new_lo, -1, new_stride)
        new_hi = max(self.hi, other.hi)
        if new_hi > self.hi * 2 and self.hi > 0:
            return StridedInterval(new_lo, -1, new_stride)
        return StridedInterval(new_lo, new_hi, new_stride)

    def union(self, other: StridedInterval) -> StridedInterval:
        """Least upper bound — 两个 strided interval 的并集.

        对两个不同 stride 的集合取并, 使用 gcd 作为新 stride.
        这保证了结果仍是 strided interval 的 safe over-approximation.
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        new_lo = min(self.lo, other.lo)
        new_stride = math.gcd(self.stride, other.stride)
        new_stride = math.gcd(new_stride, abs(other.lo - self.lo))
        if self.is_unbounded() or other.is_unbounded():
            return StridedInterval(new_lo, -1, new_stride)
        return StridedInterval(new_lo, max(self.hi, other.hi), new_stride)

    def add(self, offset: int) -> StridedInterval:
        """加常数 — 对整个集合平移."""
        hi = -1 if self.is_unbounded() else self.hi + offset
        return StridedInterval(self.lo + offset, hi, self.stride)

    def mul(self, factor: int) -> StridedInterval:
        """乘常数 — stride 也被缩放."""
        if factor == 0:
            return StridedInterval(0, 0, 0)
        hi = -1 if self.is_unbounded() else self.hi * factor
        return StridedInterval(
            self.lo * factor, hi,
            self.stride * abs(factor))

    def add_interval(self, other: StridedInterval) -> StridedInterval:
        """区间加法 [a]+[b] = [a.lo+b.lo, a.hi+b.hi]."""
        if self.is_unbounded() or other.is_unbounded():
            return StridedInterval(self.lo + other.lo, -1,
                                   math.gcd(self.stride, other.stride))
        return StridedInterval(
            self.lo + other.lo, self.hi + other.hi,
            math.gcd(self.stride, other.stride))

    # 约束检查

    def may_exceed(self, bound: int) -> bool:
        """该区间是否可能超过 bound."""
        if self.is_bottom():
            return False
        if self.is_unbounded():
            return True
        return self.hi > bound

    def must_exceed(self, bound: int) -> bool:
        """该区间是否一定超过 bound."""
        if self.is_bottom():
            return False
        return self.lo > bound

    def max_value_in_bounds(self, bound: int) -> int:
        """区间内不超过 bound 的最大值."""
        if self.is_bottom() or self.lo > bound:
            return -1
        if self.is_unbounded():
            return bound
        hi_bounded = min(self.hi, bound)
        # 找到 <= hi_bounded 的最大 stride 对齐值
        offset = (hi_bounded - self.lo) % self.stride
        return hi_bounded - offset

    def __repr__(self) -> str:
        if self.is_bottom():
            return "⊥"
        ub = "∞" if self.is_unbounded() else str(self.hi)
        if self.stride > 1:
            return f"{self.stride}[{self.lo}, {ub}]"
        return f"[{self.lo}, {ub}]"


# 工厂函数

def si_singleton(val: int) -> StridedInterval:
    """单点值."""
    return StridedInterval(val, val, 0)


def si_interval(lo: int, hi: int) -> StridedInterval:
    """连续区间 [lo, hi]."""
    return StridedInterval(lo, hi, 1)


def si_range(lo: int, hi: int, stride: int) -> StridedInterval:
    """步长区间."""
    return StridedInterval(lo, hi, stride)


def si_unbounded(lo: int = 0, stride: int = 1) -> StridedInterval:
    """无上界区间."""
    return StridedInterval(lo, -1, stride)


def si_from_mul(base: StridedInterval, multiplier: int) -> StridedInterval:
    """从 base * multiplier 构造. 用于 calloc(nmemb, size) 场景."""
    return base.mul(multiplier)
