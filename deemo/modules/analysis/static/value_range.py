# 值区间数据结构 (Value Range)
#
# 抽象解释的域元素: 表示一个变量在程序某点可能取值的范围.
# 支持 bottom (不可达), top (全范围), singleton (精确值).
#

from typing import Optional

class ValueRange:
    """值区间: [lo, hi], 支持 bottom (不可达) 和 top (全范围)."""
    __slots__ = ("lo", "hi", "is_bottom")

    def __init__(self, lo: int = 0, hi: int = 0xFFFFFFFF,
                 is_bottom: bool = False):
        self.lo = lo
        self.hi = hi
        self.is_bottom = is_bottom

    @staticmethod
    def bottom() -> "ValueRange":
        return ValueRange(is_bottom=True)

    @staticmethod
    def singleton(v: int) -> "ValueRange":
        return ValueRange(v, v)

    @staticmethod
    def top() -> "ValueRange":
        return ValueRange(0, 0xFFFFFFFF, is_bottom=False)

    @staticmethod
    def from_interval(lo: int, hi: int) -> "ValueRange":
        return ValueRange(lo, hi)

    def join(self, other: "ValueRange") -> "ValueRange":
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        return ValueRange(min(self.lo, other.lo), max(self.hi, other.hi))

    def widen(self, other: "ValueRange") -> "ValueRange":
        """Widening: 上界发散时跳到 +∞, 保证有限步收敛."""
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        new_lo = self.lo if self.lo <= other.lo else 0
        new_hi = self.hi if other.hi <= self.hi else 0x7FFFFFFF
        return ValueRange(new_lo, new_hi)

    def narrow(self, other: "ValueRange") -> "ValueRange":
        """Narrowing: 从widening结果向精确值收紧."""
        if self.is_bottom or other.is_bottom:
            return self if not other.is_bottom else other
        return ValueRange(
            other.lo if self.lo == 0 else self.lo,
            other.hi if self.hi == 0x7FFFFFFF else self.hi,
        )

    def add(self, delta: int) -> "ValueRange":
        if self.is_bottom:
            return ValueRange.bottom()
        return ValueRange(self.lo + delta, self.hi + delta)

    def mul(self, factor: int) -> "ValueRange":
        if self.is_bottom:
            return ValueRange.bottom()
        return ValueRange(self.lo * factor, self.hi * factor)

    def contains(self, v: int) -> bool:
        if self.is_bottom:
            return False
        return self.lo <= v <= self.hi

    @property
    def is_singleton(self) -> bool:
        return not self.is_bottom and self.lo == self.hi

    @property
    def span(self) -> int:
        if self.is_bottom:
            return 0
        return self.hi - self.lo

    def __repr__(self) -> str:
        if self.is_bottom:
            return "⊥"
        return f"[{self.lo:#x},{self.hi:#x}]"


__all__ = ["ValueRange"]
