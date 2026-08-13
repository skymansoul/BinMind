"""INT-RANGE 区间抽象域 — 二进制级整数区间算术引擎.

核心创新 (区别于 regex 模式匹配):
  1. 可证明 SAFETY: 区间⊆类型范围 → 不可能溢出 → 绝对安全
  2. 可证明 OVERFLOW: 区间⊃类型范围 → 必然溢出 → 必漏洞
  3. 链式传播: mul→add→shl→malloc 精确计算最终区间
  4. 有符号/无符号语义区分: signed int32 vs unsigned uint32

区间运算规则:
  ADD: [a,b] + [c,d] = [a+c, b+d]
  SUB: [a,b] - [c,d] = [a-d, b-c]
  MUL: [a,b] * [c,d] = [min(ac,ad,bc,bd), max(ac,ad,bc,bd)]
  SHL: [a,b] << k = [a<<k, b<<k] (若 b<<k 不溢出类型宽度)

Widening: 若区间在循环中增长, 上界跳至+inf/下界跳至-inf
  防止无限迭代.

创建: 2024-09-02
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Tuple, Union
from enum import Enum


class Signedness(Enum):
    """有符号/无符号语义."""
    UNSIGNED = 0
    SIGNED = 1


class BitWidth(Enum):
    """操作数位宽."""
    BIT8 = 1
    BIT16 = 2
    BIT32 = 4
    BIT64 = 8


# 区间

@dataclass
class Interval:
    """整数区间 [lo, hi].

    特殊语义:
      lo = BOTTOM, hi = BOTTOM → ⊥ (不可达)
      hi = TOP → +∞ (无上界, widening注入)
      lo = NEG_TOP → -∞ (无下界)
    """
    lo: int = 0
    hi: int = 0
    bottom: bool = False

    # 哨兵值
    BOTTOM = -1  # 仅用于bottom标记的lo/hi值
    TOP = 0x1_0000_0000_0000_0000  # 不是合法int但标志+inf
    NEG_TOP = -0x8000_0000_0000_0001  # 标志-inf

    @staticmethod
    def make(lo: int, hi: int) -> Interval:
        return Interval(lo=lo, hi=hi)

    @staticmethod
    def make_bottom() -> Interval:
        return Interval(bottom=True)

    @staticmethod
    def make_top() -> Interval:
        """[-inf, +inf] — 完全未知."""
        return Interval(lo=Interval.NEG_TOP, hi=Interval.TOP)

    @staticmethod
    def make_unsigned_max(width: BitWidth) -> Interval:
        """uintN 全范围 [0, 2^N - 1]."""
        m = (1 << (width.value * 8)) - 1
        return Interval(lo=0, hi=m)

    @staticmethod
    def make_signed_range(width: BitWidth) -> Interval:
        """intN 全范围 [INT_MIN, INT_MAX]."""
        b = width.value * 8
        return Interval(lo=-(1 << (b - 1)), hi=(1 << (b - 1)) - 1)

# 属性

    def is_bottom(self) -> bool:
        return self.bottom

    def is_top(self) -> bool:
        return (not self.bottom and
                self.lo <= Interval.NEG_TOP and
                self.hi >= Interval.TOP)

    def is_constant(self) -> bool:
        return (not self.bottom and not self.is_top() and
                self.lo == self.hi)

    def is_finite(self) -> bool:
        return (not self.bottom and not self.is_top() and
                self.lo > Interval.NEG_TOP and
                self.hi < Interval.TOP)

# 包含/比较

    def contains(self, val: int) -> bool:
        if self.is_bottom():
            return False
        if self.is_top():
            return True
        return self.lo <= val <= self.hi

    def subset_of(self, other: Interval) -> bool:
        if self.is_bottom():
            return True
        if other.is_top():
            return True
        return (self.lo >= other.lo and
                self.hi <= other.hi if not self.is_top() else False)

    def overlaps(self, other: Interval) -> bool:
        """两区间是否有交集."""
        if self.is_bottom() or other.is_bottom():
            return False
        if self.is_top() or other.is_top():
            return True
        return self.lo <= other.hi and other.lo <= self.hi

# 格操作

    def join(self, other: Interval) -> Interval:
        """最小上界 (∪)."""
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if self.is_top() or other.is_top():
            return Interval.make_top()
        return Interval(
            lo=min(self.lo, other.lo),
            hi=max(self.hi, other.hi))

    def meet(self, other: Interval) -> Interval:
        """最大下界 (∩)."""
        if self.is_bottom() or other.is_bottom():
            return Interval.make_bottom()
        if self.is_top():
            return other
        if other.is_top():
            return self
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return Interval.make_bottom()
        return Interval(lo=new_lo, hi=new_hi)

    def widen(self, other: Interval,
              max_iter: int = 3, iter_count: int = 0) -> Interval:
        """扩大算子: 防无限迭代的区间加宽.

        若迭代次数 > max_iter 且区间仍在增长,
        则将无界侧跳至 TOP, 强制收敛.
        """
        if self.is_bottom():
            return other
        if other.is_bottom():
            return self
        if iter_count < max_iter:
            return self.join(other)
        # 宽度: 加宽 — 跳至边界
        new_lo = self.lo
        new_hi = self.hi
        if other.lo < self.lo:
            new_lo = Interval.NEG_TOP if other.lo < self.lo - 0x10000 else other.lo
        if other.hi > self.hi:
            new_hi = Interval.TOP if other.hi > self.hi + 0x10000 else other.hi
        return Interval(lo=new_lo, hi=new_hi)

# 算术

    def add(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return Interval.make_bottom()
        if self.is_top() or other.is_top():
            return Interval.make_top()
        lo = (self.lo + other.lo if self.lo > Interval.NEG_TOP
              else Interval.NEG_TOP)
        hi = (self.hi + other.hi if self.hi < Interval.TOP
              else Interval.TOP)
        return Interval(lo=lo, hi=hi)

    def sub(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return Interval.make_bottom()
        if self.is_top() or other.is_top():
            return Interval.make_top()
        lo = (self.lo - other.hi if (self.lo > Interval.NEG_TOP
              and other.hi < Interval.TOP) else Interval.NEG_TOP)
        hi = (self.hi - other.lo if (self.hi < Interval.TOP
              and other.lo > Interval.NEG_TOP) else Interval.TOP)
        return Interval(lo=lo, hi=hi)

    def mul(self, other: Interval) -> Interval:
        if self.is_bottom() or other.is_bottom():
            return Interval.make_bottom()
        if self.is_top() or other.is_top():
            return Interval.make_top()
        a, b = self.lo, self.hi
        c, d = other.lo, other.hi
        # 四个角的乘积
        candidates = [a*c, a*d, b*c, b*d]
        return Interval(lo=min(candidates), hi=max(candidates))

    def shl_const(self, k: int) -> Interval:
        """左移常量位: [a,b] << k."""
        if self.is_bottom():
            return self
        if self.is_top():
            return self
        return Interval(lo=self.lo << k, hi=self.hi << k)

    def and_const(self, mask: int) -> Interval:
        """按位与常量: [a,b] & mask → [0, min(b,mask)] (过近似)."""
        if self.is_bottom():
            return self
        if self.is_top():
            return Interval(lo=0, hi=mask)
        return Interval(
            lo=0,
            hi=min(self.hi, mask))

    def truncate(self, src_width: BitWidth,
                 dst_width: BitWidth) -> Interval:
        """位宽截断: [a,b] 从 src_width 截到 dst_width."""
        if self.is_bottom() or self.is_top():
            return self
        mask = (1 << (dst_width.value * 8)) - 1
        # 截断后: lo截 = lo & mask, hi截 = hi & mask
        lo_t = self.lo & mask
        hi_t = self.hi & mask
        if lo_t <= hi_t:
            return Interval(lo=lo_t, hi=hi_t)
        # 回绕: [0xFFF0, 0x1000F] → [0, mask]
        return Interval(lo=0, hi=mask)

    def signed_extend(self, src_width: BitWidth,
                      dst_width: BitWidth) -> Interval:
        """有符号扩展: 16bit sign→32bit."""
        if self.is_bottom() or self.is_top():
            return self
        db = dst_width.value * 8
        sb = src_width.value * 8
        sign_bit = 1 << (sb - 1)
        sign_mask = ((1 << (db - sb)) - 1) << sb
        lo = self.lo
        hi = self.hi
        # 若源区间可能为负, upper half加sign_mask
        if lo & sign_bit:
            lo |= sign_mask
        if hi & sign_bit:
            hi |= sign_mask
        return Interval(lo=lo, hi=hi)

# 溢出检测

    def can_overflow(self, width: BitWidth,
                     signed: Signedness = Signedness.UNSIGNED) -> Tuple[bool, str]:
        """此区间在指定位宽/符号下是否会溢出.

        Returns: (may_overflow, reason)
        """
        if self.is_bottom():
            return (False, "unreachable")
        if self.is_top():
            return (True, "unbounded range → overflow possible")

        if signed == Signedness.UNSIGNED:
            max_val = (1 << (width.value * 8)) - 1
            min_val = 0
        else:
            b = width.value * 8
            max_val = (1 << (b - 1)) - 1
            min_val = -(1 << (b - 1))

        if self.lo < min_val:
            return (True, f"lo={self.lo} < {min_val} (min)")
        if self.hi > max_val:
            return (True, f"hi={self.hi} > {max_val} (max)")
        return (False, "in bounds")

    def overflow_severity(self, dest_width: BitWidth,
                          signed: Signedness = Signedness.UNSIGNED) -> float:
        """溢出严重度 0.0-1.0."""
        may, _ = self.can_overflow(dest_width, signed)
        if not may:
            return 0.0
        if self.is_top():
            return 0.5

        if signed == Signedness.UNSIGNED:
            max_val = (1 << (dest_width.value * 8)) - 1
        else:
            max_val = (1 << (dest_width.value * 8 - 1)) - 1

        if self.hi < Interval.TOP and self.hi <= max_val:
            return 0.0
        # 超出越多, 严重度越高
        if self.hi < Interval.TOP:
            severity = min((self.hi - max_val) / max(max_val, 1), 1.0)
            return 0.3 + 0.7 * severity
        return 0.85

    def __repr__(self) -> str:
        if self.is_bottom():
            return '⊥'
        if self.is_top():
            return '[-∞,+∞]'
        return f'[{self.lo:#x},{self.hi:#x}]={self.lo}..{self.hi}'


# 算术Transfer函数

def abstract_add(a: Interval, b: Interval) -> Interval:
    return a.add(b)


def abstract_sub(a: Interval, b: Interval) -> Interval:
    return a.sub(b)


def abstract_mul(a: Interval, b: Interval) -> Interval:
    return a.mul(b)


def abstract_imul_const(a: Interval, imm: int,
                         width: BitWidth = BitWidth.BIT32,
                         signed: Signedness = Signedness.SIGNED) -> Interval:
    """有符号乘法 imul reg, imm → 精确计算后截断."""
    result = a.mul(Interval(lo=imm, hi=imm))
    if signed == Signedness.SIGNED:
        return result.truncate(width, width)
    return result


def abstract_add_const(a: Interval, imm: int,
                        width: BitWidth = BitWidth.BIT32) -> Interval:
    """add reg, imm → 精确计算."""
    return a.add(Interval(lo=imm, hi=imm))


def abstract_shl_const(a: Interval, k: int,
                        width: BitWidth = BitWidth.BIT32,
                        signed: Signedness = Signedness.UNSIGNED) -> Interval:
    """shl reg, k → 左移后截断."""
    shifted = a.shl_const(k)
    return shifted.truncate(width, width)


# smoke
def _check():
    # 基本区间
    a = Interval(lo=0, hi=10)
    b = Interval(lo=5, hi=15)
    assert a.add(b).lo == 5 and a.add(b).hi == 25
    assert a.mul(b).lo == 0 and a.mul(b).hi == 150

    # 溢出检测
    i32 = Interval(lo=0x7FFFFFFF, hi=0x80000001)
    may, reason = i32.can_overflow(BitWidth.BIT32, Signedness.SIGNED)
    assert may, f"should overflow: {reason}"

    u32 = Interval(lo=0, hi=0x1_0000_0000)
    may2, _ = u32.can_overflow(BitWidth.BIT32, Signedness.UNSIGNED)
    assert may2

    # 安全的
    safe = Interval(lo=0, hi=0xFFFF)
    may3, _ = safe.can_overflow(BitWidth.BIT32, Signedness.UNSIGNED)
    assert not may3

    # Join
    j = a.join(b)
    assert j.lo == 0 and j.hi == 15

    # Truncation
    big = Interval(lo=0, hi=0x1_0000_0001)
    t = big.truncate(BitWidth.BIT64, BitWidth.BIT32)
    assert t.lo == 0  # wrapped

    print("[OK] interval_domain tests passed")


if __name__ == "__main__":
    _check()
