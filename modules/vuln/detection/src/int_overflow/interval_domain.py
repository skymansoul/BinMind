"""整数区间抽象域 — 算术传递函数 + 溢出判定.

基于 Cousot & Cousot, Mine, Simon & King.
区间域 O(1)/指令, 精度足以捕获 malloc(n*sizeof(T)) 的溢出模式.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple, Union


@dataclass
class Interval:
    """整数区间 [lo, hi] — bot=EMPTY, top=(-∞,+∞) 用 is_bottom/is_top 标记.

    设计决策: 不用 None 表示 top/bottom — 分支太多且容易遗漏检查.
            显式 is_top/is_bottom 让每个操作的安全性可见.
    """
    lo: int = 0
    hi: int = 0
    is_bottom: bool = False
    is_top: bool = False

    @staticmethod
    def top() -> "Interval":
        return Interval(is_top=True)

    @staticmethod
    def bottom() -> "Interval":
        return Interval(is_bottom=True)

    @staticmethod
    def const(v: int) -> "Interval":
        return Interval(lo=v, hi=v)

    @staticmethod
    def range(lo: int, hi: int) -> "Interval":
        if lo > hi:
            return Interval.bottom()
        return Interval(lo=lo, hi=hi)

    def is_constant(self) -> bool:
        return (not self.is_top and not self.is_bottom
                and self.lo == self.hi)

    def contains(self, v: int) -> bool:
        if self.is_bottom:
            return False
        if self.is_top:
            return True
        return self.lo <= v <= self.hi

    def __repr__(self) -> str:
        if self.is_bottom:
            return "⊥"
        if self.is_top:
            return "⊤"
        if self.lo == self.hi:
            return f"[{self.lo}]"
        return f"[{self.lo}, {self.hi}]"


# 区间算术
# 每条操作实现为 (op, L, R) → Result 的传递函数.
# 决策: 不在此做 widening — 调用方自己控制 widening 时机 (通常在回边处).

def interval_add(a: Interval, b: Interval) -> Interval:
    """⊕: 区间加法."""
    if a.is_bottom or b.is_bottom:
        return Interval.bottom()
    if a.is_top or b.is_top:
        return Interval.top()
    lo = a.lo + b.lo
    hi = a.hi + b.hi
    if lo > hi:
        return Interval.top()
    return Interval(lo=lo, hi=hi)


def interval_sub(a: Interval, b: Interval) -> Interval:
    """⊖: 区间减法."""
    if a.is_bottom or b.is_bottom:
        return Interval.bottom()
    if a.is_top or b.is_top:
        return Interval.top()
    lo = a.lo - b.hi
    hi = a.hi - b.lo
    return Interval(lo=lo, hi=hi)


def interval_mul(a: Interval, b: Interval) -> Interval:
    """⊗: 区间乘法 — 四个角的 min/max."""
    if a.is_bottom or b.is_bottom:
        return Interval.bottom()
    if a.is_top or b.is_top:
        return Interval.top()
    corners = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]
    return Interval(lo=min(corners), hi=max(corners))


def interval_shl(a: Interval, shift: int) -> Interval:
    """<<: 左移 — 等同于乘以 2^shift."""
    if a.is_bottom:
        return Interval.bottom()
    if a.is_top:
        return Interval.top()
    factor = 1 << shift
    return interval_mul(a, Interval.const(factor))


def interval_and_const(a: Interval, mask: int) -> Interval:
    """&: 按位与常量 — 保守区间 [0, mask]."""
    if a.is_bottom:
        return Interval.bottom()
    if a.is_top:
        return Interval.range(0, mask)
    lo = 0
    hi = min(a.hi, mask)
    return Interval(lo=lo, hi=hi)


def interval_join(a: Interval, b: Interval) -> Interval:
    """⊔: 最小上界 (LUB) — 两个区间的最小包含区间."""
    if a.is_bottom:
        return b
    if b.is_bottom:
        return a
    if a.is_top or b.is_top:
        return Interval.top()
    return Interval(lo=min(a.lo, b.lo), hi=max(a.hi, b.hi))


def interval_meet(a: Interval, b: Interval) -> Interval:
    """⊓: 最大下界 (GLB) — 两个区间的交集."""
    if a.is_bottom or b.is_bottom:
        return Interval.bottom()
    if a.is_top:
        return b
    if b.is_top:
        return a
    lo = max(a.lo, b.lo)
    hi = min(a.hi, b.hi)
    if lo > hi:
        return Interval.bottom()
    return Interval(lo=lo, hi=hi)


def interval_widen(a: Interval, b: Interval,
                   threshold: int = 0xFFFFFFFF) -> Interval:
    """∇: 外推 widening — 保证不动点迭代终止.

    Cousot-style widening: 若新区间在旧区间内 → 保持旧区间 (不动点).
    若超过 → 使用前一个边界 + 阈值跳跃.
    决策: 使用 0, 2^32-1, 2^64-1 作为阈值集合.
    """
    if a.is_bottom:
        return b
    if b.is_bottom:
        return a
    if a.is_top or b.is_top:
        return Interval.top()

    new_lo = a.lo
    new_hi = a.hi
    changed = False

    if b.lo < a.lo:
        new_lo = 0 if b.lo < 0 else min(b.lo, a.lo)
        changed = True

    if b.hi > a.hi:
        thresholds = [0xFFFF, 0xFFFFFFFF, 0xFFFFFFFFFFFFFFFF]
        new_hi = a.hi
        for t in thresholds:
            if b.hi <= t:
                new_hi = t
                break
        if new_hi == a.hi:
            new_hi = threshold
        changed = True

    if not changed:
        return a
    return Interval(lo=new_lo, hi=new_hi)


def interval_narrow(a: Interval, b: Interval) -> Interval:
    """Δ: 内推 narrowing — widening 后的精度恢复.

    若 widening 过度外推了边界, 用 narrowing 收紧.
    """
    if a.is_bottom or b.is_bottom:
        return Interval.bottom()
    if a.is_top:
        return b
    if b.is_top:
        return a

    lo = max(a.lo, b.lo) if b.lo > a.lo else b.lo
    hi = min(a.hi, b.hi) if b.hi < a.hi else b.hi
    return Interval(lo=lo, hi=hi)


# 符号感知的位宽截断
# 决策: x86-64 的 mov eax, ... 隐式零扩展到 rax.
#       但 mov al, ... 仅修改低8位, 高位保留 — 保守化为 top.
#       这里实现常见的 32→64 零扩展和 N→32 截断.

def interval_truncate(a: Interval, to_bits: int) -> Interval:
    """截断到 to_bits 位 — 模 2^to_bits."""
    if a.is_bottom or a.is_top:
        return a
    mask = (1 << to_bits) - 1
    lo = a.lo & mask
    hi = a.hi & mask
    if lo > hi:
        return Interval.range(0, mask)
    return Interval(lo=lo, hi=min(hi, mask))


def interval_zero_extend(a: Interval, from_bits: int,
                         to_bits: int) -> Interval:
    """零扩展 — 用于 mov eax, ... 后的隐式零扩展."""
    if a.is_bottom or a.is_top:
        return a
    mask = (1 << from_bits) - 1
    return Interval(lo=a.lo & mask, hi=a.hi & mask)


def interval_sign_extend(a: Interval, from_bits: int,
                         to_bits: int) -> Interval:
    """符号扩展 — 用于 movsxd 后的符号扩展.

    保守方法: 若区间跨正负 → top."""
    if a.is_bottom or a.is_top:
        return a
    sign_bit = 1 << (from_bits - 1)
    lo_negative = bool(a.lo & sign_bit)
    hi_negative = bool(a.hi & sign_bit)
    if lo_negative != hi_negative:
        return Interval.top()  # 跨正负 → 不确定 → TOP
    if lo_negative:
        ext_mask = ((1 << to_bits) - 1) ^ ((1 << from_bits) - 1)
        return Interval(lo=a.lo | ext_mask, hi=a.hi | ext_mask)
    return Interval(lo=a.lo, hi=a.hi)


# 溢出检测
# 决策: 不在这里发出告警 — 仅返回是否可以证明溢出.
#       告警由外层的 overflow_detector.py 生成.

def interval_can_overflow(a: Interval, b: Interval, op: str,
                          width_bits: int) -> bool:
    """检查 op(L, R) 是否可能超过 width_bits 位表示范围 — 含符号溢出."""
    if a.is_bottom or b.is_bottom:
        return False
    if a.is_top or b.is_top:
        return True
    u_max = (1 << width_bits) - 1
    sign_bit = 1 << (width_bits - 1)  # e.g. 0x80000000 for 32-bit
    s_max = sign_bit - 1              # e.g. 0x7FFFFFFF

    # 无符号溢出
    if op == 'mul':
        return interval_mul(a, b).hi > u_max
    elif op == 'add':
        if a.hi + b.hi > u_max:
            return True
        # 有符号溢出: 两正得负 — 区间全为正且和的符号位被置位
        if (a.lo >= 0 and a.hi < sign_bit
            and b.lo >= 0 and b.hi < sign_bit
            and a.hi + b.hi >= sign_bit):
            return True
        # 两负得正 — 区间全为负且和回绕到正 (被无符号溢出捕获)
        # 已在 a.hi + b.hi > u_max 中覆盖
        return False
    elif op == 'sub':
        if a.hi - b.lo > u_max:
            return True
        # 有符号溢出 — 区间值视为无符号, "负"=sign_bit置位
        # 情形1: 负减正 → 结果应为负, 但回绕为正
        #   a 全为负 (sign_bit 置位), b 全为正 (sign_bit 清除)
        if a.lo >= sign_bit and b.hi < sign_bit:
            if a.lo - b.hi < sign_bit:
                return True
        # 情形2: 正减负 → 结果应为正, 但溢出为负
        #   a 全为正, b 全为负
        if a.hi < sign_bit and b.lo >= sign_bit:
            if a.hi - b.lo >= sign_bit:
                return True
        return False
    elif op == 'shl':
        return interval_shl(a, b.lo).hi > u_max
    # imul (有符号乘法) — 上溢/下溢均检测
    elif op == 'imul':
        result = interval_mul(a, b)
        s_min = -(1 << (width_bits - 1))
        return (result.hi > u_max or result.hi > s_max
                or result.lo < s_min)
    return False
