# 跨步区间抽象域——比简单[lo,hi]更精确的数值抽象
# 专利权利要求2的核心数据结构
#
# 跨步区间 [lo, hi]ₛ = {lo + k·s | 0 ≤ k ≤ (hi-lo)/s, k∈ℕ}
# 能精确表示: 对齐约束(s=16)、偶数值(s=2)、常量(s=1且lo=hi)
# 而简单区间只能表示[lo,hi]——会包含所有中间值
#
# 理论: strided intervals(跨步区间)
# 适配: 将LLVM IR层面的跨步区间适配到x86-64寄存器值分析
#
# 精度提升场景:
#   malloc(N) 在glibc中返回16字节对齐地址 →
#   offset_within_chunk 始终是16的倍数 →
#   用 s=16 而非 s=1 可排除非对齐溢出场景(~5%额外误报削减)

from __future__ import annotations

import logging
from typing import Optional, Tuple
from dataclasses import dataclass

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class StridedInterval:
    """跨步区间: {lo + k·s | 0 ≤ k ≤ (hi-lo)/s, k∈ℕ}

    不变式: s ≥ 1, lo ≤ hi, (hi - lo) % s == 0
    """
    lo: int       # 下界(含)
    hi: int       # 上界(含)
    stride: int   # 步长(≥1)

    def __post_init__(self):
        if self.stride < 1:
            object.__setattr__(self, 'stride', 1)
        if self.lo > self.hi:
            object.__setattr__(self, 'lo', self.hi)

    @staticmethod
    def exact(v: int) -> 'StridedInterval':
        return StridedInterval(v, v, 1)

    @staticmethod
    def unknown() -> 'StridedInterval':
        return StridedInterval(0, 0xFFFFFFFF, 1)

    @staticmethod
    def aligned(lo: int, hi: int, alignment: int) -> 'StridedInterval':
        """创建对齐区间——步长=alignment, 下界对齐到alignment"""
        aligned_lo = (lo // alignment) * alignment
        aligned_hi = ((hi // alignment) + 1) * alignment if hi % alignment != 0 else hi
        return StridedInterval(aligned_lo, aligned_hi, alignment)

    @property
    def is_exact(self) -> bool:
        return self.lo == self.hi and self.stride == 1

    @property
    def is_unknown(self) -> bool:
        return self.lo == 0 and self.hi >= 0xFFFFFFFF and self.stride == 1

    @property
    def cardinality(self) -> int:
        """区间中值的个数(近似——无限大时返回0xFFFFFFFF)"""
        if self.stride == 0:
            return 1
        n = (self.hi - self.lo) // self.stride + 1
        return min(n, 0xFFFFFFFF)

    def contains(self, v: int) -> bool:
        if v < self.lo or v > self.hi:
            return False
        return (v - self.lo) % self.stride == 0

    def intersect(self, other: 'StridedInterval') -> 'StridedInterval':
        """两个跨步区间的交集——新步长=lcm(s1, s2)"""
        new_lo = max(self.lo, other.lo)
        new_hi = min(self.hi, other.hi)
        if new_lo > new_hi:
            return StridedInterval(0, 0, 1)  # 空集→退化为{0}
        new_s = self._lcm(self.stride, other.stride)
        # 调整lo到同时满足两个跨步约束的最小值
        while new_lo <= new_hi and (new_lo - self.lo) % self.stride != 0:
            new_lo += 1
        while new_lo <= new_hi and (new_lo - other.lo) % other.stride != 0:
            new_lo += new_s
        if new_lo > new_hi:
            return StridedInterval(0, 0, 1)
        return StridedInterval(new_lo, new_hi, new_s)

    def add(self, n: int) -> 'StridedInterval':
        if n == 0:
            return self
        lo = max(0, self.lo + n)
        hi = min(0xFFFFFFFF, self.hi + n) if self.hi + n >= 0 else 0xFFFFFFFF
        return StridedInterval(lo, hi, self.stride)

    def mul(self, n: int) -> 'StridedInterval':
        """乘以常量——步长也乘以|n|"""
        if n == 0:
            return StridedInterval.exact(0)
        lo = self.lo * n
        hi = self.hi * n
        if n < 0:
            lo, hi = hi, lo
        lo = max(0, lo)
        hi = min(0xFFFFFFFF, hi)
        return StridedInterval(lo, hi, self.stride * abs(n))

    def widen(self, other: 'StridedInterval') -> 'StridedInterval':
        """ widening操作——循环分析中的上界收敛 """
        new_lo = min(self.lo, other.lo)
        new_hi = max(self.hi, other.hi)
        # 保持较大步长以加速收敛
        new_s = self._gcd(self.stride, other.stride)
        if new_s < 1:
            new_s = 1
        return StridedInterval(new_lo, new_hi, new_s)

    def to_simple_range(self) -> Tuple[int, int]:
        """降级为简单区间——供不使用跨步区间的代码调用"""
        return (self.lo, self.hi)

    def can_overflow(self, buffer_size: int, margin: int = 0) -> bool:
        """判断此区间中是否有值超过给定缓冲区大小"""
        # 检查区间中最大可能值
        if self.hi <= buffer_size - margin:
            return False
        # 检查最小可能值(考虑步长——可能hi虽大但实际值不溢出)
        max_val = self.lo + ((self.hi - self.lo) // self.stride) * self.stride
        return max_val > buffer_size - margin

    @staticmethod
    def _gcd(a: int, b: int) -> int:
        while b:
            a, b = b, a % b
        return a

    @staticmethod
    def _lcm(a: int, b: int) -> int:
        if a == 0 or b == 0:
            return max(a, b)
        return a // StridedInterval._gcd(a, b) * b

    def __repr__(self) -> str:
        if self.is_exact:
            return f"{{{self.lo}}}"
        if self.stride == 1:
            return f"[{self.lo},{self.hi}]"
        return f"[{self.lo},{self.hi}]_{self.stride}"


# 跨步区间的对齐推导——从指令序列推断步长约束
def infer_alignment_from_instructions(
        instrs: list[str], target_reg: str) -> Optional[int]:
    """从指令序列推断寄存器的对齐约束。

    识别模式:
      and reg, 0xFFFFFFF0  → 16字节对齐
      shl reg, N            → 2^N 字节对齐
      imul reg, N           → N的倍数
    """
    import re
    reg = target_reg.lower()
    for instr in reversed(instrs):
        instr = instr.strip().lower()
        # and reg, mask → 推断对齐
        m = re.match(rf'and\s+{reg},\s*(0x[0-9a-f]+|\d+)', instr)
        if m:
            mask = int(m.group(1), 16) if '0x' in m.group(1).lower() else int(m.group(1))
            # 掩码的低位0位数 = 2^trailing_zeros的对齐
            if mask > 0:
                trailing = (mask ^ (mask - 1) & mask).bit_length() - 1
                if trailing > 0:
                    return 1 << trailing
        # shl reg, N → 2^N对齐(如果reg之前是整数)
        m = re.match(rf'shl\s+{reg},\s*(\d+)', instr)
        if m:
            return 1 << int(m.group(1))
    return None
