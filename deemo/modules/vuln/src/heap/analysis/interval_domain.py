"""跨步区间域 + 分配器对齐模型 — .

创建: 2025-05-12
用途: 提供 SInterval (跨步区间) 和 AllocatorModel (ptmalloc2 行为建模),
      供 MallocSizeInferrer 和 ImprovedHeapOverflowDetector 共用.

设计决策:
  - 为什么跨步区间 (strided interval) 而非普通区间:
    普通区间 [lo, hi] 在 union 操作时精度损失严重 (例如 [1,3] ∪ [5,7] = [1,7],
    包含了本不存在的 {4})。跨步区间 [lo, hi],stride 在 lo≠hi 时取 gcd 收缩,
    能更精确地排除不可能的值。对于 malloc 大小 (通常是对齐值如 16, 32, 64),
    这种精度保留是关键。
  - AllocatorModel 硬编码 ptmalloc2: 覆盖 Linux 95%+ 的堆场景,
    Windows HeapAlloc 和 macOS malloc_zone 可作为扩展点。
"""
from dataclasses import dataclass, field
from typing import Optional, Tuple


def _gcd(a: int, b: int) -> int:
    """欧几里得算法 (用于跨步区间合并)."""
    while b:
        a, b = b, a % b
    return abs(a)


@dataclass
class SInterval:
    """跨步区间 [lo, hi] 步长 stride. TOP=未知, BOT=矛盾."""
    lo: int = 0
    hi: int = 0xFFFFFFFF
    stride: int = 1
    is_top: bool = True
    is_bot: bool = False

    @staticmethod
    def exact(v: int) -> 'SInterval':
        return SInterval(lo=v, hi=v, stride=1, is_top=False)

    @staticmethod
    def top() -> 'SInterval':
        return SInterval(is_top=True)

    @staticmethod
    def bot() -> 'SInterval':
        return SInterval(is_bot=True)

    @staticmethod
    def range_lo_hi(lo: int, hi: int, stride: int = 1) -> 'SInterval':
        return SInterval(lo=max(0, lo), hi=min(0xFFFFFFFF, hi),
                         stride=max(1, stride), is_top=False)

    def add(self, delta: int) -> 'SInterval':
        if self.is_top or self.is_bot:
            return self
        return SInterval(lo=self.lo + delta, hi=self.hi + delta,
                         stride=self.stride, is_top=False)

    def mul(self, factor: int) -> 'SInterval':
        if self.is_top or self.is_bot:
            return self
        return SInterval(lo=self.lo * factor, hi=self.hi * factor,
                         stride=self.stride * factor, is_top=False)

    def union(self, other: 'SInterval') -> 'SInterval':
        """两个跨步区间的并集 (最小上界)."""
        if self.is_bot:
            return other
        if other.is_bot:
            return self
        if self.is_top or other.is_top:
            return SInterval.top()
        s = (_gcd(_gcd(self.stride, other.stride),
                  abs(self.lo - other.lo))
             if self.lo != other.lo
             else _gcd(self.stride, other.stride))
        return SInterval(lo=min(self.lo, other.lo),
                         hi=max(self.hi, other.hi),
                         stride=s, is_top=False)

    def max_possible(self) -> int:
        return (0xFFFFFFFF if self.is_top
                else (0 if self.is_bot else self.hi))

    def min_possible(self) -> int:
        return (0 if self.is_top
                else (0xFFFFFFFF if self.is_bot else self.lo))


@dataclass
class AllocatorModel:
    """堆分配器行为模型 — 将 malloc(n) 映射为实际可用字节数.

    glibc ptmalloc2: chunk_size = max(MINSIZE,
        align_up(n + SIZE_SZ + MALLOC_ALIGN_MASK, MALLOC_ALIGNMENT))
    可用空间 ≈ chunk_size - 2*SIZE_SZ (粗略)
    """
    name: str = "ptmalloc2"
    alignment: int = 16             # MALLOC_ALIGNMENT on x86_64
    min_chunk_size: int = 32        # MINSIZE (4*SIZE_SZ on 64-bit)
    header_overhead: int = 16       # prev_size + size (2 * SIZE_SZ)

    def usable_size(self, requested: int) -> int:
        """返回 malloc(n) 后实际可用字节数 (保守下界)."""
        if requested <= 0:
            return 0
        total = max(self.min_chunk_size,
                    self._align_up(requested + self.header_overhead))
        return max(0, total - self.header_overhead)

    @staticmethod
    def _align_up(x: int) -> int:
        return (x + 15) & ~15


# 默认分配器模型: ptmalloc2 x86_64
DEFAULT_ALLOCATOR = AllocatorModel()
