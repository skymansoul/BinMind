"""ptmalloc2 分配器内部约束模型 — 最小块大小/对齐/尺寸舍入/bin阈值.

创建: 2026-06-06 08:44
用途: 为堆溢出检测提供分配器的内部约束, 用于过滤因编译器生成的
      合法padding访问导致的误报。核心观察: malloc(1) 实际上分配 32 字节,
      编译器在结构体尾部生成的 *(ptr+28) 访问虽然在源码层面越界,
      但在二进制层面完全合法——因分配器已做了尺寸舍入。

设计决策:
  - 为什么硬编码 ptmalloc2 的约束而非做通用分配器模型:
    Linux 上 95%+ 的 C 二进制链接 glibc, 硬编码 ptmalloc2 的约束
    覆盖绝大多数实际场景。对 musl/jemalloc 可通过子类扩展。
  - 为什么最小块是 32 而非 MINSIZE 宏定义的 16:
    x86-64 下 chunk 头部 4 个 8 字节字段 (prev_size, size, fd, bk),
    即使 MINSIZE=16 (32-bit), 实际可用空间也是 32-16=16 字节起步。
    但 64-bit 的 MINSIZE=32, 统一用 32 做最保守估计。
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


# ptmalloc2 常量 (glibc 2.31+, x86-64)
MIN_CHUNK_SIZE = 32        # 最小块大小 (4 × 8-byte header fields)
MALLOC_ALIGNMENT = 16      # 指针对齐边界
SIZE_SZ = 8                # size_t 字节数
MIN_LARGE_SIZE = 512       # 大块阈值
DEFAULT_MMAP_THRESHOLD = 128 * 1024  # mmap 阈值
MAX_FAST_SIZE = 80         # fastbin 最大大小 (默认)


@dataclass
class AllocatorConstraint:
    """一次 malloc 调用的分配器约束."""
    requested_size: int          # 用户请求的大小
    actual_chunk_size: int       # 分配器分配的实际块大小 (含 header)
    usable_size: int             # 用户可用的字节数 (actual - 2*SIZE_SZ)
    aligned: bool = True         # 是否满足对齐要求
    is_mmap: bool = False        # 是否通过 mmap 分配


class Ptmalloc2Model:
    """ptmalloc2 分配器内部约束模型.

    将用户请求的 malloc(n) 映射为分配器实际分配的大小,
    考虑尺寸舍入、对齐填充、最小块约束和 bin 分类。

    使用方式:
      model = Ptmalloc2Model()
      constraint = model.model_alloc(100)
      # constraint.usable_size = 112 (实际可用字节, 不是100)
      # 编译器可能在这个范围内做合法访问
    """

    def __init__(self):
        # 缓存: requested_size → AllocatorConstraint
        self._cache: Dict[int, AllocatorConstraint] = {}

    def model_alloc(self, requested_size: int) -> AllocatorConstraint:
        """将用户请求大小映射为分配器实际分配的约束."""
        if requested_size in self._cache:
            return self._cache[requested_size]

        size = max(requested_size, 0)

        # mmap 路径: 超过阈值 → mmap, 页面对齐
        if size >= DEFAULT_MMAP_THRESHOLD:
            actual = self._round_up(size + 2 * SIZE_SZ, 4096)
            usable = actual - 2 * SIZE_SZ
            constraint = AllocatorConstraint(
                requested_size=size, actual_chunk_size=actual,
                usable_size=usable, is_mmap=True)
            self._cache[requested_size] = constraint
            return constraint

        # 常规路径: 最小块 + 对齐 + 舍入
        # chunk_size = max(MIN_CHUNK_SIZE, align_up(size + header, MALLOC_ALIGNMENT))
        min_data_size = max(size, MIN_CHUNK_SIZE - 2 * SIZE_SZ)
        chunk_size = self._round_up(
            min_data_size + 2 * SIZE_SZ, MALLOC_ALIGNMENT)

        # 确保不小于最小块
        chunk_size = max(MIN_CHUNK_SIZE, chunk_size)
        usable = chunk_size - 2 * SIZE_SZ

        constraint = AllocatorConstraint(
            requested_size=size, actual_chunk_size=chunk_size,
            usable_size=usable, aligned=True, is_mmap=False)
        self._cache[requested_size] = constraint
        return constraint

    def is_within_usable_bounds(self, requested_size: int,
                                 offset: int,
                                 access_size: int = 1) -> bool:
        """检查 offset + access_size 是否在分配器的可用范围内.

        关键过滤逻辑: 源码层面的 '越界' 在二进制层面可能合法,
        因为分配器做了尺寸舍入。
        """
        constraint = self.model_alloc(requested_size)
        return (offset >= 0
                and offset + access_size <= constraint.usable_size)

    def safe_padding_range(self, requested_size: int) -> int:
        """返回因分配器舍入而多出的安全 padding 字节数.

        例如 malloc(100) → usable_size=104, padding=4 字节。
        编译器可能在这 4 字节中做合法访问 (struct padding),
        静态分析不应报告这些访问为溢出。
        """
        constraint = self.model_alloc(requested_size)
        return max(0, constraint.usable_size - requested_size)

    def size_to_bin_category(self, requested_size: int) -> str:
        """返回尺寸对应的 bin 类别."""
        constraint = self.model_alloc(requested_size)
        cs = constraint.actual_chunk_size
        if cs <= MAX_FAST_SIZE:
            return 'fastbin'
        if cs < MIN_LARGE_SIZE:
            return 'smallbin'
        if constraint.is_mmap:
            return 'mmap'
        return 'largebin'

    @staticmethod
    def _round_up(val: int, align: int) -> int:
        """向上对齐."""
        return (val + align - 1) & ~(align - 1)

    def stats(self) -> dict:
        return {
            'min_chunk_size': MIN_CHUNK_SIZE,
            'alignment': MALLOC_ALIGNMENT,
            'max_fast_size': MAX_FAST_SIZE,
            'mmap_threshold': DEFAULT_MMAP_THRESHOLD,
            'modeled_allocs': len(self._cache),
        }

    def clear(self) -> None:
        self._cache.clear()
