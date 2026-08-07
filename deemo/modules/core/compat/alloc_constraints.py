# coding: utf-8
"""分配器约束建模 — 将 glibc/ptmalloc 的对齐与大小类约束纳入安全证明.

堆溢出误报的另一主因: 分析器忽略了分配器内部的对齐和最小块约束.
例如 malloc(5) 实际分配 16 字节 (对齐到 16B 且最小块 32B on x64),
用户写入 8 字节不会溢出到下一块.

本模块为常见分配器建模这些约束, 用于在溢出判定时调整写入大小阈值.
"""

from dataclasses import dataclass
from typing import Dict, Optional


@dataclass
class AllocConstraints:
    """分配器的内部约束参数."""
    min_chunk_size: int = 32       # 最小分配块 (含元数据, x64 glibc)
    alignment: int = 16            # 对齐边界
    metadata_overhead: int = 16    # 每块元数据开销 (prev_size + size)
    tcache_bin_max: int = 1032     # tcache 最大块 (glibc 2.26+, x64)
    fastbin_max: int = 160         # fastbin 最大块 (含元数据)

    def effective_size(self, requested: int) -> int:
        """返回给定请求大小的实际分配大小 (含对齐和最小块约束)."""
        # glibc: chunk_size = max(MINSIZE, (requested + MALLOC_ALIGNMENT - 1) & ~(MALLOC_ALIGNMENT-1))
        # 其中 MINSIZE = 32 (x64), MALLOC_ALIGNMENT = 16
        needed = requested + self.metadata_overhead
        aligned = (needed + self.alignment - 1) & ~(self.alignment - 1)
        return max(self.min_chunk_size, aligned)

    def usable_size(self, requested: int) -> int:
        """用户实际可用的字节数 (去除元数据后的净大小)."""
        return self.effective_size(requested) - self.metadata_overhead


# 常见分配器的预定义约束
CONSTRAINTS: Dict[str, AllocConstraints] = {
    'glibc_ptmalloc_x64': AllocConstraints(
        min_chunk_size=32, alignment=16, metadata_overhead=16,
        tcache_bin_max=1032, fastbin_max=160,
    ),
    'glibc_ptmalloc_x86': AllocConstraints(
        min_chunk_size=16, alignment=8, metadata_overhead=8,
        tcache_bin_max=516, fastbin_max=80,
    ),
    'windows_lfh_x64': AllocConstraints(
        min_chunk_size=48, alignment=16, metadata_overhead=16,
    ),
    'kernel_slab': AllocConstraints(
        min_chunk_size=8, alignment=8, metadata_overhead=0,
    ),
}


def get_constraints(allocator_type: str, arch: str = 'x86_64') -> AllocConstraints:
    """根据分配器类型和架构获取约束."""
    key = f'{allocator_type}_{arch}'
    if key in CONSTRAINTS:
        return CONSTRAINTS[key]
    if allocator_type in ('glibc_ptmalloc', 'generic'):
        return CONSTRAINTS.get(f'glibc_ptmalloc_{arch}',
                              CONSTRAINTS['glibc_ptmalloc_x64'])
    return AllocConstraints()


def is_overflow_infeasible(
    requested_alloc: int, write_size: int,
    allocator_type: str = 'glibc_ptmalloc', arch: str = 'x86_64',
) -> bool:
    """判断: 给定分配请求大小和写入大小, 溢出是否不可能发生.

    返回 True = 可证明不会溢出 (写操作完全落在分配块内).
    理由: malloc(N) 实际分配 effective_size(N) 字节, 用户可用 usable_size(N).
    若 write_size ≤ usable_size(N), 则不会溢出.
    """
    constraints = get_constraints(allocator_type, arch)
    usable = constraints.usable_size(requested_alloc)
    return write_size <= usable
