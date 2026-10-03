"""
分配器chunk模型 —— 建模glibc ptmalloc的堆块布局, 识别"slack space"。

核心问题: 堆溢出检测简单比较 store_offset > malloc_size 时就报溢出,
但 glibc ptmalloc 实际分配的 chunk 比请求大小大:
  - chunk header: 16 bytes (prev_size + size, 或 8 bytes on 32-bit)
  - 最小 chunk: 32 bytes (x86_64)
  - 对齐: 16 bytes (x86_64 MALLOC_ALIGNMENT)
  - tcache/fastbin 对其有额外的 binning 约束

malloc(100) → 实际 chunk 可用空间 = align_up(100 + 16, 16) - 16
            = 112 - 16 = 96? 不。实际分配逻辑:
            usable_size = max(MIN_CHUNK_SIZE - 2*SIZE_SZ, aligned_size) - 2*SIZE_SZ

更精确: glibc 的 request2size():
  request2size(req) = max(MINSIZE, (req + SIZE_SZ + MALLOC_ALIGNMENT - 1)
                                & ~(MALLOC_ALIGNMENT - 1))
其中 SIZE_SZ = 8 (x86_64), MINSIZE = 32, MALLOC_ALIGNMENT = 16.

所以:
  malloc(1)  → usable = 32 - 16 = 16? 实际结果是可用空间>请求,
              但有最小chunk限制. 精确地说, 返回的chunk可用空间 >= req.
  malloc(100) → req+8 = 108 → align_up(108,16) = 112.
              可用空间 = 112 - 8(prev_size only, size共享) >= 104.

对于静态分析, 我们只需要一个保守的 slack space 计算:
  actual_usable = max(alloc_arg, align_up(alloc_arg, MALLOC_ALIGNMENT))

store offset 落在 [alloc_arg, actual_usable) 区间内 → 非溢出
store offset >= actual_usable → 溢出

这消除了一类根本性的误报: "写入偏移大于malloc参数, 但仍在chunk边界内"。

  - glibc source: malloc/malloc.c — request2size(), checked_request2size()
  - "Malloc Des-Maleficarum" (blackngel, Phrack 66): chunk layout exploitation
  - "The Art of Exploitation": heap internals chapter
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional, Tuple

class Allocator(str, Enum):
    GLIBC_PTMALLOC = "glibc_ptmalloc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    UNKNOWN = "unknown"

# glibc ptmalloc constants (x86_64)
SIZE_SZ = 8            # sizeof(size_t)
MALLOC_ALIGNMENT = 16  # 2 * SIZE_SZ
MINSIZE = 32           # 4 * SIZE_SZ (minimum chunk size)
CHUNK_OVERHEAD = 16    # prev_size(8) + size(8) — 但 prev_size 可复用

@dataclass
class ChunkLayout:
    """一个堆chunk的内存布局估计。"""
    requested_size: int       # malloc的参数
    chunk_size: int           # 实际chunk总大小 (含metadata)
    usable_size: int          # 用户可用字节数
    alignment: int = MALLOC_ALIGNMENT
    overhead: int = CHUNK_OVERHEAD
    allocator: Allocator = Allocator.GLIBC_PTMALLOC

    @property
    def slack_space(self) -> int:
        """请求大小之上、chunk可用空间之内的'余量'字节数。"""
        return max(0, self.usable_size - self.requested_size)

def align_up(size: int, alignment: int = MALLOC_ALIGNMENT) -> int:
    return ((size + alignment - 1) // alignment) * alignment

def glibc_request2size(request: int) -> int:
    """Glibc request2size() 的保守近似。

    返回chunk可用空间的下界估计。
    实际glibc更复杂(tcache, fastbin, mmap阈值),
    这里只计算最坏情况下的最小可用空间。

    关键: in-use chunk的prev_size字段可被复用(user data),
    因此usable = chunk_total - SIZE_SZ (仅减去size字段).
    """
    if request <= 0:
        return 0
    padded = request + SIZE_SZ
    if padded < MINSIZE:
        padded = MINSIZE
    chunk_total = align_up(padded, MALLOC_ALIGNMENT)
    usable = chunk_total - SIZE_SZ
    return max(0, usable)

def estimate_chunk_layout(
    alloc_arg: int,
    alloc_func: str = 'malloc',
    allocator: Allocator = Allocator.GLIBC_PTMALLOC,
) -> ChunkLayout:
    """根据分配函数和参数, 估计实际chunk布局。

    calloc(n,m)处理: 总请求 = n*m, 对齐由calloc内部处理。
    realloc(ptr, n): chunk布局同malloc(n)。
    """
    if allocator == Allocator.GLIBC_PTMALLOC:
        usable = glibc_request2size(alloc_arg)
        chunk_total = usable + 2 * SIZE_SZ
        # 确保 chunk_total 已对齐
        chunk_total = align_up(chunk_total, MALLOC_ALIGNMENT)
    else:
        # 保守: 假设不额外对齐, slack=0
        usable = alloc_arg
        chunk_total = alloc_arg + CHUNK_OVERHEAD

    return ChunkLayout(
        requested_size=alloc_arg,
        chunk_size=chunk_total,
        usable_size=usable,
        alignment=MALLOC_ALIGNMENT,
        overhead=CHUNK_OVERHEAD,
        allocator=allocator,
    )

def is_within_slack(store_offset: int, layout: ChunkLayout) -> bool:
    """判断store_offset是否落在slack空间内(合法写入, 非溢出)。"""
    return layout.requested_size <= store_offset < layout.usable_size

def would_overflow(store_offset: int, store_size: int,
                   layout: ChunkLayout) -> Tuple[bool, int, str]:
    """判断写入是否会溢出chunk边界。

    返回 (is_overflow, overflow_bytes, reason)。

    考虑三项:
      1. 写入起始偏移 < usable_size → 可能安全
      2. 写入结束 = offset + size → 若 > usable_size → 溢出
      3. 若store_size未知(-1), 保守按1字节算
    """
    effective_store_size = max(1, store_size)
    write_end = store_offset + effective_store_size

    if write_end <= layout.requested_size:
        return False, 0, (
            f'write ends at {write_end} <= requested {layout.requested_size}')
    if write_end <= layout.usable_size:
        return False, 0, (
            f'write ends at {write_end} <= usable {layout.usable_size} '
            f'(within slack)')
    overflow = write_end - layout.usable_size
    return True, overflow, (
        f'write ends at {write_end} > usable {layout.usable_size} '
        f'(overflow by {overflow}B)')

def compute_effective_boundary(
    alloc_arg: int,
    alloc_func: str = 'malloc',
) -> int:
    """计算堆分配的'有效边界'——store offset必须超过它才算溢出。

    这是误报过滤的核心: 不用malloc的参数做边界,
    而用分配器实际给chunk分配的空间做边界。

    保守设计: 使用 max(alloc_arg, usable_size) 的上界,
    保证零漏报——只有明确超出chunk的写入才报告。
    """
    layout = estimate_chunk_layout(alloc_arg, alloc_func)
    return max(alloc_arg, layout.usable_size)
