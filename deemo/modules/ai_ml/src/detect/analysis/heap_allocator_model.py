# 堆分配器行为模型——建模glibc ptmalloc的内部约束
# 关键事实: malloc(N)因对齐而实际可用 > N
# 不建模: malloc(32)+memcpy(38)被误判溢出，但实际可用≥40字节
#
# 理论依据:
#   - glibc ptmalloc2: overhead=SIZE_SZ=8, round_up(N+SIZE_SZ, 16)-SIZE_SZ
# dlmalloc: 对齐8/16字节，chunk overhead=8/16字节
#   - "Heap Disjointness": 堆对象自然分离，无需保守假设
#
# 决策: 默认glibc x86_64(overhead=8, min_chunk=32, alignment=16)
#       musl用overhead=16(与glibc不同)，jemalloc=8, windows_heap=16

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
import logging

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class AllocatorKind(Enum):
    GLIBC_PTMALLOC2 = "glibc_ptmalloc2"
    MUSL_MALLOCNG = "musl_mallocng"
    JEMALLOC = "jemalloc"
    WINDOWS_HEAP = "windows_heap"


@dataclass(frozen=True)
class AllocatorParams:
    """堆分配器的行为参数——每个分配器有不同的对齐/overhead策略"""
    min_alignment: int       # 最小对齐字节数
    chunk_overhead: int      # chunk header大小(bytes)
    min_chunk_size: int      # 最小chunk大小(bytes,含header)
    round_up_to: int         # 对齐粒度(通常=min_alignment的倍数)
    use_bins: bool = True    # 是否使用bin管理(影响小chunk的合并)


# 常见分配器参数——实测和源码验证
_ALLOCATOR_PARAMS = {
    AllocatorKind.GLIBC_PTMALLOC2: AllocatorParams(
        # overhead=8 (SIZE_SZ): next chunk的prev_size字段可被当前chunk数据复用
        min_alignment=16, chunk_overhead=8, min_chunk_size=32,
        round_up_to=16),
    AllocatorKind.MUSL_MALLOCNG: AllocatorParams(
        min_alignment=16, chunk_overhead=16, min_chunk_size=32,
        round_up_to=16),
    AllocatorKind.JEMALLOC: AllocatorParams(
        min_alignment=16, chunk_overhead=8, min_chunk_size=16,
        round_up_to=16),
    AllocatorKind.WINDOWS_HEAP: AllocatorParams(
        min_alignment=16, chunk_overhead=16, min_chunk_size=48,
        round_up_to=16),
}


class HeapAllocatorModel:
    """堆分配器行为模型——计算malloc(N)的实际可用空间。

    一个size参数为N的malloc调用实际提供多少可安全写入的字节?
    答: usable_size(N) = round_up(N + overhead, alignment) - overhead

    示例(glibc x64, alignment=16, overhead=8):
      malloc(32) → round_up(40,16)-8 = 48-8 = 40 (不是32)
      malloc(48) → round_up(56,16)-8 = 64-8 = 56
      malloc(1)  → max(32, round_up(9,16)) - 8 = 32-8 = 24 (最小chunk)
    """

    def __init__(self,
                 kind: AllocatorKind = AllocatorKind.GLIBC_PTMALLOC2,
                 params: AllocatorParams | None = None):
        self._kind = kind
        self._params = params or _ALLOCATOR_PARAMS.get(
            kind, _ALLOCATOR_PARAMS[AllocatorKind.GLIBC_PTMALLOC2])

    @property
    def alignment(self) -> int:
        return self._params.min_alignment

    @property
    def overhead(self) -> int:
        return self._params.chunk_overhead

    @property
    def min_usable(self) -> int:
        return self._params.min_chunk_size - self._params.chunk_overhead

    def usable_size(self, requested_bytes: int) -> int:
        """给定malloc(N)中的N, 返回实际可安全写入的字节数。

        调用方可以安全写入usable_size(N)字节而不会溢出到相邻chunk。
        用于与memcpy的拷贝大小对比——若copy_size <= usable_size(alloc_size),
        则不是溢出。
        """
        if requested_bytes <= 0:
            return 0
        p = self._params
        # round_up(requested + overhead, alignment) - overhead
        total = requested_bytes + p.chunk_overhead
        if total % p.round_up_to != 0:
            total = ((total // p.round_up_to) + 1) * p.round_up_to
        if total < p.min_chunk_size:
            total = p.min_chunk_size
        return total - p.chunk_overhead

    def is_safe_copy(self, alloc_requested: int, copy_bytes: int,
                     margin: int = 0) -> bool:
        """判断从malloc(alloc_requested)获得的缓冲区是否能安全容纳copy_bytes。

        margin: 额外的安全边界(默认0, 保守场景可设8-16)

        返回True表示安全(不会溢出), False表示潜在溢出。
        """
        usable = self.usable_size(alloc_requested)
        return copy_bytes <= usable - margin

    def overflow_bytes(self, alloc_requested: int, copy_bytes: int) -> int:
        """计算溢出字节数——负数或0表示安全"""
        usable = self.usable_size(alloc_requested)
        return copy_bytes - usable

# 多分配函数支持

    def usable_size_for_func(self, alloc_func: str,
                              args: list[int]) -> int:
        """对特定分配函数计算可用空间。
        calloc(nmemb, size)需要特殊处理——arg[0]*arg[1]后需要同样的对齐。
        """
        func = alloc_func.lower()
        if func == 'calloc':
            if len(args) >= 2 and args[0] > 0 and args[1] > 0:
                return self.usable_size(args[0] * args[1])
            return 0
        elif func in ('malloc', 'realloc', 'alloca'):
            return self.usable_size(args[0]) if args else 0
        elif func == 'realloc':
            return self.usable_size(args[1]) if len(args) >= 2 else (
                self.usable_size(args[0]) if args else 0)
        return 0
