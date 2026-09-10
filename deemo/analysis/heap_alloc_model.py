"""
堆分配器模型 — ptmalloc2/jemalloc/tcmalloc 的抽象建模。

背景: malloc(n) 不能按字面 n 字节建模 — 实际分配器存在最小 chunk
(ptmalloc2 64-bit 为 32B)、16B 对齐、内部碎片与 size→chunk 映射规则;
忽略这些约束会引入大量误报, 如 malloc(5) 实际可用区大于 5B, 朴素区间
[0,4] 会把 offset≥5 的写入误判为溢出。

依据: ptmalloc2 的 request2size 宏; jemalloc 的 sz_size2index 量化表;
GCC -Walloc-size-larger-than= / -Wstringop-overflow= 启发式。

设计决策: 默认 ptmalloc2 (Linux x86_64 最常见); 后端可插拔, 支持
jemalloc/tcmalloc 的 size class 查表; 分配器未知时保守取最小对齐假设
(16B, 不假设 min chunk)。
"""

from dataclasses import dataclass
from typing import Dict, Optional, Tuple, List
from enum import Enum

class AllocatorKind(Enum):
    PTMALLOC2 = "ptmalloc2"      # glibc 默认
    JEMALLOC = "jemalloc"         # FreeBSD / Facebook
    TCMALLOC = "tcmalloc"         # Google
    MINIMAL = "minimal"           # 仅 16-byte 对齐, 不做 min chunk 假设

@dataclass
class HeapChunkModel:
    """一次 malloc 调用的堆块模型."""
    requested_size: int       # 用户请求大小
    usable_size: int          # 实际可用大小 (含内部碎片, 不含metadata)
    alignment: int            # 对齐约束
    min_offset: int = 0       # 合法写入最小偏移
    max_offset: int = 0       # 合法写入最大偏移 (usable_size - 1)

    def __post_init__(self):
        self.min_offset = 0
        self.max_offset = max(0, self.usable_size - 1)

    def is_offset_safe(self, offset: int, access_size: int = 1) -> bool:
        """检查偏移+访问大小是否在合法范围内."""
        end = offset + access_size
        return self.min_offset <= offset and end <= self.usable_size

# ptmalloc2 glibc 模型 (x86_64)

class Ptmalloc2Model:
    """ptmalloc2 (glibc) 堆分配器模型 — x86_64。

    依据 (glibc-2.35 malloc/malloc.c):
      MALLOC_ALIGNMENT = 16 (2*SIZE_SZ, SIZE_SZ = 8)
      MINSIZE = 4*SIZE_SZ = 32 (最小 chunk 大小)
      request2size(req) = max(MINSIZE, ((req) + SIZE_SZ + 15) & ~15),
                          结果为含 header 的 chunk 大小。

    使用中 chunk 的 fd/bk 区可被用户数据复用。为削减误报, 不用精确的
    requested_size 作为写边界, 而取 (requested_size + 对齐填充);
    usable_size() 采用保守口径: 16 字节对齐、下限 16, 且不低于请求大小。
    """

    ALIGNMENT = 16
    MIN_CHUNK = 32       # MINSIZE
    MIN_USABLE = 16      # MINSIZE - 2*SIZE_SZ (保守值)
    OVERHEAD = 16        # prev_size + size header

    @staticmethod
    def usable_size(requested: int) -> int:
        """获取用户请求 size 对应的实际可用大小."""
        if requested <= 0:
            return 0
        # glibc request2size 近似
        raw = requested + Ptmalloc2Model.OVERHEAD - 8  # +8 是因为 SIZE_SZ 已在 overhead 中
        # 对齐到 16
        aligned = (raw + 15) & ~15
        chunk_size = max(Ptmalloc2Model.MIN_CHUNK, aligned)
        usable = chunk_size - Ptmalloc2Model.OVERHEAD
        return max(usable, requested)  # 至少不低于用户请求

# jemalloc 模型

class JemallocModel:
    """jemalloc size class 模型.

    jemalloc 使用预定义的 size class 表:
      小分配 (≤ 14336 bytes on 64-bit): 取最近的 size class
      大分配: 对齐到 PAGE (4096)

    参考: jemalloc-5.3.0 include/jemalloc/internal/size_classes.h
    """

    # jemalloc 5.x 64-bit small size classes (quantum=16, lg_quantum=4)
    _SMALL_CLASSES: Tuple[int, ...] = (
        8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256,
        320, 384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792,
        2048, 2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192,
        10240, 12288, 14336,
    )

    @staticmethod
    def usable_size(requested: int) -> int:
        """返回 jemalloc 的实际 usable size."""
        if requested <= 0:
            return 0
        for sz in JemallocModel._SMALL_CLASSES:
            if requested <= sz:
                return sz
        # 大分配: 对齐到 4096
        return ((requested + 4095) // 4096) * 4096

# 通用接口

class HeapAllocModel:
    """堆分配器模型 — 统一接口.

    用途:
      model = HeapAllocModel(AllocatorKind.PTMALLOC2)
      chunk = model.model_allocation(malloc_size=100)  # 100B 请求
      print(chunk.usable_size)  # 实际可用大小
      print(chunk.is_offset_safe(offset=95, access_size=8))  # False (溢出)
    """

    def __init__(self, kind: AllocatorKind = AllocatorKind.PTMALLOC2):
        self.kind = kind
        self._model = {
            AllocatorKind.PTMALLOC2: Ptmalloc2Model,
            AllocatorKind.JEMALLOC: JemallocModel,
            AllocatorKind.TCMALLOC: Ptmalloc2Model,  # tcmalloc 近似同 ptmalloc
            AllocatorKind.MINIMAL: None,
        }[kind]

    def model_allocation(self, malloc_size: int) -> HeapChunkModel:
        """获取一次 malloc(size) 的完整堆块模型."""
        if malloc_size <= 0:
            return HeapChunkModel(0, 0, 16)

        if self._model is not None:
            usable = self._model.usable_size(malloc_size)
            alignment = self._model.ALIGNMENT if hasattr(self._model, 'ALIGNMENT') else 16
        else:
            # MINIMAL: 只对齐到 16, 不添加额外 usable
            usable = (malloc_size + 15) & ~15
            alignment = 16

        return HeapChunkModel(
            requested_size=malloc_size,
            usable_size=usable,
            alignment=alignment,
            min_offset=0,
            max_offset=usable - 1)

    def safe_write_range(self, malloc_size: int) -> Tuple[int, int]:
        """返回安全写入的偏移范围 (inclusive)."""
        chunk = self.model_allocation(malloc_size)
        return (chunk.min_offset, chunk.max_offset)

    def may_overflow(self, malloc_size: int, write_offset: int,
                     write_size: int = 1) -> bool:
        """检查给定参数组合是否可能构成溢出."""
        chunk = self.model_allocation(malloc_size)
        return not chunk.is_offset_safe(write_offset, write_size)
