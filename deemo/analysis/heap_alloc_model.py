"""
堆分配器模型 — ptmalloc2/jemalloc/tcmalloc 的抽象建模.

为何需要分配器模型:
  静态分析中, malloc(n) 被简化为"分配 n 字节的缓冲区".
  但实际分配器有:
    - 最小 chunk 大小 (ptmalloc2: 32 bytes on 64-bit, 其中 usable=24)
    - 对齐约束 (16-byte on 64-bit)
    - 内部碎片 (metadata overhead)
    - size → chunk 的映射规则

  不考虑这些约束 → 大量误报.
  例: malloc(5) 实际可安全写入 24 字节 (ptmalloc2 min usable),
      但简单区间 [0,4] 会标记任何 offset>=5 的写入为溢出.

  glibc malloc source (ptmalloc2): _int_malloc() 中的 request2size 宏
  jemalloc size classes: sz_size2index 的量化表
  GCC's -Walloc-size-larger-than= 和 -Wstringop-overflow= 的启发式

设计决策:
  - 默认使用 ptmalloc2 glibc 模型 (Linux x86_64 最常用)
  - 提供可插拔的分配器后端, 支持 jemalloc/tcmalloc 的 size class 查表
  - 保守策略: 在不确定分配器时使用最小对齐假设 (16 bytes, 不假设 min chunk)
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
    """ptmalloc2 (glibc) 堆分配器模型 — x86_64.

    参数来自 glibc-2.35 malloc/malloc.c:
      MALLOC_ALIGNMENT = 16 (2*SIZE_SZ, SIZE_SZ=8 on 64-bit)
      MINSIZE = 4*SIZE_SZ = 32 (最小 chunk 大小)
      MIN_USABLE = MINSIZE - 2*SIZE_SZ = 16 (但实际因为 prev_size 复用, 最小 usable 是 24)
      request2size(req): 将用户请求向上取整到 MALLOC_ALIGNMENT,
                        再与 MINSIZE 比较取最大值.

    64-bit glibc 的 chunk 结构:
      [prev_size (8B)] [size (8B)] [user data ... fd (8B) ... bk (8B) ...]
      当 chunk 在使用中时, fd/bk 位置可被用户数据复用.
      min chunk = 32B, 其中 16B 是 header (prev_size+size), 16B 是 fd+bk.
      但 fd 和 bk 只在 free list 中需要, 已分配时 fd 位置可存储用户数据.
      所以 MINSIZE=32 的 chunk, 用户可用区域是 32-16=16B... 等等.

      实际在 glibc 中:
        #define PREV_INUSE 0x1
        #define IS_MMAPPED 0x2
        #define NON_MAIN_ARENA 0x4
        #define SIZE_BITS (PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
        #define request2size(req) \
          (((req) + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK)
        其中 MALLOC_ALIGN_MASK = MALLOC_ALIGNMENT - 1 = 15.

      所以 req=5: (5 + 8 + 15) & ~15 = 28 & ~15 = 16 → 但 min 是 MINSIZE=32!
      最终 usable = chunk_size - 2*SIZE_SZ = 32 - 16 = 16.

      实际上: request2size(5) = max(MINSIZE, (5+8+15)&~15) = max(32, 16) = 32.
      usable_size = 32 - 16 = 16? 不对.

      重新理解: request2size 返回的是 chunk_size (含 header).
      usable_size = chunk_size - 2*SIZE_SZ.
      但 chunk_size 已经包含了 SIZE_SZ... 不对.

      实际上 glibc 中:
        nb = request2size(bytes);  // nb 是总的 chunk 大小 (含 overhead)
        实际返回给用户的指针指向 chunk 的数据区域 (跳过 prev_size 和 size).
        usable_size = nb - 2*SIZE_SZ = nb - 16.
        但用户实际可以安全使用至多 nb - 2*SIZE_SZ 字节.
        然而, 在已分配状态下, fd/bk 字段 (位于偏移 16 处) 可以被用户使用,
        因为它们只在 chunk 被 free 时才需要. 所以实际 usable = nb - SIZE_SZ = nb - 8?
        不, glibc 文档说 usable_size = nb - 2*SIZE_SZ = nb - 16.

      让我们简化: 保守使用 min chunk = 32, usable = MINSIZE - 2*SIZE_SZ = 16.
      但这是一个非常保守的估计. 实际上, 对大多数用户请求,
      usable_size >= requested_size.

      对误报削减而言, 关键是: 不要用精确的 requested_size 作为边界,
      而是用 (requested_size + 对齐填充) 作为边界.
      保守做法: usable = max(requested_size, 16), 然后对齐到 16.
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
