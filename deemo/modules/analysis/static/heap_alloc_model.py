# 堆分配器感知的约束模型 (Heap Allocator-Aware Constraint Model)
#
# 核心决策:
#   堆溢出误报的一个重要来源是未考虑分配器的内部行为.
#   例如 glibc malloc(62) 实际分配的是 80 字节的 chunk (含元数据),
#   写入 63 字节不会溢出. 但简单的 min(align(request, 16), 32) 不够精确.
#
#   本模块为不同堆分配器提供精确的 size→chunk_size 映射.
#   支持: glibc ptmalloc2, jemalloc, tcmalloc, Windows RtlHeap.
#
# 建模来源:
#   - glibc malloc.c (2.35-2.39): chunk_size = max(MINSIZE, request+2*SIZE_SZ) 按 MALLOC_ALIGNMENT 对齐
#   - jemalloc 5.3: size class 查找表
#   - tcmalloc: page 级大小分配
#

from enum import Enum
from typing import Dict, Optional, Tuple


class AllocatorFamily(Enum):
    GLIBC = "glibc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    WINDOWS = "windows"
    GENERIC = "generic"


# glibc 2.35+: MALLOC_ALIGNMENT = 16, MINSIZE = 32 (x86-64), SIZE_SZ = 8
# chunk 开销 = 2 * SIZE_SZ = 16 bytes (prev_size + size)
# 最小可用空间 = MINSIZE - 2*SIZE_SZ = 16 bytes
# 请求大小按对齐存储

def glibc_chunk_size(request: int) -> int:
    """glibc ptmalloc2 的实际 chunk 大小 (x86-64).

    request: 用户请求的字节数.
    返回: 实际 chunk 的总大小 (含元数据).
    可用数据区 = chunk_size - SIZE_SZ (8 bytes), 因为下一个chunk的
    prev_size字段在当前chunk in-use时可复用.

    glibc request2size公式:
      (request + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK
      SIZE_SZ=8, MALLOC_ALIGN_MASK=15, MINSIZE=32
    """
    if request < 0:
        return 32
    size = (request + 8 + 15) & ~15
    return max(size, 32)


# jemalloc size classes (5.x, x86-64)
_JEMALLOC_SIZE_CLASSES = [
    8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144,
    7168, 8192, 10240, 12288, 14336, 16384,
]


def jemalloc_chunk_size(request: int) -> int:
    """jemalloc 分配器: 返回所属 size class 的大小."""
    for sc in _JEMALLOC_SIZE_CLASSES:
        if request <= sc:
            return sc
    # 大对象: 页面对齐
    return (request + 4095) & ~4095


# tcmalloc: 使用 size map, 简化模型
_TCMALLOC_CLASSES = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]


def tcmalloc_chunk_size(request: int) -> int:
    """tcmalloc: 向上取到最近的 size class."""
    for sc in _TCMALLOC_CLASSES:
        if request <= sc:
            return sc
    return (request + 4095) & ~4095


# Windows HeapAlloc: 默认 8 字节对齐, 最小块 16 字节
def windows_chunk_size(request: int) -> int:
    """Windows RtlHeap / HeapAlloc."""
    return max(16, (request + 7) & ~7)


_ALLOCATOR_MODELS = {
    AllocatorFamily.GLIBC: glibc_chunk_size,
    AllocatorFamily.JEMALLOC: jemalloc_chunk_size,
    AllocatorFamily.TCMALLOC: tcmalloc_chunk_size,
    AllocatorFamily.WINDOWS: windows_chunk_size,
    AllocatorFamily.GENERIC: lambda r: max(16, (r + 15) & ~15),
}


class HeapAllocModel:
    """堆分配器行为模型.

    提供: request_size → actual_chunk_size 映射.
    不同分配器的内部开销不同, 影响"是否溢出"的判断.
    """

    def __init__(self, family: AllocatorFamily = AllocatorFamily.GLIBC):
        self._family = family
        self._model = _ALLOCATOR_MODELS.get(family, _ALLOCATOR_MODELS[AllocatorFamily.GENERIC])

    def actual_chunk_size(self, request: int) -> int:
        """用户请求N字节 → 分配器实际分配的chunk总大小."""
        return self._model(request)

    def usable_size(self, request: int) -> int:
        """用户请求N字节 → 实际可安全写入的字节数 (malloc_usable_size近似).

        glibc: usable = chunk - SIZE_SZ(8), 因下一个chunk的prev_size在
        当前chunk in-use时可被复用, 实际可写8字节额外空间.
        """
        chunk = self.actual_chunk_size(request)
        if self._family == AllocatorFamily.GLIBC:
            return chunk - 8
        elif self._family == AllocatorFamily.JEMALLOC:
            return chunk
        elif self._family == AllocatorFamily.TCMALLOC:
            return chunk - 8
        elif self._family == AllocatorFamily.WINDOWS:
            return chunk - 8
        return chunk

    def is_overflow(self, request: int, write_size: int) -> Tuple[bool, str]:
        """判断给定请求大小和写入大小是否构成溢出.

        返回: (溢出标志, 判断依据描述).
        """
        usable = self.usable_size(request)
        if write_size <= usable:
            return False, (
                f"safe: write({write_size}) <= usable({usable}) "
                f"[request={request}, chunk={self.actual_chunk_size(request)}, "
                f"allocator={self._family.value}]"
            )
        return True, (
            f"overflow: write({write_size}) > usable({usable}) "
            f"[request={request}, chunk={self.actual_chunk_size(request)}, "
            f"allocator={self._family.value}]"
        )

    def min_overflow_write(self, request: int) -> int:
        """给定分配请求, 触发溢出的最小写入量."""
        return self.usable_size(request) + 1

    @property
    def family(self) -> AllocatorFamily:
        return self._family

    def set_family(self, family: AllocatorFamily):
        self._family = family
        self._model = _ALLOCATOR_MODELS.get(family, _ALLOCATOR_MODELS[AllocatorFamily.GENERIC])

    @staticmethod
    def detect_allocator(imports: Dict[str, str]) -> AllocatorFamily:
        """从导入表推断二进制使用的堆分配器.

        imports: {函数名: 来源库} 的字典.
        """
        funcs = set(imports.keys())
        if "__libc_malloc" in funcs or "malloc@GLIBC" in funcs:
            return AllocatorFamily.GLIBC
        if "je_malloc" in funcs or "mallocx" in funcs:
            return AllocatorFamily.JEMALLOC
        if "tc_malloc" in funcs:
            return AllocatorFamily.TCMALLOC
        if "HeapAlloc" in funcs or "RtlAllocateHeap" in funcs:
            return AllocatorFamily.WINDOWS
        # 大部分Linux ELF链接glibc
        if any("GLIBC" in k for k in funcs):
            return AllocatorFamily.GLIBC
        return AllocatorFamily.GENERIC


__all__ = [
    "HeapAllocModel", "AllocatorFamily",
    "glibc_chunk_size", "jemalloc_chunk_size",
    "tcmalloc_chunk_size", "windows_chunk_size",
]
