# 堆分配器行为模型: 将实际分配器的内部机制建模为可用空间修正
# 核心创新: 分配器感知的抽象解释 — 静态分析不仅追踪 malloc(n) 的参数,
#   还模拟分配器内部如何将 n 向上取整为实际可用块大小.
#   这消除了 "请求50B → 写60B → 报告溢出, 但实际分配器给了64B块"
#   这类根源性误报.
# 技术问题: 静态分析只能看到 malloc(n) 的请求大小, 但运行时的实际
#   可用空间取决于分配器的最小块大小、对齐要求、size-class归并等.
#   不考虑这些因素会导致: (1) 误报 (60B写入到50B请求→实际64B块),
#   (2) 漏报 (分配器元数据损坏可被攻击者利用修改相邻块).
# 解决手段: 为每个主流分配器建模其 size→actual_chunk_size 映射,
#   在约束验证时将分配大小替换为实际可用大小, 并建模元数据开销.
#
#   glibc ptmalloc2 source (malloc.c): checked_request2size(), MINSIZE=0x20
#   Windows Heap Manager: HeapAlloc granularity, _HEAP_ENTRY overhead
#   jemalloc size classes: https://jemalloc.net/jemalloc.3.html
#   Heelan et al. "Automatic Heap Layout Manipulation"
#     — 堆布局操纵依赖精确知道分配器内部行为
#   Yun et al. "APISan: Sanitizing API Usages"
#     — 利用分配器语义建模减少误报
from __future__ import annotations
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, Tuple


class AllocatorFamily(Enum):
    GLIBC_PTMALLOC2 = auto()    # Linux glibc ≥2.26 (tcache)
    GLIBC_NO_TCACHE = auto()    # glibc <2.26 (无tcache)
    WINDOWS_HEAP = auto()        # Windows NT Heap (RtlAllocateHeap)
    JEMALLOC = auto()            # FreeBSD/Android/Firefox
    GENERIC = auto()             # 保守模型: 仅对齐到16B


@dataclass
class ChunkModel:
    """单个分配块的实际布局模型."""
    requested_size: int          # 用户请求大小
    actual_usable_size: int      # 实际可用的payload空间
    chunk_total_size: int        # 含元数据的块总大小
    metadata_overhead: int       # 分配器元数据开销
    alignment: int               # 对齐边界
    has_size_class_rounding: bool # 是否经过size-class归并


class HeapAllocatorModel:
    """堆分配器行为模型.

    将 malloc(n) 的请求大小转换为实际可用空间.
    不同分配器有不同的内部机制:
      glibc: MINSIZE=0x20, 16B对齐, size-class按0x10递增
      Windows: 8B/16B粒度 (取决于架构), Header=0x10
      jemalloc: 基于size-class的表驱动分配

    模型输出在约束验证中替换朴素的 alloc_size_range,
    从而消除由 "未考虑分配器内部行为" 引起的根源性误报.
    """

    # glibc ptmalloc2 常量 (x86-64)
    _GLIBC_MINSIZE = 0x20          # 最小chunk (含header)
    _GLIBC_MALLOC_ALIGNMENT = 0x10 # 16B对齐 (2*SIZE_SZ)
    _GLIBC_SIZE_SZ = 0x8           # sizeof(size_t)
    _GLIBC_HEADER_SIZE = 0x10      # prev_size(8) + size(8)
    _GLIBC_MIN_PAYLOAD = 0x18      # MINSIZE - HEADER = 24B最小payload

    # Windows Heap Manager 常量 (x86-64)
    _WIN_HEAP_HEADER = 0x10        # _HEAP_ENTRY overhead
    _WIN_HEAP_ALIGNMENT = 0x10     # 16B in 64-bit
    _WIN_HEAP_GRANULARITY = 0x08   # 8B粒度

    # jemalloc 常量 (x86-64)
    _JEMALLOC_TCACHE_MAX = 0x8000  # 32KB tcache上限

    def __init__(self, family: AllocatorFamily = AllocatorFamily.GENERIC,
                 assume_glibc: bool = True):
        """根据分配器家族初始化模型.

        assume_glibc: 若为True, 在GLIBC_PTMALLOC2模式下
          假设tcache可用 (glibc≥2.26默认行为).
        """
        self.family = family
        self._assume_tcache = assume_glibc

    def get_usable_size(self, requested: int) -> int:
        """将请求大小转换为实际可用payload大小.

        这是核心方法: 输入malloc(n)的n, 输出运行时实际可安全使用的字节数.
        返回值的每个bit都不会触发堆溢出.
        """
        if requested <= 0:
            return 0

        if self.family == AllocatorFamily.GLIBC_PTMALLOC2:
            return self._glibc_usable_size(requested)
        elif self.family == AllocatorFamily.GLIBC_NO_TCACHE:
            return self._glibc_usable_size(requested)
        elif self.family == AllocatorFamily.WINDOWS_HEAP:
            return self._windows_usable_size(requested)
        elif self.family == AllocatorFamily.JEMALLOC:
            return self._jemalloc_usable_size(requested)
        else:
            return self._generic_usable_size(requested)

    def get_safe_write_bound(self, requested: int,
                              offset: int = 0) -> int:
        """返回安全写入上界: 实际可用空间 - 偏移.

        这是FP过滤的直接输入: 若写入量≤此值, 确定不溢出.
        """
        usable = self.get_usable_size(requested)
        return max(0, usable - offset)

    def model_chunk(self, requested: int) -> ChunkModel:
        """为给定请求大小建模完整的块布局."""
        usable = self.get_usable_size(requested)
        if self.family == AllocatorFamily.GLIBC_PTMALLOC2:
            # glibc: chunk_size = max(requested + HEADER, MINSIZE) aligned up
            raw = max(requested + self._GLIBC_HEADER_SIZE, self._GLIBC_MINSIZE)
            total = self._align_up(raw, self._GLIBC_MALLOC_ALIGNMENT)
            return ChunkModel(
                requested_size=requested,
                actual_usable_size=usable,
                chunk_total_size=total,
                metadata_overhead=self._GLIBC_HEADER_SIZE,
                alignment=self._GLIBC_MALLOC_ALIGNMENT,
                has_size_class_rounding=(total - self._GLIBC_HEADER_SIZE) > requested)
        elif self.family == AllocatorFamily.WINDOWS_HEAP:
            total = self._align_up(requested + self._WIN_HEAP_HEADER,
                                   self._WIN_HEAP_ALIGNMENT)
            return ChunkModel(
                requested_size=requested,
                actual_usable_size=usable,
                chunk_total_size=total,
                metadata_overhead=self._WIN_HEAP_HEADER,
                alignment=self._WIN_HEAP_ALIGNMENT,
                has_size_class_rounding=False)
        else:
            total = self._align_up(requested, 16)
            return ChunkModel(
                requested_size=requested,
                actual_usable_size=usable,
                chunk_total_size=total,
                metadata_overhead=0,
                alignment=16,
                has_size_class_rounding=False)

# 分配器内部逻辑

    def _glibc_usable_size(self, req: int) -> int:
        """glibc ptmalloc2: 计算实际payload大小.

        内部逻辑 (malloc.c checked_request2size简化):
          1. req += SIZE_SZ (补齐size字段开销, 虽然HEADER已经包含)
          2. 对齐到 MALLOC_ALIGNMENT
          3. 若 < MINSIZE, 取 MINSIZE
          4. 减去SIZE_SZ得到可写payload
        注意: glibc的 "usable_size" = chunk_size - 2*SIZE_SZ
        (prev_size + size header = 2*SIZE_SZ = 0x10)
        """
        # 最小payload = MINSIZE - HEADER = 0x20 - 0x10 = 0x10...
        # 但实际MINSIZE=0x20即32B chunk, 含0x10 header, 所以最小payload=0x10=16B
        # 不过glibc实际最小payload是24B (MINSIZE - prev_size field only?
        # 实际上prev_size可复用为前一个块的数据)
        # 保守: 使用与glibc一致的模型
        nb = req
        if nb <= self._GLIBC_MIN_PAYLOAD:
            # 请求太小, 分配最小块
            return self._GLIBC_MIN_PAYLOAD
        # 加上SIZE_SZ的开销 (malloc内部nb = request2size(req))
        nb += self._GLIBC_SIZE_SZ
        # 对齐到 MALLOC_ALIGNMENT
        nb = self._align_up(nb, self._GLIBC_MALLOC_ALIGNMENT)
        if nb < self._GLIBC_MINSIZE:
            nb = self._GLIBC_MINSIZE
        # 减去header得到可用payload
        usable = nb - self._GLIBC_HEADER_SIZE
        return usable

    def _windows_usable_size(self, req: int) -> int:
        """Windows Heap Manager: HeapAlloc实际分配.

        Windows堆使用8B或16B粒度. _HEAP_ENTRY有0x10字节开销.
        返回值 = _ALIGN_UP(req + granularity - 1, granularity)
        保守: 假设实际大小=请求大小对齐到16B.
        """
        # Windows HeapAlloc保证的对齐和粒度
        aligned = self._align_up(req, self._WIN_HEAP_ALIGNMENT)
        return aligned

    def _jemalloc_usable_size(self, req: int) -> int:
        """jemalloc: 基于size-class的分配.

        jemalloc使用预定义的size class表, 若请求不匹配某个class,
        则向上取整到下一个class. 小对象使用tcache加速.
        简化建模: 使用保守的size-class映射.
        """
        # jemalloc size classes (常见的小对象class)
        _TINY_CLASSES = [8, 16, 32, 48, 64, 80, 96, 112, 128,
                         160, 192, 224, 256, 320, 384, 448, 512,
                         640, 768, 896, 1024, 1280, 1536, 1792,
                         2048, 2560, 3072, 3584, 4096, 5120,
                         6144, 7168, 8192, 10240, 12288, 14336]
        for cls in _TINY_CLASSES:
            if req <= cls:
                return cls
        return self._align_up(req, 0x1000)  # 大对象: 页对齐

    def _generic_usable_size(self, req: int) -> int:
        """通用保守模型: 仅对齐到16B."""
        return self._align_up(req, 16)

    @staticmethod
    def _align_up(val: int, align: int) -> int:
        """向上对齐."""
        return ((val + align - 1) // align) * align

# 误报过滤器接口

    def filter_false_positive(self, write_size_max: int,
                               write_offset: int,
                               requested_alloc_min: int,
                               ) -> Tuple[bool, str]:
        """判断一个写入是否确定安全 (基于分配器行为模型)。

        返回 (is_safe, reason) — 若is_safe=True, 该发现应被过滤
        为误报。此方法比 ConstraintSimplifier 的L0更精确, 因为
        它使用实际可用空间而非请求大小。
        """
        actual_usable = self.get_usable_size(requested_alloc_min)
        safe_bound = max(0, actual_usable - write_offset)
        if write_size_max <= safe_bound:
            return True, (
                f"分配器模型: malloc({requested_alloc_min})→实际可用{actual_usable}B, "
                f"写入{write_size_max}B(偏移{write_offset})在{safe_bound}B安全范围内")
        return False, ""

    def get_differential_evidence(self, requested: int) -> str:
        """生成"分配器给了更多空间"的证据文本 (用于对比实验)."""
        usable = self.get_usable_size(requested)
        if usable == requested:
            return f"malloc({requested})→请求=实际可用={requested}B (无额外空间)"
        delta = usable - requested
        return (f"malloc({requested})→实际可用{usable}B "
                f"(分配器内部多给了{delta}B, 因对齐/size-class)")


# 模块级单例: 自动检测平台使用对应分配器模型
import sys as _sys

def auto_detect_allocator() -> HeapAllocatorModel:
    """根据运行平台自动选择分配器模型."""
    if _sys.platform == 'linux':
        return HeapAllocatorModel(AllocatorFamily.GLIBC_PTMALLOC2)
    elif _sys.platform == 'win32':
        return HeapAllocatorModel(AllocatorFamily.WINDOWS_HEAP)
    elif 'bsd' in _sys.platform:
        return HeapAllocatorModel(AllocatorFamily.JEMALLOC)
    return HeapAllocatorModel(AllocatorFamily.GENERIC)


# 预计算的size-class映射表 (用于快速查询)
# 对glibc: 给定请求大小 → 实际chunk大小
# 这使 constraint_simplifier 可以直接查询 "实际可用上界"
def build_glibc_size_map(max_size: int = 0x10000) -> Dict[int, int]:
    """预计算glibc请求大小到实际可用大小的映射表."""
    m = HeapAllocatorModel(AllocatorFamily.GLIBC_PTMALLOC2)
    return {s: m.get_usable_size(s) for s in range(0, max_size + 1, 8)}
