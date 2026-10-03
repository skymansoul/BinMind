"""
多分配器统一模型 — ptmalloc2/jemalloc/tcmalloc 的 request2size 转换.

提供统一接口 usable_size(requested_size) → int.
与 heap_alloc_model.py 的差异: 本模块为轻量纯函数版本, 不依赖 StridedInterval.
用于 Tier 0 快速过滤 (仅在纯常量分配/写入时触发).
"""


from enum import Enum, auto


class AllocKind(Enum):
    PTMALLOC2 = auto()
    JEMALLOC = auto()
    TCMALLOC = auto()


# ptmalloc2
def ptmalloc2_usable_size(requested: int) -> int:
    """glibc ptmalloc2 request2size 保守近似.

    公式: chunk_size = max(MINSIZE, align_up(req + SIZE_SZ, MALLOC_ALIGNMENT))
          usable = chunk_size - 2 * SIZE_SZ
    其中 SIZE_SZ=8 (64位), MALLOC_ALIGNMENT=16, MINSIZE=32.
    """
    if requested <= 0:
        requested = 1
    SIZE_SZ = 8
    MALLOC_ALIGNMENT = 16
    MINSIZE = 32
    # align up
    req_plus_overhead = requested + SIZE_SZ
    chunk_size = (req_plus_overhead + MALLOC_ALIGNMENT - 1) & ~(MALLOC_ALIGNMENT - 1)
    if chunk_size < MINSIZE:
        chunk_size = MINSIZE
    usable = chunk_size - 2 * SIZE_SZ
    return usable


# jemalloc (size class 表, 36类)
_JEMALLOC_SIZE_CLASSES = [
    8, 16, 32, 48, 64, 80, 96, 112, 128, 160,
    192, 224, 256, 320, 384, 448, 512, 640, 768, 896,
    1024, 1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096,
    5120, 6144, 7168, 8192, 10240, 12288, 14336,
]


def jemalloc_usable_size(requested: int) -> int:
    """jemalloc size class 查找."""
    if requested <= 0:
        return _JEMALLOC_SIZE_CLASSES[0]
    for sc in _JEMALLOC_SIZE_CLASSES:
        if sc >= requested:
            return sc
    # 超出最大size class → page对齐
    return (requested + 4095) & ~4095


# tcmalloc (简化: 8字节对齐, 最小8B)
def tcmalloc_usable_size(requested: int) -> int:
    """tcmalloc: 8字节对齐, 最小8字节."""
    if requested <= 0:
        return 8
    return (requested + 7) & ~7


# 统一接口

class AllocatorModel:
    """多分配器门面.

    使用: model = AllocatorModel(AllocKind.PTMALLOC2)
          usable = model.usable(256)  # → 248 (64位glibc ptmalloc2)
    """

    def __init__(self, kind: AllocKind = AllocKind.PTMALLOC2):
        self._kind = kind
        if kind == AllocKind.PTMALLOC2:
            self._fn = ptmalloc2_usable_size
        elif kind == AllocKind.JEMALLOC:
            self._fn = jemalloc_usable_size
        elif kind == AllocKind.TCMALLOC:
            self._fn = tcmalloc_usable_size
        else:
            self._fn = ptmalloc2_usable_size

    def usable(self, requested: int) -> int:
        return self._fn(requested)

    def is_safe_const(self, alloc_n: int, write_n: int) -> bool:
        """常量判定: 分配 alloc_n, 写入 write_n, 是否安全."""
        return write_n <= self.usable(alloc_n)

    def adjust_threshold(self, alloc_n: int) -> int:
        """返回在此分配下, 写入最大安全大小."""
        return self.usable(alloc_n)
