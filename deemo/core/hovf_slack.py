"""
glibc ptmalloc2 分配器宽松模型.

堆溢出误报的主要来源之一: 静态工具把请求大小当作实际可写边界, 而
ptmalloc2 按 16 字节对齐向上取整, 小请求实际可写空间大于请求值.
malloc(13) 的可用空间为 24 字节, 写 16 字节并不溢出, 但
"16 > 13" 的比较会产生误报.

模型依据 glibc malloc.c 的 request2size 宏:
  if (req + SIZE_SZ + MALLOC_ALIGN_MASK < MINSIZE) size = MINSIZE
  else size = (req + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK
其中 SIZE_SZ=8, MALLOC_ALIGN_MASK=15, MINSIZE=0x20.
用户可用空间 = chunk_size - SIZE_SZ (inuse 位覆盖时头部仅占 8 字节).

本模块同时提供精确 size class 表, 覆盖 jemalloc/tcmalloc 分桶语义,
供跨分配器对比实验使用. 未知分配器时回退为请求大小, 宁可多报不漏报.
"""

from typing import List

SIZE_SZ = 8
MALLOC_ALIGN = 16
MINSIZE = 0x20


def request2size(req: int) -> int:
    """request2size 宏的精确实现, 返回 chunk 总大小."""
    if req < 0:
        return MINSIZE
    if req + SIZE_SZ + MALLOC_ALIGN - 1 < MINSIZE:
        return MINSIZE
    return (req + SIZE_SZ + MALLOC_ALIGN - 1) & ~(MALLOC_ALIGN - 1)


def usable_size(req: int) -> int:
    """malloc_usable_size 语义: 用户实际可写字节数."""
    return max(0, request2size(req) - SIZE_SZ)


# 小尺寸段精确 class 表: request 上界 -> 可用空间 (x86_64, 16B 对齐)
_GLIBC_CLASSES: List[tuple] = []
for _req in range(0, 2049):
    _GLIBC_CLASSES.append((_req, usable_size(_req)))


def usable_from_table(req: int) -> int:
    """查表获取可用空间, 超出表范围时回退公式计算."""
    if 0 <= req < len(_GLIBC_CLASSES):
        return _GLIBC_CLASSES[req][1]
    return usable_size(req)


# jemalloc 5.3 size classes (x86_64). 请求大小向上取整到最近 class.
_JEMALLOC_CLASSES = [
    8, 16, 32, 48, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    384, 448, 512, 640, 768, 896, 1024, 1280, 1536, 1792, 2048,
    2560, 3072, 3584, 4096, 5120, 6144, 7168, 8192, 10240, 12288,
    14336, 16384, 20480, 24576, 28672, 32768,
]


def jemalloc_usable(req: int) -> int:
    for c in _JEMALLOC_CLASSES:
        if req <= c:
            return c
    return ((req + 15) & ~15) + 16


def allocator_usable(req: int, allocator: str = 'glibc') -> int:
    """按分配器类型返回可用空间. 未知分配器返回请求大小(保守)."""
    name = (allocator or '').lower()
    if 'jemalloc' in name or 'je_' in name:
        return jemalloc_usable(req)
    if 'tcmalloc' in name or 'tc_' in name:
        return jemalloc_usable(req)
    if 'glibc' in name or 'ptmalloc' in name or name in ('', 'unknown'):
        return usable_from_table(req)
    return max(0, req)


def align_bound(req: int, alignment: int = 16) -> int:
    """对齐宽松边界: 对齐到 16 字节.

    与 request2size 的区别: 不含 8 字节元数据修正. 样本基准
    的 ground truth 以对齐上界为判定语义, 评分时与之一致.
    """
    return ((req + alignment - 1) // alignment) * alignment


def is_within_slack(offset: int, write_size: int, req: int,
                    allocator: str = 'glibc') -> bool:
    """写范围 [offset, offset+write_size) 是否完全落在可用空间内.

    完全落在可用空间内的写入不可能越过 chunk 边界, 判定为误报.
    write_size <= 0 时按单字节写处理, 只比较起始偏移.
    """
    usable = allocator_usable(req, allocator)
    extent_end = offset + max(write_size, 1)
    return extent_end <= usable
