# coding: utf-8
# 创建: 2026-05-15  |  分配器可用大小模型——对齐 padding 语义
#
"""
分配器可用大小 (usable_size) 模型。

误报来源: 写入量略超请求大小但落在分配器对齐 padding 内, 不构成溢出。
例如 glibc 下 malloc(17) 实际 chunk 32 字节, usable = 24,
写入 20 字节完全合法。纯 size 比较会误报。

模型:
  glibc ptmalloc2 request2size + usable = chunk_size - SIZE_SZ (8)
  msvcrt (MinGW) 对齐 16, usable = align16(req+8) - 8 近似
  其他/未知: 保守返回请求大小本身 (不放大可用区间, 避免误删)

设计决策:
  - 仅放大"安全空间"到明确的对齐语义, 不做启发式宽松
  - mode 选择: "glibc" / "msvcrt" / "none", 默认 glibc
"""

from dataclasses import dataclass
from typing import Optional

_SZ_SZ = 8
_ALIGN_MASK = 15
_MINSIZE = 32


def glibc_usable(request: int) -> int:
    """glibc ptmalloc2: request2size + usable_size."""
    if request < 0:
        return 0
    if request == 0:
        return 0
    if request + _SZ_SZ + _ALIGN_MASK < _MINSIZE:
        chunk = _MINSIZE
    else:
        chunk = (request + _SZ_SZ + _ALIGN_MASK) & ~_ALIGN_MASK
    usable = chunk - _SZ_SZ
    return max(request, usable)


def msvcrt_usable(request: int) -> int:
    """msvcrt (MinGW PE): 16 字节对齐 header 近似."""
    if request < 0:
        return 0
    if request == 0:
        return 0
    chunk = (request + 8 + 15) & ~15
    usable = chunk - 8
    return max(request, usable)


def linear_usable(request: int) -> int:
    """保守模型: 无对齐语义, 可用 = 请求."""
    return max(0, request)


@dataclass
class AllocConstraint:
    """一次分配请求的可用空间约束."""
    requested: int
    usable: int
    padding: int
    mode: str


class UsableSizeModel:
    """分配器可用大小模型."""

    def __init__(self, mode: str = "glibc"):
        self.mode = mode
        self._stats = {"queries": 0}

    def model(self, requested: int) -> AllocConstraint:
        self._stats["queries"] += 1
        if self.mode == "glibc":
            usable = glibc_usable(requested)
        elif self.mode == "msvcrt":
            usable = msvcrt_usable(requested)
        else:
            usable = linear_usable(requested)
        return AllocConstraint(
            requested=requested, usable=usable,
            padding=usable - requested, mode=self.mode)

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = [
    "UsableSizeModel", "AllocConstraint",
    "glibc_usable", "msvcrt_usable", "linear_usable",
]
