"""
分配器感知边界模型 — 块大小对齐松弛与有效写边界。

决策逻辑:
  堆溢出判定的核心比较对象不是"请求的分配大小", 而是"分配器实际
  提供的可用空间"。glibc ptmalloc2 的 request2size 会对请求大小
  做 16 字节对齐并附加 8 字节元数据, 导致请求 13B 实际可用 24B。
  忽略该松弛会把"对齐填充内的合法写入"误报为溢出。本模块把
  requested_size 映射为 usable_size, 供判定引擎作为安全阈值。

  同时对 calloc/realloc 的语义差异建模: calloc 的乘法溢出回绕
  是真实漏洞点, 不套用对齐松弛。

不处理: 自定义分配器 (kmalloc/slab), 默认保守使用请求大小。
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Optional

MIN_CHUNK_64 = 0x20    # x86_64 最小 chunk 32B
META_64 = 8            # prev_size 字段
ALIGN_64 = 16


class AllocKind(Enum):
    MALLOC = 'malloc'
    CALLOC = 'calloc'
    REALLOC = 'realloc'


@dataclass(frozen=True)
class AllocBound:
    """分配点的有效边界信息."""
    requested: int          # 请求大小 (可精确求值时)
    usable: int             # 实际可用空间 (ptmalloc2 模型)
    alignment_relaxed: bool # 是否应用了对齐松弛
    kind: AllocKind
    symbolic: bool = False  # 请求大小为符号表达式, 无法精确求值


def request2usable(requested: int, kind: AllocKind = AllocKind.MALLOC) -> int:
    """glibc ptmalloc2 request2size 模型的可用空间计算.

    chunk_size = max(0x20, align16(requested + 8))
    usable = chunk_size - 8
    calloc/realloc 同样走该对齐, 但调用方需自行处理乘法回绕。
    """
    if requested <= 0:
        return MIN_CHUNK_64 - META_64
    chunk_size = max(MIN_CHUNK_64,
                     ((requested + META_64 + ALIGN_64 - 1) // ALIGN_64) * ALIGN_64)
    return chunk_size - META_64


def alloc_bound(requested: int,
                kind: AllocKind = AllocKind.MALLOC) -> AllocBound:
    """构造分配点边界. requested <= 0 视为符号分配."""
    if requested <= 0:
        return AllocBound(0, 0, False, kind, symbolic=True)
    usable = request2usable(requested, kind)
    return AllocBound(requested, usable, usable > requested, kind)


def slack_bytes(requested: int,
                kind: AllocKind = AllocKind.MALLOC) -> int:
    """对齐松弛字节数: usable - requested."""
    if requested <= 0:
        return 0
    return request2usable(requested, kind) - requested


def write_end_exceeds(offset: int, write_size: int, bound: AllocBound) -> bool:
    """判定写入终点是否超过有效边界.

    offset 为相对基址的起始偏移, write_size 为写入字节数。
    写入终点 = offset + write_size, 与 usable 比较。
    """
    if bound.symbolic:
        return True  # 符号分配: 保守视为可能越界
    return offset + max(write_size, 1) > bound.usable


def offset_within_bound(offset: int, bound: AllocBound) -> bool:
    """offset 是否落在有效边界内 (单次定长写入, 无写大小信息时)."""
    if bound.symbolic:
        return False
    return 0 <= offset < bound.usable
