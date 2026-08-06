"""
Off-by-One 漏洞精度评分 — 边界类型×相邻数据敏感度×页对齐放大。

问题定义:
  Off-by-one 不是单一漏洞类型 — 根据溢出的字节值、相邻数据布局和
  内存区域，利用难度跨越 0 (不可利用) 到 10 (确定可利用)。

  关键区分:
    - NULL byte off-by-one → 可修改 next chunk 的 PREV_INUSE 位 (堆利用)
    - 可控字节 off-by-one → 可覆写相邻变量的 LSB → 指针劫持
    - 栈 off-by-one → 可覆写 saved rbp 的 LSB → 栈迁移
    - 页边界 off-by-one → 可能写入未映射页 → crash-only (不可利用)

  本模块是第一个 off-by-one 精度评分模型。

参考:
  Poisoned NUL byte (glibc): chunk overlapping via PREV_INUSE clear
  CTF off-by-one writeups (2024): LSB overwrite → stack pivot
  无现有评分工具.

修改记录:
  2026-08-02 09:15 - 初始版本，边界类型×相邻敏感度的二维矩阵
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class BoundaryType(Enum):
    NULL_BYTE = "null_byte"          # 0x00 — 经典堆利用
    CONTROLLED_BYTE = "controlled"   # 攻击者可控的任意字节
    FIXED_NONZERO = "fixed_nonzero"  # 固定非零值
    UNKNOWN = "unknown"


class AdjacentType(Enum):
    CHUNK_METADATA = "chunk_metadata"   # 相邻堆块的元数据 (size/prev_size)
    FUNCTION_PTR = "function_ptr"       # 函数指针/vtable 指针
    DATA_PTR = "data_ptr"               # 数据指针
    SAVED_RBP = "saved_rbp"             # 栈上的 saved frame pointer
    INTEGER = "integer"                 # 整数/计数器
    PADDING = "padding"                 # 对齐填充 (无害)
    UNKNOWN = "unknown"


# 边界类型 × 相邻类型 → 利用难度分 (0-10)
_EXPLOIT_MATRIX: Dict[BoundaryType, Dict[AdjacentType, float]] = {
    BoundaryType.NULL_BYTE: {
        AdjacentType.CHUNK_METADATA: 9.0,  # PREV_INUSE 清零 → chunk overlapping
        AdjacentType.FUNCTION_PTR:   6.5,  # 函数指针 LSB 清零 → 重定向
        AdjacentType.DATA_PTR:       5.0,  # 数据指针 LSB → 部分控制
        AdjacentType.SAVED_RBP:      7.0,  # saved rbp LSB → 栈迁移原语
        AdjacentType.INTEGER:        2.0,
        AdjacentType.PADDING:        0.5,
    },
    BoundaryType.CONTROLLED_BYTE: {
        AdjacentType.CHUNK_METADATA: 8.5,
        AdjacentType.FUNCTION_PTR:   9.0,  # 可控字节覆写函数指针 → 最高危
        AdjacentType.DATA_PTR:       7.5,
        AdjacentType.SAVED_RBP:      8.5,
        AdjacentType.INTEGER:        4.0,
    },
    BoundaryType.FIXED_NONZERO: {
        AdjacentType.CHUNK_METADATA: 5.0,
        AdjacentType.FUNCTION_PTR:   3.0,
        AdjacentType.DATA_PTR:       2.5,
        AdjacentType.SAVED_RBP:      3.5,
        AdjacentType.INTEGER:        2.0,
    },
}
_DEFAULT_EXPLOIT = {a: 1.0 for a in AdjacentType}


@dataclass
class OffByOneScore:
    """Off-by-one 漏洞精度评分。"""
    boundary_type: BoundaryType
    adjacent_type: AdjacentType
    byte_value: int                # 溢出的字节值 (0-255)
    is_page_aligned: bool          # 是否在页边界 (4096 对齐)
    exploitability: float          # 0-10
    primitives: List[str] = field(default_factory=list)
    technique: str = ''


def _guess_adjacent(
    context: str,
    is_heap: bool = False,
    is_stack: bool = False,
) -> AdjacentType:
    ctx = context.lower()
    if is_heap and any(kw in ctx for kw in ('chunk', 'malloc', 'free',
           'size', 'prev_size', 'metadata')):
        return AdjacentType.CHUNK_METADATA
    if any(kw in ctx for kw in ('function', 'vtable', 'callback',
           'handler', 'func_ptr')):
        return AdjacentType.FUNCTION_PTR
    if is_stack and any(kw in ctx for kw in ('rbp', 'frame', 'saved',
           'return')):
        return AdjacentType.SAVED_RBP
    if any(kw in ctx for kw in ('pointer', 'ptr', 'address', 'buf',
           'data_ptr', 'ref')):
        return AdjacentType.DATA_PTR
    if any(kw in ctx for kw in ('int', 'count', 'size', 'len',
           'index', 'flag')):
        return AdjacentType.INTEGER
    if any(kw in ctx for kw in ('pad', 'align', 'reserved',
           'unused', 'padding')):
        return AdjacentType.PADDING
    return AdjacentType.UNKNOWN


def score_off_by_one(
    byte_value: int = 0,
    context: str = '',
    is_heap: bool = False,
    is_stack: bool = False,
    buffer_address: int = 0,
) -> OffByOneScore:
    """
    评估 off-by-one 漏洞的利用精度。

    byte_value: 溢出的字节值 (0=NULL, 1-255=可控或固定)。
    buffer_address: 缓冲区地址，用于页边界检测。
    """
    # 边界类型分类
    if byte_value == 0:
        btype = BoundaryType.NULL_BYTE
    elif byte_value > 0:
        btype = BoundaryType.CONTROLLED_BYTE
    else:
        btype = BoundaryType.UNKNOWN

    adjacent = _guess_adjacent(context, is_heap, is_stack)
    page_aligned = (buffer_address & 0xFFF) == 0 if buffer_address else False

    # 从矩阵取基准分
    matrix_row = _EXPLOIT_MATRIX.get(btype, _DEFAULT_EXPLOIT)
    base = matrix_row.get(adjacent, 1.0)

    # 页边界修正
    if page_aligned:
        base -= 5.0  # 写入 guard page → crash-only
        base = max(0.0, base)

    # NULL byte + 堆元数据 → 额外提升 (经典 poison null byte)
    if btype == BoundaryType.NULL_BYTE and adjacent == AdjacentType.CHUNK_METADATA:
        base = min(base + 0.5, 10.0)

    exploitability = round(min(10.0, max(0.0, base)), 1)

    # 可用原语
    prims = []
    if btype == BoundaryType.NULL_BYTE and adjacent == AdjacentType.CHUNK_METADATA:
        prims.append('chunk_overlapping')
        prims.append('prev_inuse_clear')
    if adjacent in (AdjacentType.FUNCTION_PTR, AdjacentType.SAVED_RBP) and exploitability >= 6.0:
        prims.append('control_flow_hijack')
    if adjacent == AdjacentType.DATA_PTR and exploitability >= 5.0:
        prims.append('pointer_corruption')

    # 利用技术推荐
    if prims and 'chunk_overlapping' in prims:
        tech = 'Poison NUL byte → chunk overlapping → tcache poisoning / fastbin attack'
    elif prims and 'control_flow_hijack' in prims:
        tech = '覆写函数指针/saved RBP → ROP chain / stack pivot'
    elif exploitability <= 1.0:
        tech = '不可利用 — 溢出目标为填充/页边界'
    else:
        tech = '部分利用 — 需要额外原语 (信息泄露+堆布局)'

    return OffByOneScore(
        boundary_type=btype,
        adjacent_type=adjacent,
        byte_value=byte_value,
        is_page_aligned=page_aligned,
        exploitability=exploitability,
        primitives=prims,
        technique=tech,
    )
