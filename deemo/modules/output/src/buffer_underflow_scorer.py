"""
缓冲区下溢利用性评分 — 溢出方向×相邻区域×元数据破坏潜力。

问题定义:
  缓冲区下溢 (向低地址方向越界写) 与上溢有不同的利用路径:
    - 堆下溢 → 写前一个 chunk 的元数据 (prev_size/size) → chunk overlapping
    - 栈下溢 → 写调用者的局部变量 → 可能覆盖函数指针/返回地址
    - 全局下溢 → 写相邻全局变量 → 数据破坏

  下溢的特殊性:
    - 可以修改前一个 chunk 的 size → 合并伪造 → overlapping
    - 可以修改 prev_size → 后向合并控制
    - 可以破坏 fastbin/tcache 链表指针 (如果恰好在链表上)

  本模块是第一个缓冲区下溢利用性量化模型。

参考:
  CWE-124: Buffer Underwrite ('Buffer Underflow')
  CWE-786: Access of Memory Location Before Start of Buffer
  glibc向后合并: unlink_chunk → prev_size 检查
  无现有量化工具.

修改记录:
  2026-08-02 14:22 - 初始版本，位置×元数据×大小的三维矩阵
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class UnderflowLocation(Enum):
    HEAP_METADATA = "heap_metadata"      # 写前一个chunk的size/prev_size
    HEAP_USERDATA = "heap_userdata"      # 写前一个chunk的用户数据
    STACK_FRAME = "stack_frame"          # 写调用者的栈帧
    STACK_LOCALS = "stack_locals"        # 写同栈帧的其他局部变量
    GLOBAL_DATA = "global_data"          # 写相邻全局/BSS变量
    HEAP_FREELIST = "heap_freelist"      # 写tcache/fastbin链表 (最危险)
    UNKNOWN = "unknown"


# 位置→基准利用性
_LOCATION_BASE: Dict[UnderflowLocation, float] = {
    UnderflowLocation.HEAP_FREELIST:   9.5,  # 直接写freelist指针→任意分配
    UnderflowLocation.HEAP_METADATA:   8.0,  # chunk overlapping原语
    UnderflowLocation.STACK_FRAME:     7.5,  # saved rbp/返回地址
    UnderflowLocation.HEAP_USERDATA:   5.0,  # 数据破坏→可能转化为信息泄露或控制流
    UnderflowLocation.STACK_LOCALS:    4.5,
    UnderflowLocation.GLOBAL_DATA:     3.5,
    UnderflowLocation.UNKNOWN:         2.0,
}


@dataclass
class UnderflowScore:
    """缓冲区下溢利用性评分。"""
    location: UnderflowLocation
    underflow_bytes: int           # 下溢字节数
    adjacent_sensitivity: str      # 相邻数据的敏感度标签
    is_guarded: bool               # 是否临近 guard page
    exploitability: float          # 0-10
    primitives: List[str] = field(default_factory=list)
    technique: str = ''


def _classify_location(
    is_heap: bool = False,
    is_stack: bool = False,
    is_global: bool = False,
    adjacent_context: str = '',
) -> UnderflowLocation:
    ctx = adjacent_context.lower()

    if is_heap:
        if any(kw in ctx for kw in ('freelist', 'tcache', 'fastbin', 'fd', 'bk', 'next')):
            return UnderflowLocation.HEAP_FREELIST
        if any(kw in ctx for kw in ('size', 'prev_size', 'metadata', 'header')):
            return UnderflowLocation.HEAP_METADATA
        return UnderflowLocation.HEAP_USERDATA

    if is_stack:
        if any(kw in ctx for kw in ('rbp', 'frame', 'saved', 'return', 'ret_addr')):
            return UnderflowLocation.STACK_FRAME
        return UnderflowLocation.STACK_LOCALS

    if is_global:
        return UnderflowLocation.GLOBAL_DATA

    return UnderflowLocation.UNKNOWN


def score_buffer_underflow(
    is_heap: bool = False,
    is_stack: bool = False,
    is_global: bool = False,
    adjacent_context: str = '',
    underflow_bytes: int = 4,
    is_guarded: bool = False,
    has_canary: bool = False,
) -> UnderflowScore:
    """
    评估缓冲区下溢的利用性。

    underflow_bytes: 下溢字节数。更多字节→更大控制面。
    is_guarded: 是否临近 guard page → 溢出即 crash。
    has_canary: 栈上是否有 canary → 阻止栈帧破坏。
    """
    location = _classify_location(is_heap, is_stack, is_global, adjacent_context)
    base = _LOCATION_BASE.get(location, 2.0)

    # 字节数修正
    if underflow_bytes <= 1:
        byte_bonus = -1.5  # 单字节下溢 — 控制有限
    elif underflow_bytes <= 4:
        byte_bonus = 0.0
    elif underflow_bytes <= 16:
        byte_bonus = 1.0   # 足够覆盖完整的元数据字段
    else:
        byte_bonus = 2.0   # 大量溢出 — 完全控制

    # guard page 惩罚
    guard_penalty = 8.0 if is_guarded else 0.0

    # 栈 canary 惩罚
    canary_penalty = 3.0 if (has_canary and location in (
        UnderflowLocation.STACK_FRAME, UnderflowLocation.STACK_LOCALS)) else 0.0

    exploitability = round(max(0.0, min(10.0,
        base + byte_bonus - guard_penalty - canary_penalty)), 1)

    # 利用原语
    prims = []
    if location == UnderflowLocation.HEAP_FREELIST and exploitability >= 4.0:
        prims.append('freelist_corruption')
        prims.append('arbitrary_alloc')
    if location == UnderflowLocation.HEAP_METADATA and exploitability >= 5.0:
        prims.append('chunk_overlapping')
        prims.append('backward_consolidation_control')
    if location in (UnderflowLocation.STACK_FRAME, UnderflowLocation.STACK_LOCALS) and exploitability >= 5.0:
        prims.append('stack_variable_corruption')
        if not has_canary and location == UnderflowLocation.STACK_FRAME:
            prims.append('return_address_overwrite')

    # 利用技术
    if location == UnderflowLocation.HEAP_FREELIST:
        tech = ('freelist 破坏 → 伪造 fd/bk 指针 → '
                '任意地址分配 → 任意写入原语')
    elif location == UnderflowLocation.HEAP_METADATA:
        tech = ('chunk overlapping → 修改 prev_size 触发向后合并 → '
                'overlapping chunks → tcache poisoning')
    elif location == UnderflowLocation.STACK_FRAME and not has_canary:
        tech = ('栈帧破坏 → 覆写 saved RBP → '
                'leave; ret → 栈迁移到攻击者控制区域')
    else:
        tech = '数据破坏为主。利用需要额外的原语或信息泄露'

    return UnderflowScore(
        location=location,
        underflow_bytes=underflow_bytes,
        adjacent_sensitivity=adjacent_context or 'unknown',
        is_guarded=is_guarded,
        exploitability=exploitability,
        primitives=prims,
        technique=tech,
    )
