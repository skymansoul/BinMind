# coding: utf-8
"""
Buffer Underflow 检测 — CWE-124 (Buffer Underwrite), 对称于 heap overflow.
L1: 负偏移访问检测 L2: 指针算术溯源 L3: 前邻 chunk 影响分析.
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple


class UnderflowRisk(Enum):
    SAFE = auto()          # 无负偏移
    LOW = auto()           # 负偏移但 ≤ metadata 大小 (在 chunk header 内)
    MEDIUM = auto()        # 命中前邻 chunk 的用户数据
    HIGH = auto()          # 前邻 chunk metadata 损坏 → 可能堆利用
    CRITICAL = auto()      # 可控负偏移 → 任意负向写


@dataclass
class UnderflowAnalysis:
    """单次 buffer underflow 分析结果."""
    base_addr: int            # 缓冲区基址
    base_size: int            # 缓冲区大小
    access_offset: int        # 访问偏移 (负值)
    effective_addr: int       # base + offset
    write_size: int           # 写入大小
    risk: UnderflowRisk
    hits_prev_metadata: bool  # 是否命中前邻 chunk 的元数据
    prev_chunk_size: int      # 前邻 chunk 的大小 (若已知)
    confidence: float
    description: str


def detect_buffer_underflow(
    base_addr: int, base_size: int,
    access_offset: int, write_size: int = 8,
    metadata_size: int = 16,
    prev_chunk_size: Optional[int] = None,
) -> UnderflowAnalysis:
    """L1-L2: 检测 buffer underflow — 负偏移访问.

    Args:
      base_addr: 缓冲区基址
      base_size: malloc(N) 中的 N
      access_offset: 实际访问偏移 (负值表示向前)
      write_size: 写入大小 (字节)
      metadata_size: chunk 元数据大小 (默认 16 = prev_size+size)
      prev_chunk_size: 前邻 chunk 的大小 (若已知)
    """
    if access_offset >= 0:
        return UnderflowAnalysis(
            base_addr=base_addr, base_size=base_size,
            access_offset=access_offset,
            effective_addr=base_addr + access_offset,
            write_size=write_size,
            risk=UnderflowRisk.SAFE,
            hits_prev_metadata=False,
            prev_chunk_size=prev_chunk_size or 0,
            confidence=0.0,
            description='access_offset >= 0, 非 buffer underflow')

    abs_offset = abs(access_offset)

    # 负偏移 ≤ metadata_size: 仅影响当前 chunk 的 header
    if abs_offset <= metadata_size:
        return UnderflowAnalysis(
            base_addr=base_addr, base_size=base_size,
            access_offset=access_offset,
            effective_addr=base_addr + access_offset,
            write_size=write_size,
            risk=UnderflowRisk.LOW,
            hits_prev_metadata=True,
            prev_chunk_size=prev_chunk_size or 0,
            confidence=0.40,
            description=f'负偏移 {abs_offset}B ≤ metadata({metadata_size}B) → 影响当前 chunk header')

    # 负偏移 > metadata_size: 影响前邻 chunk
    into_prev = abs_offset - metadata_size  # 进入前邻 chunk 的深度

    if prev_chunk_size and prev_chunk_size > 0:
        prev_usable = prev_chunk_size - metadata_size

        if into_prev <= metadata_size:
            # 命中前邻 chunk 的 metadata
            return UnderflowAnalysis(
                base_addr=base_addr, base_size=base_size,
                access_offset=access_offset,
                effective_addr=base_addr + access_offset,
                write_size=write_size,
                risk=UnderflowRisk.HIGH,
                hits_prev_metadata=True,
                prev_chunk_size=prev_chunk_size,
                confidence=0.85,
                description=(
                    f'负偏移 {abs_offset}B → 进入前邻 chunk ({prev_chunk_size}B) '
                    f'metadata 区 {into_prev}B → 可损坏 prev_size/size → 堆利用'))
        elif into_prev <= prev_usable:
            return UnderflowAnalysis(
                base_addr=base_addr, base_size=base_size,
                access_offset=access_offset,
                effective_addr=base_addr + access_offset,
                write_size=write_size,
                risk=UnderflowRisk.MEDIUM,
                hits_prev_metadata=False,
                prev_chunk_size=prev_chunk_size,
                confidence=0.65,
                description=f'负偏移 {abs_offset}B → 命中前邻 chunk 用户数据 {into_prev}B')
        else:
            return UnderflowAnalysis(
                base_addr=base_addr, base_size=base_size,
                access_offset=access_offset,
                effective_addr=base_addr + access_offset,
                write_size=write_size,
                risk=UnderflowRisk.CRITICAL,
                hits_prev_metadata=True,
                prev_chunk_size=prev_chunk_size,
                confidence=0.90,
                description=f'负偏移 {abs_offset}B → 完全穿越前邻 chunk → 可损坏更早的堆结构')

    # 无前邻信息 → 保守假设
    return UnderflowAnalysis(
        base_addr=base_addr, base_size=base_size,
        access_offset=access_offset,
        effective_addr=base_addr + access_offset,
        write_size=write_size,
        risk=UnderflowRisk.MEDIUM if into_prev <= 64 else UnderflowRisk.HIGH,
        hits_prev_metadata=(into_prev <= metadata_size),
        prev_chunk_size=prev_chunk_size or 0,
        confidence=0.55,
        description=f'负偏移 {abs_offset}B → 无前邻信息, 保守估计进入 {into_prev}B')


# L2: 指针算术溯源

@dataclass
class PointerArithTrace:
    """指针算术溯源结果."""
    base_ptr: str
    operations: List[Tuple[str, int]]  # [(op, value), ...]  e.g. [('sub', 16)]
    final_offset: int
    underflow_analysis: UnderflowAnalysis


def trace_pointer_arithmetic(
    base_ptr: str, operations: List[Tuple[str, int]],
    base_size: int, metadata_size: int = 16,
    prev_chunk_size: Optional[int] = None,
) -> PointerArithTrace:
    """L2: 追踪指针算术操作, 识别负偏移.

    operations: [('add', N), ('sub', M), ('mul', K), ...]
    计算最终偏移 = Σ(add_values) - Σ(sub_values) × products
    """
    offset = 0
    for op, val in operations:
        if op == 'add':
            offset += val
        elif op == 'sub':
            offset -= val
        elif op == 'mul':
            offset *= val

    analysis = detect_buffer_underflow(
        0, base_size, offset, 8, metadata_size, prev_chunk_size)

    return PointerArithTrace(
        base_ptr=base_ptr, operations=operations,
        final_offset=offset, underflow_analysis=analysis)


# L3: 前邻 chunk 影响分析

class PrevChunkAnalyzer:
    """L3: 前邻 chunk 影响分析 — 评估负偏移写入对堆完整性的影响.

    前邻 chunk 布局:
      [+0]  prev_size  (8B)
      [+8]  size       (8B, 含 flags: PREV_INUSE|IS_MMAPPED|NON_MAIN_ARENA)
      [+16] user_data  (分配大小 - 16)

    负偏移写入可导致:
      1. 损坏 prev_size   → free 时错误合并
      2. 损坏 size/flags  → PREV_INUSE 翻转 → 向后合并攻击
      3. 损坏 user_data   → 信息泄露 / 数据损坏
    """

    # 前邻 chunk 中被覆写的字段及其影响
    _FIELD_IMPACTS = {
        'prev_size': {
            'risk': UnderflowRisk.HIGH,
            'exploit': 'prev_size 覆写 → free 合并时错误计算前邻 chunk 位置',
            'technique': 'House of Force / backward consolidation',
        },
        'size_flags': {
            'risk': UnderflowRisk.CRITICAL,
            'exploit': 'PREV_INUSE 翻转 + 前邻伪造 → 释放时合并到攻击者控制的 chunk',
            'technique': 'House of Einherjar (backward variant)',
        },
        'user_data': {
            'risk': UnderflowRisk.MEDIUM,
            'exploit': '损坏前邻 chunk 的用户数据 → 信息泄露或逻辑错误',
            'technique': 'Data-only attack',
        },
    }

    def analyze_prev_chunk_impact(
        self, analysis: UnderflowAnalysis,
    ) -> Dict:
        """分析负偏移写入对前邻 chunk 的影响."""
        abs_off = abs(analysis.access_offset)
        metadata_size = 16

        if abs_off <= 8:
            field = 'prev_size'
        elif abs_off <= 16:
            field = 'size_flags'
        else:
            field = 'user_data'

        impact = self._FIELD_IMPACTS[field]
        return {
            'field': field,
            'risk': impact['risk'].name,
            'exploit_description': impact['exploit'],
            'technique': impact['technique'],
            'write_size': analysis.write_size,
            'offset_into_field': abs_off - (0 if field == 'prev_size' else 8 if field == 'size_flags' else 16),
            'confidence': analysis.confidence,
        }


def batch_detect_underflow(
    candidates: List[Dict],
    metadata_size: int = 16,
) -> Tuple[List[Dict], Dict]:
    """批量 buffer underflow 检测."""
    results = []
    stats = {'total': len(candidates), 'safe': 0, 'low': 0, 'medium': 0,
             'high': 0, 'critical': 0}

    analyzer = PrevChunkAnalyzer()

    for c in candidates:
        base_size = c.get('alloc_size', c.get('base_size', 0))
        access_offset = c.get('offset', c.get('access_offset', 0))
        write_size = c.get('write_size', 8)
        prev_sz = c.get('prev_chunk_size')

        analysis = detect_buffer_underflow(
            0, base_size, access_offset, write_size,
            metadata_size, prev_sz)

        impact = analyzer.analyze_prev_chunk_impact(analysis)

        stats[analysis.risk.name.lower()] = stats.get(
            analysis.risk.name.lower(), 0) + 1

        results.append({
            'vuln_type': 'buffer_underflow',
            'cwe': 'CWE-124',
            'risk': analysis.risk.name,
            'confidence': analysis.confidence,
            'is_dangerous': analysis.risk in (
                UnderflowRisk.HIGH, UnderflowRisk.CRITICAL),
            'description': analysis.description,
            'prev_impact': impact,
        })

    stats['dangerous'] = sum(
        1 for r in results if r['is_dangerous'])
    return results, stats
