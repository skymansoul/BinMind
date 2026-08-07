# 修改记录:
# 2025-08-12 10:48 - 贝叶斯字段边界聚合: 多条 trace 的字段访问证据加权合并
# 2025-08-12 15:55 - 冲突解决策略: 字段边界冲突时选择最高后验概率的划分

"""多 trace 结构体布局聚合恢复 - 从多次执行中合并 struct 字段证据

单次执行动态分析 (dynamic_struct_prober.py) 只能观察到该执行中
实际访问的字段--大量未访问字段的边界和类型无法确定

多次执行 (不同输入、不同代码路径) 暴露不同的字段子集
将这些子集合并可恢复更完整的结构体布局

方法:
  1. 每条 trace 独立产生字段访问证据: (offset, size, access_count, access_type)
  2. 贝叶斯聚合: 将多条 trace 的证据在字段边界上累积
     每个可能的字段划分得到后验概率
  3. 冲突解决: 若两 trace 在同偏移处产生冲突的大小, 选择后验概率更高者
  4. 字段置信度: 被更多 trace 访问的字段->更高置信度

与现有工作的关系:
- dynamic_struct_prober.py: 单 trace -> 本模块: 多 trace 贝叶斯聚合
- WYTIWYG: 精确栈变量恢复->本模块: 堆结构体
- 单次探测局限性在 WYTIWYG 第 7 节讨论--多 trace 是其推荐的方向
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


# 数据结构

@dataclass
class FieldAccess:
    """单次 trace 中的字段访问证据"""
    offset: int                # 结构体基址的偏移
    size: int                  # 访问大小 (1/2/4/8 字节)
    access_count: int = 1      # 此偏移的访问次数
    trace_id: int = 0          # 来自哪条 trace
    access_type: str = 'read'  # read | write | both


@dataclass
class StructField:
    """聚合后的推断结构体字段"""
    field_name: str            # 自动生成的名称 (field_0, field_4, ...)
    offset: int
    size: int
    confidence: float          # [0,1]
    # 聚合信息
    num_traces_observed: int
    total_accesses: int
    access_types: Set[str] = field(default_factory=set)


@dataclass
class StructLayout:
    """恢复的结构体布局"""
    struct_name: str
    total_size: int            # 估算的总大小
    fields: List[StructField]
    layout_confidence: float   # 整体置信度
    # 未解决区域
    unresolved_regions: List[Tuple[int, int]]  # (offset, size)


class MultiTraceStructRecoverer:
    """多 trace 结构体布局聚合恢复器

    用法:
    recoverer = MultiTraceStructRecoverer()
    layout = recoverer.recover(
        access_evidence=[
            [FieldAccess(0, 8, 5, 0), FieldAccess(8, 4, 2, 0)],
            [FieldAccess(0, 8, 3, 1), FieldAccess(16, 8, 1, 1)],
        ],
        struct_name='MyStruct',
    )
    """

    _PRIOR_SIZES = [1, 2, 4, 8]  # 字段大小的先验分布 (常见对齐)

    def recover(
        self,
        access_evidence: List[List[FieldAccess]],
        struct_name: str = '',
        max_struct_size: int = 4096,
    ) -> StructLayout:
        """从多条 trace 的访问证据中聚合恢复结构体布局

        access_evidence: [[trace_0_accesses], [trace_1_accesses], ...]

        返回 StructLayout
        """
        # 1. 合并所有 trace 的访问证据
        offset_evidence: Dict[int, Dict[str, Any]] = defaultdict(
            lambda: {
                'total_accesses': 0,
                'size_votes': defaultdict(int),  # size -> count
                'trace_ids': set(),
                'access_types': set(),
            }
        )

        for trace_id, trace_accesses in enumerate(access_evidence):
            for fa in trace_accesses:
                ev = offset_evidence[fa.offset]
                ev['total_accesses'] += fa.access_count
                ev['size_votes'][fa.size] += fa.access_count
                ev['trace_ids'].add(trace_id)
                ev['access_types'].add(fa.access_type)

        if not offset_evidence:
            return StructLayout(
                struct_name=struct_name, total_size=0,
                fields=[], layout_confidence=0.0,
                unresolved_regions=[],
            )

        # 2. 贝叶斯字段边界推断
        sorted_offsets = sorted(offset_evidence.keys())
        fields: List[StructField] = []
        unresolved: List[Tuple[int, int]] = []

        for off in sorted_offsets:
            ev = offset_evidence[off]
            # 选择后验概率最高的字段大小
            best_size = self._best_field_size(ev['size_votes'])
            confidence = self._field_confidence(
                ev['size_votes'], ev['total_accesses'],
                len(ev['trace_ids']), len(access_evidence),
            )

            if confidence > 0.30:
                fields.append(StructField(
                    field_name=f'field_{off:#x}',
                    offset=off,
                    size=best_size,
                    confidence=confidence,
                    num_traces_observed=len(ev['trace_ids']),
                    total_accesses=ev['total_accesses'],
                    access_types=ev['access_types'],
                ))
            else:
                # 低置信度->标记为未解决
                unresolved.append((off, best_size))

        # 3. 解决字段重叠冲突
        fields = self._resolve_overlaps(fields)

        # 4. 估算总大小
        if fields:
            last_field = max(fields, key=lambda f: f.offset + f.size)
            total_size = last_field.offset + last_field.size
        else:
            total_size = max(sorted_offsets) + 8 if sorted_offsets else 0

        # 整体置信度 = 字段置信度的平均
        overall_conf = (
            sum(f.confidence for f in fields) / len(fields)
            if fields else 0.0
        )

        return StructLayout(
            struct_name=struct_name,
            total_size=total_size,
            fields=sorted(fields, key=lambda f: f.offset),
            layout_confidence=round(overall_conf, 4),
            unresolved_regions=unresolved,
        )

    def _best_field_size(
        self, size_votes: Dict[int, int]
    ) -> int:
        """选择后验概率最高的字段大小

        使用简单贝叶斯: P(size | votes) ∝ P(votes | size) x P(size)
        P(votes | size) = size_votes[size] / total_votes
        P(size) = 1/|allowed_sizes| (均匀先验)
        """
        if not size_votes:
            return 8  # 默认

        total = sum(size_votes.values())
        best_size = 8
        best_score = -1.0

        for sz, votes in size_votes.items():
            # 后验 ∝ 证据力度 x 先验
            likelihood = votes / total
            prior = 1.0 / len(self._PRIOR_SIZES)
            score = likelihood * prior

            if score > best_score:
                best_score = score
                best_size = sz

        return best_size

    def _field_confidence(
        self,
        size_votes: Dict[int, int],
        total_accesses: int,
        num_traces: int,
        total_traces: int,
    ) -> float:
        """字段的置信度--基于访问密度和多 trace 一致性

        置信度 = (trace 覆盖率) x (大小投票集中度)
        trace 覆盖率 = 观测到此字段的 trace 数 / 总 trace 数
        大小投票集中度 = 最大投票数 / 总投票数 (1=一致, 分散=低)
        """
        if total_traces == 0 or total_accesses == 0:
            return 0.0

        trace_coverage = num_traces / total_traces
        total_votes = sum(size_votes.values())
        max_votes = max(size_votes.values()) if size_votes else 0
        size_consensus = max_votes / total_votes if total_votes > 0 else 0.0

        return trace_coverage * 0.6 + size_consensus * 0.4

    def _resolve_overlaps(
        self, fields: List[StructField]
    ) -> List[StructField]:
        """解决字段边界重叠--保留置信度更高的字段"""
        if len(fields) < 2:
            return fields

        resolved: List[StructField] = []
        fields_sorted = sorted(fields, key=lambda f: (f.offset, -f.confidence))

        for f in fields_sorted:
            # 检查是否与已解析字段重叠
            overlaps = False
            for existing in resolved:
                if (
                    f.offset < existing.offset + existing.size
                    and f.offset + f.size > existing.offset
                ):
                    # 重叠->保留置信度高者
                    overlaps = True
                    if f.confidence > existing.confidence:
                        resolved.remove(existing)
                        resolved.append(f)
                    break

            if not overlaps:
                resolved.append(f)

        return resolved
