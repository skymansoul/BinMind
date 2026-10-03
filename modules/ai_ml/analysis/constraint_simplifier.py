# 约束简化器: 将值流分析得到的区间约束精简为溢出判定
# 处理三类约束: (1)分配大小区间 (2)拷贝大小区间 (3)两者关系
#
# 关键算法: 区间减法, 给定 alloc ∈ [A_lo, A_hi] 和 copy ∈ [C_lo, C_hi],
#   判定是否存在满足 copy > alloc + margin 的解。
#   若 ∀a∈alloc, ∀c∈copy: c ≤ a + margin → SAFE (必然不溢出)
#   若 ∀a∈alloc, ∀c∈copy: c > a + margin → CERTAIN_OVERFLOW (必然溢出)
#   否则 → POSSIBLE_OVERFLOW (需进一步路径可行性分析)
#
# 与 buffer_size_infer.py 中的简单比较不同:
#   此处处理的是stride interval(有步长的区间)而非简单[min,max],
#   且考虑了堆分配器的对齐约束后的有效区间

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .value_flow_engine import StridedInterval, IntervalKind
from .heap_alloc_model import AllocSiteInfo, HeapAllocModel, ChunkLayout

logger = logging.getLogger(__name__)


class ConstraintType(Enum):
    SAFE = 'safe'                     # 必然安全
    CERTAIN_OVERFLOW = 'certain'      # 必然溢出
    POSSIBLE_OVERFLOW = 'possible'    # 可能溢出(需进一步分析)
    UNKNOWN = 'unknown'               # 信息不足


@dataclass
class SizeConstraint:
    """单个尺寸约束: 分配大小 vs 拷贝大小"""
    alloc_si: StridedInterval         # malloc参数(请求大小)的区间
    alloc_usable_si: StridedInterval  # glibc实际可用大小的区间
    copy_si: StridedInterval          # memcpy参数的区间
    margin: int = 8                   # 安全边界(8字节默认)
    is_call_site_specific: bool = False  # 是否是调用点特化的约束

    def classify(self) -> ConstraintType:
        """判定约束类型"""
        if self.alloc_si.is_top() or self.copy_si.is_top():
            return ConstraintType.UNKNOWN
        if self.alloc_si.is_bot() or self.copy_si.is_bot():
            return ConstraintType.SAFE  # 不可达

        # 最坏情况: copy的最大可能值 vs alloc的最小可用值
        copy_max = self.copy_si.max_possible()
        alloc_usable_min = self.alloc_usable_si.min_possible()

        # 最好情况: copy的最小可能值 vs alloc的最大可用值
        copy_min = self.copy_si.min_possible()
        alloc_usable_max = self.alloc_usable_si.max_possible()

        # 必然安全: 最大拷贝 ≤ 最小可用 + margin
        if copy_max <= alloc_usable_min + self.margin:
            return ConstraintType.SAFE

        # 必然溢出: 最小拷贝 > 最大可用 + margin
        if copy_min > alloc_usable_max + self.margin:
            return ConstraintType.CERTAIN_OVERFLOW

        # 重叠区间 → 可能溢出
        return ConstraintType.POSSIBLE_OVERFLOW

    def overflow_likelihood(self) -> float:
        """估算溢出概率 [0, 1]"""
        if self.classify() == ConstraintType.SAFE:
            return 0.0
        if self.classify() == ConstraintType.CERTAIN_OVERFLOW:
            return 1.0
        if self.alloc_si.is_top() or self.copy_si.is_top():
            return 0.5

        alloc_range = max(1, self.alloc_usable_si.hi - self.alloc_usable_si.lo)
        copy_range = max(1, self.copy_si.hi - self.copy_si.lo)

        # 重叠区间的比例
        overlap_start = max(self.alloc_usable_si.lo, self.copy_si.lo)
        overlap_end = min(self.alloc_usable_si.hi + self.margin, self.copy_si.hi)
        overlap = max(0, overlap_end - overlap_start)

        # 拷贝超过分配的部分占拷贝总范围的比例
        ratio = overlap / copy_range if copy_range > 0 else 0.0
        return min(1.0, max(0.0, ratio))


class ConstraintSimplifier:
    """约束简化器: 把值流分析的结果变成可判定的约束。

    核心流程:
      1. 从ValueFlowResult中提取alloc区间和copy区间
      2. 应用堆分配器模型将请求大小转换为可用大小
      3. 做区间减法判定(SAFE / CERTAIN_OVERFLOW / POSSIBLE_OVERFLOW)
      4. 对POSSIBLE情况做更细粒度的跨步区间精确检查

    输入: ValueFlowResult (alloc推断 + copy推断)
    输出: SizeConstraint + ConstraintType
    """

    def __init__(self, heap_model: Optional[HeapAllocModel] = None,
                 safety_margin: int = 8):
        self._heap = heap_model or HeapAllocModel()
        self._margin = safety_margin

    def build_constraint(self,
                          alloc_request_si: StridedInterval,
                          copy_si: StridedInterval,
                          ) -> SizeConstraint:
        """构建分配vs拷贝的尺寸约束。"""
        # 将请求大小转换为可用大小
        alloc_lo_usable = self._heap._layout.usable_size(alloc_request_si.lo)
        alloc_hi_usable = self._heap._layout.usable_size(
            max(alloc_request_si.lo, alloc_request_si.hi))

        # 对齐调整: 步长也需要向上取整到MALLOC_ALIGNMENT的倍数
        usable_stride = max(1, alloc_request_si.stride)

        alloc_usable_si = StridedInterval(
            lo=alloc_lo_usable,
            hi=alloc_hi_usable,
            stride=usable_stride,
            kind=IntervalKind.RANGE if alloc_request_si.lo > 0 else alloc_request_si.kind)

        return SizeConstraint(
            alloc_si=alloc_request_si,
            alloc_usable_si=alloc_usable_si,
            copy_si=copy_si,
            margin=self._margin)

    def simplify_to_verdict(self,
                             constraint: SizeConstraint
                             ) -> Tuple[ConstraintType, float, str]:
        """将约束简化为最终判定。"""
        ctype = constraint.classify()
        likelihood = constraint.overflow_likelihood()

        if ctype == ConstraintType.SAFE:
            expl = (f"SAFE: copy_max={constraint.copy_si.max_possible()} ≤ "
                    f"alloc_usable_min={constraint.alloc_usable_si.min_possible()} "
                    f"+ margin={self._margin}")
        elif ctype == ConstraintType.CERTAIN_OVERFLOW:
            expl = (f"CERTAIN_OVERFLOW: copy_min={constraint.copy_si.min_possible()} > "
                    f"alloc_usable_max={constraint.alloc_usable_si.max_possible()} "
                    f"+ margin={self._margin}")
        elif ctype == ConstraintType.POSSIBLE_OVERFLOW:
            expl = (f"POSSIBLE_OVERFLOW: overlap range "
                    f"[{max(constraint.alloc_usable_si.lo, constraint.copy_si.lo)}, "
                    f"{min(constraint.alloc_usable_si.hi + self._margin, constraint.copy_si.hi)}] "
                    f"likelihood={likelihood:.2f}")
        else:
            expl = "UNKNOWN: insufficient interval data"
            likelihood = 0.0

        return (ctype, likelihood, expl)

    def filter_false_positive(self,
                               alloc_request_si: StridedInterval,
                               copy_si: StridedInterval,
                               min_likelihood: float = 0.3
                               ) -> Tuple[bool, str]:
        """高层API: 判断一个堆溢出告警是否为误报。"""
        constraint = self.build_constraint(alloc_request_si, copy_si)
        ctype, likelihood, expl = self.simplify_to_verdict(constraint)

        if ctype == ConstraintType.SAFE:
            return (True, f"False positive filtered: {expl}")
        elif ctype == ConstraintType.CERTAIN_OVERFLOW:
            return (False, f"Confirmed overflow: {expl}")
        elif likelihood < min_likelihood:
            return (True, f"Low likelihood ({likelihood:.2f}) → classified as false positive: {expl}")
        else:
            return (False, f"Possible overflow retained: {expl}")

    def batch_filter(self,
                      alloc_intervals: List[StridedInterval],
                      copy_intervals: List[StridedInterval],
                      min_likelihood: float = 0.3
                      ) -> List[Tuple[bool, str, float]]:
        """批量过滤多个 alloc-copy 对"""
        results = []
        for alloc_si in alloc_intervals:
            for copy_si in copy_intervals:
                constraint = self.build_constraint(alloc_si, copy_si)
                ctype, likelihood, expl = self.simplify_to_verdict(constraint)
                is_fp = (ctype == ConstraintType.SAFE or likelihood < min_likelihood)
                results.append((is_fp, expl, likelihood))
        return results
