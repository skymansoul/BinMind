"""
堆溢出集成判定器 — 融合仿射关系+StridedInterval+路径约束+分配器模型的统一决策.

四维度独立打分, 加权融合:
  维度1 (仿射关系): alloc_expr 和 write_expr 的符号差分 — 权重 0.35
  维度2 (StridedInterval): 区间重叠度判定 — 权重 0.25
  维度3 (路径约束): 守卫条件对区间的精化效果 — 权重 0.20
  维度4 (分配器语义): glibc对齐和最小块 — 权重 0.20

融合规则: 任一维度证明 SAFE → FILTER; 任一维度证明 OVERFLOW → KEEP.
评分函数已移至 heap_integrator_types.py.
"""


from typing import Any, Dict, List, Optional

from analysis.affine_relation_tracker import AffineRelationTracker
from analysis.strided_interval import StridedInterval
from analysis.heap_integrator_types import (
    DimensionVerdict, DimensionScore, IntegratedVerdict,
    score_dimension_affine, score_dimension_interval,
    score_dimension_path, score_dimension_allocator,
)


class HeapOverflowIntegrator:
    """堆溢出集成判定器 — 四维融合决策."""

    _WEIGHTS = {'affine': 0.35, 'interval': 0.25,
                'path': 0.20, 'allocator': 0.20}

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        self._affine_tracker = AffineRelationTracker()

    def analyze(self, pseudocode: str = "", alloc_size: int = 0,
                write_size: int = 0, func_name: str = "",
                path_constraints: Optional[List[Any]] = None,
                alloc_si: Optional[StridedInterval] = None,
                write_si: Optional[StridedInterval] = None,
                alloc_func: str = "malloc",
                size_var: str = "size") -> IntegratedVerdict:
        """执行四维融合分析."""
        scores = [
            score_dimension_affine(self._affine_tracker, pseudocode,
                                   alloc_size, write_size),
            score_dimension_interval(alloc_size, write_size, alloc_si,
                                     write_si, func_name, self._overlap_ratio),
            score_dimension_path(pseudocode, alloc_size, write_size,
                                 path_constraints, size_var),
            score_dimension_allocator(alloc_size, write_size, alloc_func,
                                      self._effective_size),
        ]
        return self._fuse(scores, alloc_size, write_size)

    def _fuse(self, scores: List[DimensionScore],
              alloc_size: int, write_size: int) -> IntegratedVerdict:
        """加权融合四个维度的评分."""
        any_safe = any(s.verdict == DimensionVerdict.SAFE for s in scores)

        if any_safe:
            safe_dims = [s.dimension for s in scores
                        if s.verdict == DimensionVerdict.SAFE]
            return IntegratedVerdict(
                is_overflow=False, is_false_positive=True,
                confidence=0.85, fp_likelihood=0.85,
                dimension_scores=scores,
                recommendations=[f"filtered by: {', '.join(safe_dims)}"],
                effective_alloc=self._effective_size(alloc_size, "malloc"))

        weighted_sum = 0.0
        weight_sum = 0.0
        for s in scores:
            w = self._WEIGHTS.get(s.dimension, 0.20)
            weighted_sum += s.score * w * s.confidence
            weight_sum += w * s.confidence
        fused_score = weighted_sum / weight_sum if weight_sum > 0 else 0.0

        if fused_score >= 0.40:
            is_overflow, is_fp = True, False
        elif fused_score <= -0.40:
            is_overflow, is_fp = False, True
        else:
            is_overflow, is_fp = True, False  # 保守保留

        fp_likelihood = max(0.0, min(1.0, 0.5 - fused_score))
        confidence = 1.0 - abs(fused_score) * 0.5
        recs = []
        if any(s.verdict == DimensionVerdict.OVERFLOW for s in scores):
            recs.append("at least one dimension confirms overflow")
        if -0.40 < fused_score < 0.40:
            recs.append("fused score uncertain — recommend manual review")

        return IntegratedVerdict(
            is_overflow=is_overflow, is_false_positive=is_fp,
            confidence=round(confidence, 3),
            fp_likelihood=round(fp_likelihood, 3),
            dimension_scores=scores, recommendations=recs,
            effective_alloc=self._effective_size(alloc_size, "malloc"))

    @staticmethod
    def _overlap_ratio(a: StridedInterval, b: StridedInterval) -> float:
        """计算两个区间的重叠比例."""
        if a.is_unbounded() or b.is_unbounded():
            return 0.5
        overlap_lo = max(a.lo, b.lo)
        overlap_hi = min(a.hi, b.hi)
        if overlap_lo > overlap_hi:
            return 0.0
        total_range = max(a.hi, b.hi) - min(a.lo, b.lo)
        if total_range == 0:
            return 1.0
        return min(1.0, (overlap_hi - overlap_lo) / total_range)

    @staticmethod
    def _effective_size(requested: int, alloc_func: str) -> int:
        """glibc ptmalloc2: request -> usable size."""
        if requested <= 0:
            return 0
        align = 16
        min_chunk = 32
        header = 16
        aligned = ((requested + header + align - 1) // align) * align
        return max(min_chunk, aligned) - header


__all__ = ['DimensionVerdict', 'DimensionScore', 'IntegratedVerdict',
           'HeapOverflowIntegrator', 'integrate_heap_finding']
