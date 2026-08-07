"""
堆溢出集成判定 — 类型定义 + 维度评分函数 + 便捷入口.
"""


from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from analysis.strided_interval import (
    StridedInterval, si_singleton, si_unbounded,
)


class DimensionVerdict(Enum):
    SAFE = "SAFE"
    OVERFLOW = "OVERFLOW"
    LIKELY_SAFE = "LIKELY_SAFE"
    LIKELY_OVERFLOW = "LIKELY_OVERFLOW"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class DimensionScore:
    """单个分析维度的评分."""
    dimension: str
    verdict: DimensionVerdict
    score: float
    confidence: float
    reasoning: str


@dataclass
class IntegratedVerdict:
    """融合判定结果."""
    is_overflow: bool
    is_false_positive: bool
    confidence: float
    fp_likelihood: float
    dimension_scores: List[DimensionScore] = field(default_factory=list)
    recommendations: List[str] = field(default_factory=list)
    alloc_expr: Optional[Any] = None
    write_expr: Optional[Any] = None
    effective_alloc: int = 0


# 各维度评分函数 (从 HeapOverflowIntegrator 拆出)

def score_dimension_affine(affine_tracker, pseudocode: str,
                           alloc_size: int, write_size: int) -> DimensionScore:
    """维度1: 仿射关系分析."""
    if not pseudocode:
        return DimensionScore('affine', DimensionVerdict.UNCERTAIN, 0.0, 0.0,
                              "no pseudocode available")
    relations = affine_tracker.track_alloc_write_relation(pseudocode)
    if not relations:
        return DimensionScore('affine', DimensionVerdict.UNCERTAIN, 0.0, 0.0,
                              "no alloc-write pairs found")
    conclusive = [r for r in relations if r.is_conclusive]
    shared = [r for r in relations if r.shared_vars]
    if conclusive:
        best = conclusive[0]
        if best.verdict == "SAFE":
            return DimensionScore('affine', DimensionVerdict.SAFE, -0.85, 0.90,
                                  f"affine proof: {best.condition}")
        elif best.verdict == "OVERFLOW":
            return DimensionScore('affine', DimensionVerdict.OVERFLOW, 0.85, 0.90,
                                  f"affine proof: {best.condition}")
    if shared:
        best = shared[0]
        if best.verdict == "CONDITIONAL":
            return DimensionScore('affine', DimensionVerdict.UNCERTAIN, 0.20, 0.50,
                                  f"shared vars {best.shared_vars} but conditional: {best.condition}")
    return DimensionScore('affine', DimensionVerdict.UNCERTAIN, 0.0, 0.30,
                          f"{len(relations)} pairs, none conclusive")


def score_dimension_interval(alloc_size: int, write_size: int,
                             alloc_si: Optional[StridedInterval],
                             write_si: Optional[StridedInterval],
                             func_name: str,
                             overlap_fn) -> DimensionScore:
    """维度2: StridedInterval 区间分析."""
    if alloc_si is None:
        alloc_si = si_singleton(alloc_size) if alloc_size > 0 else si_unbounded(0)
    if write_si is None:
        write_si = si_singleton(write_size) if write_size > 0 else si_unbounded(0)
    if write_si.must_exceed(alloc_si.hi if not alloc_si.is_unbounded() else 2**63 - 1):
        return DimensionScore('interval', DimensionVerdict.OVERFLOW, 0.80, 0.85,
                              f"write min={write_si.lo} > alloc max={alloc_si.hi}")
    if not write_si.may_exceed(alloc_si.lo):
        return DimensionScore('interval', DimensionVerdict.SAFE, -0.70, 0.85,
                              f"write max <= alloc min={alloc_si.lo}")
    if alloc_si.is_unbounded() or write_si.is_unbounded():
        return DimensionScore('interval', DimensionVerdict.UNCERTAIN, 0.10, 0.40,
                              "unbounded interval")
    overlap_ratio = overlap_fn(alloc_si, write_si)
    if overlap_ratio < 0.1:
        return DimensionScore('interval', DimensionVerdict.LIKELY_OVERFLOW, 0.50, 0.65,
                              f"minimal overlap ({overlap_ratio:.1%})")
    elif overlap_ratio > 0.9:
        return DimensionScore('interval', DimensionVerdict.LIKELY_SAFE, -0.30, 0.55,
                              f"high overlap ({overlap_ratio:.1%})")
    return DimensionScore('interval', DimensionVerdict.UNCERTAIN, 0.0, 0.45,
                          f"overlap {overlap_ratio:.1%}")


def score_dimension_path(pseudocode: str, alloc_size: int, write_size: int,
                         path_constraints: Optional[List[Any]],
                         size_var: str) -> DimensionScore:
    """维度3: 路径约束精化."""
    if not path_constraints and not pseudocode:
        return DimensionScore('path', DimensionVerdict.UNCERTAIN, 0.0, 0.0,
                              "no path constraints or pseudocode")
    if not path_constraints:
        try:
            from analysis.guard_inference import infer_guards
            guards = infer_guards(pseudocode)
            if not guards:
                return DimensionScore('path', DimensionVerdict.UNCERTAIN, 0.0, 0.40,
                                      "no guards inferred")
        except ImportError:
            return DimensionScore('path', DimensionVerdict.UNCERTAIN, 0.0, 0.30,
                                  "guard_inference unavailable")
    if path_constraints:
        for c in path_constraints:
            c_var = getattr(c, 'var', getattr(c, 'variable', ''))
            if c_var == size_var:
                c_op = getattr(c, 'op', '')
                c_val = getattr(c, 'constant', getattr(c, 'value', 0))
                if c_op in ('le', '<=') and c_val <= alloc_size:
                    return DimensionScore('path', DimensionVerdict.SAFE, -0.60, 0.70,
                                          f"guard {c_var} <= {c_val} <= alloc({alloc_size})")
                if c_op in ('<=', 'le', 'lt', '<') and c_val < write_size:
                    return DimensionScore('path', DimensionVerdict.OVERFLOW, 0.55, 0.65,
                                          f"guard {c_var} <= {c_val} < write({write_size})")
    return DimensionScore('path', DimensionVerdict.UNCERTAIN, 0.0, 0.45,
                          "no decisive path constraint found")


def score_dimension_allocator(alloc_size: int, write_size: int,
                              alloc_func: str, effective_fn) -> DimensionScore:
    """维度4: 分配器语义."""
    effective = effective_fn(alloc_size, alloc_func)
    if write_size <= effective:
        return DimensionScore('allocator', DimensionVerdict.SAFE, -0.55, 0.80,
                              f"write({write_size}) <= effective_chunk({effective})")
    if write_size <= effective + 16:
        return DimensionScore('allocator', DimensionVerdict.LIKELY_OVERFLOW, 0.20, 0.55,
                              f"write({write_size}) slightly exceeds effective({effective})")
    return DimensionScore('allocator', DimensionVerdict.OVERFLOW, 0.60, 0.80,
                          f"write({write_size}) > effective_chunk({effective}) by {write_size - effective}B")


def integrate_heap_finding(pseudocode: str, alloc_size: int, write_size: int,
                           func_name: str = "",
                           path_constraints: Optional[List[Any]] = None,
                           platform: str = "x86_64",
                           alloc_func: str = "malloc") -> IntegratedVerdict:
    """便捷入口: 单次调用集成判定."""
    from analysis.heap_overflow_integrator import HeapOverflowIntegrator
    integrator = HeapOverflowIntegrator(platform=platform)
    return integrator.analyze(pseudocode=pseudocode, alloc_size=alloc_size,
                              write_size=write_size, func_name=func_name,
                              path_constraints=path_constraints,
                              alloc_func=alloc_func)
