"""
GAPSBV 端到端检测管道 — 集成全部7维度, 一键判定堆溢出。

这是 BinMind 堆溢出检测的统一入口。整合以下维度:
  维度1 (仿射关系, 权重0.35): AffineRelationTracker — alloc-write 符号差分
  维度2 (路径约束, 权重0.20): GuardConditionInferrer — if(var OP const) 守卫
  维度3 (StridedInterval, 权重0.25): StridedInterval — s[lo,hi] 域 + chunk 语义
  维度4 (分配器语义, 权重0.20): AllocatorChunkModel — request2size, alignment
  维度5 (完备性检查, 权重0.05): CompletenessCheck — 显式溢出模式安全网
  维度6 (循环累积, 权重0.15): LoopAccumulator — 循环内逐字节写入累计分析
  维度7 (分配前约束, 权重0.10): PreAllocConstraint — malloc前变量上界窄化

融合规则 (保守):
  任一维度证明 SAFE → 整体 FILTER (保证零额外假阴性, dim5 不参与 SAFE)
  任一维度证明 OVERFLOW 且无 SAFE → KEEP
  全部 UNCERTAIN → 输出 UNCERTAIN + 加权置信度

入口函数:
  detect_heap_overflow_gapsbv(pseudocode: str) → GapsbvReport

用法:
  from analysis.gapsbv_pipeline import detect_heap_overflow_gapsbv
  report = detect_heap_overflow_gapsbv(open('vuln.c').read())
  print(report.verdict, report.confidence)
"""

from typing import Tuple

from analysis.affine_relation_tracker import AffineRelationTracker
from analysis.guard_condition_inferrer import (
    GuardConditionInferrer, infer_guard_bounds,
)
from analysis.gapsbv_dimensions import (
    GapsbvVerdict, DimensionResult, GapsbvReport,
    _resolve_macros,
    dim1_affine_relations, dim2_guard_analysis,
    dim3_strided_interval, dim4_allocator_semantics,
)
from analysis.gapsbv_dimension5 import dim5_completeness_check
from analysis.heap_loop_accumulator import (
    HeapLoopAccumulator, LoopWriteVerdict, LoopWriteFinding)
from analysis.pre_alloc_constraint import (
    PreAllocConstraint, evaluate_pre_alloc_safety)


def _dim6_loop_accumulation(pseudocode: str) -> DimensionResult:
    """维度6: 循环感知堆写入累积分析 (权重0.15).
    检测循环内逐字节/逐块累积写入是否超出分配大小.
    """
    try:
        acc = HeapLoopAccumulator()
        findings = acc.analyze(pseudocode)
        if not findings:
            return DimensionResult(
                name="loop_accum", weight=0.15,
                verdict="UNCERTAIN", confidence=0.0,
                reason="no loop writes to heap buffers")
        worst = max(findings, key=lambda f: (
            2 if f.verdict == LoopWriteVerdict.OVERFLOW else
            1 if f.verdict == LoopWriteVerdict.UNCERTAIN else 0))
        if worst.verdict == LoopWriteVerdict.SAFE:
            return DimensionResult(
                name="loop_accum", weight=0.15,
                verdict="SAFE", confidence=0.9, reason=worst.reason)
        elif worst.verdict == LoopWriteVerdict.OVERFLOW:
            return DimensionResult(
                name="loop_accum", weight=0.15,
                verdict="OVERFLOW", confidence=0.85, reason=worst.reason)
        return DimensionResult(
            name="loop_accum", weight=0.15,
            verdict="UNCERTAIN", confidence=0.3, reason=worst.reason)
    except Exception:
        return DimensionResult(
            name="loop_accum", weight=0.15,
            verdict="UNCERTAIN", confidence=0.0, reason="error")


def _dim7_pre_alloc_constraint(pseudocode: str) -> DimensionResult:
    """维度7: 分配前约束窄化 (权重0.10).
    追踪malloc前变量的上界约束, 消除限幅变量误报.
    """
    try:
        verdict, confidence, reason = evaluate_pre_alloc_safety(pseudocode)
        return DimensionResult(
            name="pre_alloc", weight=0.10,
            verdict=verdict, confidence=confidence, reason=reason)
    except Exception:
        return DimensionResult(
            name="pre_alloc", weight=0.10,
            verdict="UNCERTAIN", confidence=0.0, reason="error")


def detect_heap_overflow_gapsbv(pseudocode: str) -> GapsbvReport:
    """GAPSBV 端到端堆溢出检测。

    返回含最终 verdict/confidence/各维度详情的 GapsbvReport。
    """
    # 先展开宏, 再提取守卫边界 (用于精化仿射关系分析)
    expanded = _resolve_macros(pseudocode)
    guard_bounds = infer_guard_bounds(expanded)

    # 运行七个维度
    dims = [
        dim1_affine_relations(pseudocode, guard_bounds),
        dim3_strided_interval(pseudocode),
        dim2_guard_analysis(pseudocode),
        dim4_allocator_semantics(pseudocode),
        dim5_completeness_check(pseudocode),
        _dim6_loop_accumulation(pseudocode),
        _dim7_pre_alloc_constraint(pseudocode),
    ]

    # 保守融合规则: 任一维度 SAFE → 整体 FILTER
    safe_dims = [d for d in dims if d.verdict == "SAFE"]
    overflow_dims = [d for d in dims if d.verdict == "OVERFLOW"]
    active_filters = [d.name for d in safe_dims]

    if safe_dims:
        verdict = "SAFE"
        confidence = max(d.confidence for d in safe_dims)
    elif overflow_dims:
        verdict = "OVERFLOW"
        confidence = max(d.confidence for d in overflow_dims)
    else:
        weighted_conf = sum(d.confidence * d.weight for d in dims)
        verdict = "CONDITIONAL" if weighted_conf > 0.25 else "UNCERTAIN"
        confidence = weighted_conf

    # 统计信息
    affine_count = 0
    try:
        tracker = AffineRelationTracker()
        rels = tracker.track_alloc_write_relation(pseudocode)
        affine_count = len(rels)
    except Exception:
        pass

    guard_count = 0
    try:
        inferrer = GuardConditionInferrer()
        gs_list = inferrer.extract_guards(expanded)
        guard_count = sum(len(g.conditions) for g in gs_list)
    except Exception:
        pass

    alloc_count = expanded.count('malloc(') + expanded.count('calloc(')

    return GapsbvReport(
        verdict=verdict,
        confidence=round(confidence, 4),
        dimensions=dims,
        affine_relations=affine_count,
        guard_conditions=guard_count,
        alloc_sites=alloc_count,
        active_filters=active_filters,
    )


def detect_heap_gapsbv_quick(source: str) -> Tuple[str, float]:
    """快速检测 (返回 verdict, confidence), 用于批量扫描."""
    report = detect_heap_overflow_gapsbv(source)
    return report.verdict, report.confidence


__all__ = [
    'GapsbvVerdict', 'DimensionResult', 'GapsbvReport',
    'detect_heap_overflow_gapsbv', 'detect_heap_gapsbv_quick',
]
