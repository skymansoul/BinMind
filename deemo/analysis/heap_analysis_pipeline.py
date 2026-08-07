"""
堆溢出检测的增强分析管线 —— 集成所有新分析模块。

管线阶段:
  Stage 0: 现有基础检测 (heap_overflow_detector) —— 保持兼容
  Stage 1: 值流追踪 (HeapFlowTracker) —— 确定分配大小的来源和约束
  Stage 2: 指针别名解析 (PointerAliasTracker) —— 统一派生指针的偏移
  Stage 3: 路径敏感区间分析 (PathSensitiveHeapAnalyzer) —— 区间域判定
  Stage 4: 分配器约束检查 (AllocatorConstraintChecker) —— glibc 语义过滤
  Stage 5: 多因子置信度评分 (HeapConfidenceScorer) —— 最终分类

每个阶段可独立启用/禁用, 任一阶段不可用 (ImportError) 时自动跳过。
最终输出: 分类后的候选列表 + 管线统计 + 各阶段耗时。
"""

import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


@dataclass
class PipelineStats:
    """管线各阶段的统计数据。"""
    stage_basic: int = 0
    stage_flow: int = 0
    stage_alias: int = 0
    stage_path: int = 0
    stage_allocator: int = 0
    stage_score: int = 0
    filtered_count: int = 0
    kept_count: int = 0
    total_time_ms: float = 0.0
    errors: List[str] = field(default_factory=list)


def run_heap_analysis_pipeline(
    ir_lines: List[str],
    decompiled_text: str = "",
    func_name: str = "",
    enable_stages: Optional[List[str]] = None,
) -> Tuple[List[Any], PipelineStats]:
    """运行堆溢出检测的完整增强管线。

    参数:
      ir_lines: IR/伪代码行列表
      decompiled_text: 原始反编译文本 (若 ir_lines 为空)
      func_name: 函数名 (用于上下文评分)
      enable_stages: 启用的阶段列表, None = 全部启用。
        可选值: ["basic", "flow", "alias", "path", "allocator", "score"]

    返回: (分类后的候选列表, 管线统计)
    """
    stats = PipelineStats()
    t0 = time.time()

    if not ir_lines and decompiled_text:
        from core.ir_normalizer import normalize_ir
        ir_lines = normalize_ir(decompiled_text)

    if enable_stages is None:
        enable_stages = ["basic", "flow", "alias", "path", "allocator", "score"]

    # Stage 0: 基础检测 (保持向后兼容)
    candidates = []
    if "basic" in enable_stages:
        try:
            from core.heap_overflow_detector import detect_heap_overflow
            candidates = detect_heap_overflow(ir_lines, decompiled_text)
            stats.stage_basic = len(candidates)
        except ImportError as e:
            stats.errors.append(f"basic: {e}")

    if not candidates:
        stats.total_time_ms = (time.time() - t0) * 1000
        return [], stats

    # Stage 1: 值流追踪 —— 增强每个候选的分配大小信息
    if "flow" in enable_stages:
        try:
            from core.heap_flow_tracker import HeapFlowTracker
            tracker = HeapFlowTracker()
            text = decompiled_text or "\n".join(ir_lines)
            traces = tracker.trace(text)
            # 将追踪结果附加到对应候选
            for c in candidates:
                for tr in traces:
                    if tr.alloc_func == c.alloc_site.alloc_func:
                        if tr.source_type.value == "constant":
                            val = int(tr.size_var) if tr.size_var.isdigit() else 0
                            if val > 0:
                                c.alloc_site.size_arg = val
                                c.alloc_site.size_is_dynamic = False
                        c._flow_trace = tr  # 附加元数据
                        break
            stats.stage_flow = len(traces)
        except ImportError as e:
            stats.errors.append(f"flow: {e}")

    # Stage 2: 指针别名解析
    if "alias" in enable_stages:
        try:
            from analysis.pointer_alias_tracker import PointerAliasTracker
            alias_tracker = PointerAliasTracker()
            for c in candidates:
                alias_tracker.register_heap_base(c.alloc_site.result_var)
            alias_tracker.trace_aliases(ir_lines)
            # 解析每个候选的 store 偏移
            for c in candidates:
                resolved = alias_tracker.resolve_store(
                    c.overflow_store.base_var,
                    c.overflow_store.offset,
                )
                if resolved.derived_var:
                    c.overflow_store.base_var = resolved.base_var
                    c.overflow_store.offset = resolved.total_offset
                c._alias_info = resolved
            stats.stage_alias = len(alias_tracker._aliases)
        except ImportError as e:
            stats.errors.append(f"alias: {e}")

    # Stage 3: 路径敏感区间分析
    if "path" in enable_stages:
        try:
            from analysis.heap_path_analyzer import path_sensitive_analyze
            text = decompiled_text or "\n".join(ir_lines)
            verdicts = path_sensitive_analyze(text)
            for c in candidates:
                for v in verdicts:
                    if (v.alloc_line in c.description and
                        v.write_line in c.description):
                        c._path_verdict = v
                        # 路径分析证明安全 → 降置信度
                        if v.verdict == "SAFE":
                            c.confidence = min(c.confidence, 0.35)
                        break
            stats.stage_path = len(verdicts)
        except ImportError as e:
            stats.errors.append(f"path: {e}")

    # Stage 4: 分配器约束检查
    if "allocator" in enable_stages:
        try:
            from core.allocator_constraints import (
                AllocSize, AllocatorConstraintChecker)
            checker = AllocatorConstraintChecker()
            for c in candidates[:]:
                if c.alloc_site.size_arg > 0 and not c.alloc_site.size_is_dynamic:
                    actual = AllocSize.from_request(c.alloc_site.size_arg)
                    write_size = c.overflow_store.store_size
                    total_write = c.overflow_store.offset + max(write_size, 4)
                    if actual.can_contain(total_write):
                        candidates.remove(c)
                        stats.filtered_count += 1
            stats.stage_allocator = stats.filtered_count
        except ImportError as e:
            stats.errors.append(f"allocator: {e}")

    # Stage 5: 多因子置信度评分
    if "score" in enable_stages:
        try:
            from analysis.heap_confidence_scorer import classify_heap_overflows
            candidates = classify_heap_overflows(
                candidates, ir_lines, func_name)
            stats.stage_score = len(candidates)
        except ImportError as e:
            stats.errors.append(f"score: {e}")

    # 最终排序: 高置信度在前
    candidates.sort(key=lambda c: getattr(c, 'combined_confidence',
                                          c.confidence), reverse=True)
    stats.kept_count = len(candidates)
    stats.total_time_ms = (time.time() - t0) * 1000
    return candidates, stats


__all__ = ['run_heap_analysis_pipeline', 'PipelineStats']
