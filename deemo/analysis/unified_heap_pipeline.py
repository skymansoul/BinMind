"""
统一堆溢出检测流水线 v2 — 集成全部算法模块的单一入口.

流水线阶段:
  Stage 1 (IR→alloc sites):          提取 malloc/calloc/realloc 及 size 参数
  Stage 2 (inter-proc summary):       跨函数 size constraint 传播
  Stage 3 (strided interval):         将 size 表达式抽象为 strided interval
  Stage 4 (guard inference):          提取写入前的边界检查守卫
  Stage 5 (path condition refine):    路径条件精化 strided interval
  Stage 6 (allocator constraint):     应用 glibc ptmalloc 语义 → 校正有效容量
  Stage 7 (heap shape model):         堆拓扑建模 → 溢出影响评估
  Stage 8 (verdict):                  综合所有阶段输出 → 最终判定

设计原则:
  - 每个阶段独立、可跳过 (若 ImportError 则降级)
  - 阶段间用 dataclass 传递结果, 不耦合到具体实现
  - 最终 verdict 包含 confidence, fp_likelihood, reasoning 三要素
  - 原始检测结果保留 (只降置信度, 不删除告警)
"""


import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from analysis.strided_interval import (
    StridedInterval, si_singleton, si_interval, si_unbounded,
)


@dataclass
class PipelineFinding:
    """流水线中间结果 — 单个堆操作点的全阶段分析."""
    func_name: str = ""
    line: int = 0
    alloc_func: str = ""
    alloc_size: int = 0
    alloc_effective: int = 0          # 分配器实际可用大小 (Stage 6)
    write_size: int = 0
    write_offset: int = 0
    size_var: str = ""
    # 各阶段结果
    size_interval: Optional[StridedInterval] = None   # Stage 3
    is_guarded: bool = False                           # Stage 4
    guard_desc: str = ""                               # Stage 4
    path_safe_ratio: float = 1.0                       # Stage 5
    allocator_verdict: str = "UNCERTAIN"               # Stage 6
    overflow_bytes: int = 0                            # Stage 7
    exploitability: float = 0.0                        # Stage 7
    # 最终判定
    is_true_positive: bool = True
    confidence: float = 0.5
    fp_likelihood: float = 0.5
    reasoning: str = ""
    scan_time_ms: float = 0.0


@dataclass
class PipelineResult:
    """流水线输出."""
    findings: List[PipelineFinding] = field(default_factory=list)
    stats: Dict[str, Any] = field(default_factory=dict)
    total_time_ms: float = 0.0


class UnifiedHeapPipeline:
    """统一堆溢出检测流水线.

    每个阶段可选; 禁用阶段不引入外部依赖.
    """

    def __init__(self, enable_interproc: bool = True,
                 enable_path_sensitive: bool = True,
                 enable_heap_shape: bool = True,
                 enable_allocator_model: bool = True):
        self._enable_interproc = enable_interproc
        self._enable_path_sensitive = enable_path_sensitive
        self._enable_heap_shape = enable_heap_shape
        self._enable_allocator_model = enable_allocator_model

    def analyze(self, decompiled_funcs: Dict[str, str],
                ir_lines: Optional[List[str]] = None,
                binary_path: str = "") -> PipelineResult:
        """主分析入口.

        Args:
            decompiled_funcs: {func_name: pseudocode} 映射
            ir_lines: 可选, 线性 IR 行列表
            binary_path: 可选, 二进制文件路径 (用于分配器检测)

        Returns:
            PipelineResult 包含所有经过滤的 findings 和统计信息
        """
        t0 = time.time()
        findings = []
        stats = {
            'functions_analyzed': 0,
            'alloc_sites_found': 0,
            'guard_matches': 0,
            'path_segments': 0,
            'fp_filtered': 0,
            'confirmed': 0,
        }

        # Stage 0: 确认分配器类型
        allocator = "glibc-ptmalloc2"
        if binary_path:
            try:
                from core.allocator_model import detect_allocator
                a = detect_allocator(binary_path)
                allocator = a.value
            except ImportError:
                pass

        # Stage 1: 提取基本 alloc sites
        for func_name, code in decompiled_funcs.items():
            pf = self._extract_findings(func_name, code)
            findings.extend(pf)
            stats['functions_analyzed'] += 1

        stats['alloc_sites_found'] = len(findings)
        if not findings:
            result = PipelineResult(findings=[], stats=stats,
                                    total_time_ms=(time.time() - t0) * 1000)
            return result

        # Stage 2: 跨函数摘要传播
        if self._enable_interproc and len(decompiled_funcs) > 1:
            try:
                from analysis.interproc_size_summary import InterProcSizeSummarizer
                summarizer = InterProcSizeSummarizer()
                summaries = summarizer.propagate(decompiled_funcs)
                self._apply_summaries(findings, summaries)
            except ImportError:
                pass

        # Stage 3: Strided interval 精化
        for pf in findings:
            si = si_interval(0, pf.alloc_size) if pf.alloc_size > 0 else si_unbounded(0)
            pf.size_interval = si

        # Stage 4: Guard inference
        if ir_lines:
            try:
                from analysis.guard_inference import GuardInferenceEngine
                engine = GuardInferenceEngine()
                for pf in findings:
                    result = engine.infer(ir_lines, pf.line, pf.alloc_size,
                                          pf.line + 1, pf.size_var or "")
                    pf.is_guarded = (result.verdict.value == "protected")
                    pf.guard_desc = result.description
                    if pf.is_guarded:
                        stats['guard_matches'] += 1
            except ImportError:
                pass

        # Stage 5: 路径条件精化
        if self._enable_path_sensitive:
            try:
                from analysis.path_condition_tracker import PathConditionTracker
                pct = PathConditionTracker()
                for pf in findings:
                    func_code = decompiled_funcs.get(pf.func_name, "")
                    if not func_code:
                        continue
                    segments = pct.build_path_segments(func_code, pf.func_name)
                    stats['path_segments'] += len(segments)
                    pf.path_safe_ratio = pct.compute_fp_likelihood(
                        pf.alloc_size, pf.write_size, segments, pf.size_var or "size")
            except ImportError:
                pass

        # Stage 6: 分配器约束
        if self._enable_allocator_model:
            for pf in findings:
                if pf.alloc_size <= 0 or pf.write_size <= 0:
                    continue
                try:
                    from analysis.strided_interval import AllocSize
                    actual = AllocSize.from_request(pf.alloc_size)
                    pf.alloc_effective = actual.effective
                    pf.allocator_verdict = (
                        "FILTER" if pf.write_size <= actual.effective else "KEEP"
                    )
                except ImportError:
                    pf.alloc_effective = pf.alloc_size

        # Stage 7: 堆形状建模
        if self._enable_heap_shape:
            try:
                from analysis.heap_shape_model import HeapShapeModel
                model = HeapShapeModel()
                for func_name, code in decompiled_funcs.items():
                    func_findings = [f for f in findings if f.func_name == func_name]
                    if not func_findings:
                        continue
                    alloc_sites = [{
                        'var_name': f.size_var, 'alloc_func': f.alloc_func,
                        'size_arg': f.alloc_size, 'line': f.line,
                    } for f in func_findings]
                    shape = model.build_shape(func_name, alloc_sites)
                    for pf in func_findings:
                        assess = model.assess_overflow(
                            shape, pf.size_var or "", pf.write_offset, pf.write_size)
                        pf.overflow_bytes = assess.overflow_bytes
                        pf.exploitability = assess.exploitability
            except ImportError:
                pass

        # Stage 8: 综合判定
        for pf in findings:
            self._compute_final_verdict(pf)
            if pf.fp_likelihood > 0.65:
                stats['fp_filtered'] += 1
            else:
                stats['confirmed'] += 1

        result = PipelineResult(
            findings=sorted(findings, key=lambda f: -f.confidence),
            stats=stats,
            total_time_ms=(time.time() - t0) * 1000,
        )
        return result

    # helpers (delegated to pipeline_stage_helpers)

    def _extract_findings(self, func_name: str,
                          code: str) -> List[PipelineFinding]:
        """Stage 1: 从单函数代码中提取基础 alloc+write pairs。"""
        from analysis.pipeline_stage_helpers import extract_alloc_write_pairs
        raw = extract_alloc_write_pairs(func_name, code)
        return [
            PipelineFinding(
                func_name=r['func_name'], line=r['line'],
                alloc_func=r['alloc_func'], alloc_size=r['alloc_size'],
                write_size=r['write_size'], size_var=r['size_var'],
            )
            for r in raw
        ]

    @staticmethod
    def _apply_summaries(findings: List[PipelineFinding],
                         summaries: Dict) -> None:
        """将跨函数摘要应用到 findings."""
        from analysis.pipeline_stage_helpers import apply_interproc_summaries
        apply_interproc_summaries(findings, summaries)

    @staticmethod
    def _compute_final_verdict(pf: PipelineFinding) -> None:
        """综合所有阶段计算最终判定."""
        from analysis.pipeline_stage_helpers import compute_final_verdict
        fp_likelihood, confidence, is_tp, reasoning = compute_final_verdict(pf)
        pf.fp_likelihood = fp_likelihood
        pf.confidence = confidence
        pf.is_true_positive = is_tp
        pf.reasoning = reasoning


def quick_analyze(code: str, func_name: str = "unknown") -> List[PipelineFinding]:
    """便捷接口: 单函数快速分析."""
    pipeline = UnifiedHeapPipeline(
        enable_interproc=False, enable_path_sensitive=True,
        enable_heap_shape=True, enable_allocator_model=True,
    )
    result = pipeline.analyze({func_name: code})
    return result.findings


__all__ = [
    'PipelineFinding', 'PipelineResult', 'UnifiedHeapPipeline', 'quick_analyze',
]
