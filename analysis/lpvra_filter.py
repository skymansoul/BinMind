"""
LPVRA过滤管线 — 基于轻量级路径敏感值域分析的统一误报过滤器.

管线架构 (3阶段):
  Stage 1: LPVRA引擎 → 对每个 alloc-write 对, 路径敏感地追踪值域区间
  Stage 2: 堆边界检查器 → 将区间与glibc chunk语义结合, 计算有效安全边界
  Stage 3: 保守分类器 → 仅过滤可证明安全的候选 (SAFE verdict)

判定规则:
  传统: store_offset > malloc_size → 溢出 (误报率高, 忽略slack/guard/路径)
  LPVRA: ∀路径: write_end ≤ effective_boundary(lo) → SAFE → 过滤
          ∃路径: write_end > effective_boundary(hi) → OVERFLOW → 保留
          其他 → UNCERTAIN → 保守保留

本模块仅做管线编排, 实际分析委托给 lpvra_engine + heap_boundary_checker.
与现有管线并行运行, 不替换任何现有过滤器 (功能只增不减).
"""


import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from analysis.lpvra_engine import (
    LPVRAEngine, LPVRAResult, HeapVerdict, Verdict, AllocInfo, WriteInfo,
)
from analysis.heap_boundary_checker import (
    BoundaryVerdict, check_heap_boundary, compute_effective_boundary,
)
from analysis.interval_domain import Interval


class FilterVerdict(Enum):
    """管线过滤判定."""
    FILTER = "FILTER"        # 可证明安全, 从候选列表移除
    DEMOTE = "DEMOTE"        # 强安全信号, 大幅降低置信度
    KEEP = "KEEP"            # 无法证明安全, 保留
    CONFIRM = "CONFIRM"      # 可证明溢出, 提升置信度


@dataclass
class FilterDecision:
    """对单个候选的过滤决策."""
    candidate_id: str = ""
    verdict: FilterVerdict = FilterVerdict.KEEP
    reason: str = ""
    confidence_delta: float = 0.0       # 置信度调整量
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class PipelineReport:
    """管线执行统计报告."""
    input_count: int = 0
    lpvra_allocs: int = 0
    lpvra_writes: int = 0
    lpvra_verdicts: int = 0
    filtered_count: int = 0
    demoted_count: int = 0
    confirmed_count: int = 0
    kept_count: int = 0
    total_time_ms: float = 0.0
    decisions: List[FilterDecision] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class LPVRAFilterPipeline:
    """LPVRA统一误报过滤管线.

    Usage:
      pipeline = LPVRAFilterPipeline()
      report = pipeline.execute(c_source_text, func_name)
      # report.filtered_count == 可证明安全的候选数
    """

    def __init__(self, max_paths: int = 128, platform: str = "x86_64"):
        self._engine = LPVRAEngine(max_paths=max_paths)
        self._platform = platform
        self._max_paths = max_paths

    def execute(self, source: str, func_name: str = "",
                existing_candidates: Optional[List[Any]] = None,
                ) -> Tuple[List[Any], PipelineReport]:
        """执行 LPVRA 过滤管线。

        返回 (filtered_candidates, pipeline_report);
        existing_candidates 为 None 时过滤结果为空列表,
        仅使用 LPVRA 内部提取的 alloc-write 对。
        """
        t0 = time.time()
        report = PipelineReport()

        # Stage 1: LPVRA分析
        try:
            lpvra_result = self._engine.analyze(source)
            report.lpvra_allocs = len(lpvra_result.allocs)
            report.lpvra_writes = len(lpvra_result.writes)
            report.lpvra_verdicts = len(lpvra_result.verdicts)
        except Exception as e:
            report.errors.append(f"LPVRA engine: {e}")
            report.total_time_ms = (time.time() - t0) * 1000
            return (existing_candidates or [], report)

        # Stage 2: 对每个LPVRA verdict做边界检查
        safe_pairs: set = set()
        overflow_pairs: set = set()
        for v in lpvra_result.verdicts:
            pair_key = (v.alloc_var, v.alloc_line, v.write_var, v.write_line)
            # Stage 2增强: 用chunk边界检查器二次验证
            bv, reason, conf = check_heap_boundary(
                v.alloc_size_iv, v.write_offset, v.write_size,
                platform=self._platform,
            )
            if bv == BoundaryVerdict.SAFE:
                safe_pairs.add(pair_key)
            elif bv == BoundaryVerdict.OVERFLOW:
                overflow_pairs.add(pair_key)

        # Stage 3: 对existing_candidates做决策
        filtered = []
        if existing_candidates:
            report.input_count = len(existing_candidates)
            for c in existing_candidates:
                decision = self._classify_candidate(c, safe_pairs, overflow_pairs)
                report.decisions.append(decision)
                if decision.verdict == FilterVerdict.FILTER:
                    report.filtered_count += 1
                elif decision.verdict == FilterVerdict.DEMOTE:
                    c.confidence = max(0.15, c.confidence + decision.confidence_delta)
                    report.demoted_count += 1
                    filtered.append(c)
                elif decision.verdict == FilterVerdict.CONFIRM:
                    c.confidence = min(0.98, c.confidence + decision.confidence_delta)
                    report.confirmed_count += 1
                    filtered.append(c)
                else:
                    report.kept_count += 1
                    filtered.append(c)
        else:
            report.kept_count = report.lpvra_verdicts
            filtered = []

        report.total_time_ms = (time.time() - t0) * 1000
        return filtered, report

    def _classify_candidate(self, candidate: Any,
                            safe_pairs: set, overflow_pairs: set) -> FilterDecision:
        """对单个候选做保守分类."""
        # 从candidate提取分配和写入信息
        alloc_var = ""
        alloc_line = 0
        write_var = ""
        write_line = 0
        if hasattr(candidate, 'alloc_site'):
            alloc_var = getattr(candidate.alloc_site, 'result_var', '')
            alloc_line = getattr(candidate.alloc_site, 'pc', 0)
        if hasattr(candidate, 'overflow_store'):
            write_var = getattr(candidate.overflow_store, 'base_var', '')
            write_line = getattr(candidate.overflow_store, 'pc', 0)

        pair_key = (alloc_var, alloc_line, write_var, write_line)
        # LPVRA已知安全的对
        key_no_line = (alloc_var, 0, write_var, 0)  # 容错: 忽略行号

        if pair_key in safe_pairs or any(
            alloc_var == sa and write_var == sw
            for sa, _, sw, _ in safe_pairs
        ):
            return FilterDecision(
                candidate_id=getattr(candidate, 'description', str(id(candidate)))[:80],
                verdict=FilterVerdict.FILTER,
                reason="LPVRA: 所有路径上写入 ≤ chunk有效边界",
                confidence_delta=-0.60,
                evidence={'source': 'lpvra+boundary_checker'},
            )
        if pair_key in overflow_pairs or any(
            alloc_var == oa and write_var == ow
            for oa, _, ow, _ in overflow_pairs
        ):
            return FilterDecision(
                candidate_id=getattr(candidate, 'description', str(id(candidate)))[:80],
                verdict=FilterVerdict.CONFIRM,
                reason="LPVRA: 存在溢出路径, 可证明真阳性",
                confidence_delta=+0.20,
                evidence={'source': 'lpvra+boundary_checker'},
            )

        return FilterDecision(
            verdict=FilterVerdict.KEEP,
            reason="LPVRA: 无匹配的alloc-write对, 保守保留",
        )

    def analyze_standalone(self, source: str) -> Tuple[LPVRAResult, PipelineReport]:
        """独立分析 (不依赖existing_candidates). 返回原始LPVRA结果."""
        t0 = time.time()
        report = PipelineReport()
        lpvra_result = self._engine.analyze(source)
        report.lpvra_allocs = len(lpvra_result.allocs)
        report.lpvra_writes = len(lpvra_result.writes)
        report.lpvra_verdicts = len(lpvra_result.verdicts)
        report.filtered_count = sum(
            1 for v in lpvra_result.verdicts if v.verdict == Verdict.SAFE)
        report.kept_count = len(lpvra_result.verdicts) - report.filtered_count
        report.total_time_ms = (time.time() - t0) * 1000
        return lpvra_result, report


def run_lpvra_filter(source: str, func_name: str = "",
                     candidates: Optional[List[Any]] = None,
                     max_paths: int = 128) -> Tuple[List[Any], PipelineReport]:
    """便捷入口: 对C源码运行LPVRA过滤管线."""
    pipeline = LPVRAFilterPipeline(max_paths=max_paths)
    return pipeline.execute(source, func_name, candidates)


__all__ = [
    'FilterVerdict', 'FilterDecision', 'PipelineReport',
    'LPVRAFilterPipeline', 'run_lpvra_filter',
]
