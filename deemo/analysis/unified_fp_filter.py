"""
统一误报过滤器 —— 五阶段堆溢出误报削减流水线.

流水线设计:
  Phase 0 — 分配器语义: 利用 glibc 对齐/最小chunk约束消除 padding 导致的误报
  Phase 1 — 路径约束收集: 提取分支条件 (if(x>N)x=N), 构建变量→上界映射
  Phase 2 — 堆布局推断: 建模连续分配的 chunk 间距, 判断溢出是否跨越chunk边界
  Phase 3 — Z3约束证明: 对 Phase 1 收集的约束做 SMT 可满足性验证
  Phase 4 — Strided Interval: 使用步长区间消除 sizeof(T) 导致的假溢出

期望效果 (基于文献和初步实验):
  基础检测器 (模式匹配):          误报率 ~75%
  + Phase 0 (分配器语义):         误报率 ~55%  (减少 20pp)
  + Phase 1+3 (路径约束+SMT):     误报率 ~35%  (减少 40pp)
  + Phase 2 (堆布局):             误报率 ~28%  (减少 7pp)
  + Phase 4 (Strided Interval):   误报率 ~20%  (减少 8pp)

  预期总计: 误报率从 ~75% 降至 ~20%, 召回率保持 > 85%.
  这组数字需要在实际 CVE 样本集上验证 (see tests/).

与现有过滤器的关系:
  · heap_false_positive_filter.py: 覆盖 Phase 0 并保留其 value-flow 追踪逻辑
  · heap_fp_filter_stages.py: Phase 0 的轻量版 — 保留对齐/结构体字段过滤
  · 本模块 = Phases 0-4 的统一入口 + 统计报告
"""


import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from core.allocator_constraints import AllocSize, AllocatorConstraintChecker
from core.heap_flow_tracker import HeapFlowTracker, TraceResult


@dataclass
class FilterStage:
    """单次过滤阶段的统计."""
    name: str = ""
    input_count: int = 0
    filtered_count: int = 0
    remaining_count: int = 0
    filter_reasons: Dict[str, int] = field(default_factory=dict)


@dataclass
class FilterReport:
    """完整过滤流水线的统计报告."""
    total_candidates: int = 0
    final_candidates: int = 0
    total_filtered: int = 0
    fp_rate_before: float = 0.0   # 过滤前估计误报率
    fp_rate_after: float = 0.0    # 过滤后估计误报率
    stages: List[FilterStage] = field(default_factory=list)
    execution_time_ms: float = 0.0


class UnifiedFPFilter:
    """五阶段统一误报过滤器.

    Usage:
      filter = UnifiedFPFilter()
      report = filter.execute(ir_lines, pseudocode, candidates)
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        self._checker = AllocatorConstraintChecker(platform)
        self._flow_tracker = HeapFlowTracker()

    def execute(
        self,
        ir_lines: List[str],
        pseudocode: str = "",
        candidates: Optional[List[Any]] = None,
        write_size: int = 0,
    ) -> FilterReport:
        """执行五阶段过滤流水线。

        candidates 为堆溢出候选列表, write_size 在候选未携带时全局
        补充; 返回含完整过滤统计的 FilterReport。
        """
        t0 = time.time()

        if candidates is None:
            candidates = []

        report = FilterReport(total_candidates=len(candidates))
        mid = self._estimates(candidates)
        report.fp_rate_before = min(0.95, max(0.0, mid))

        remaining = list(candidates)

        # Phase 0 — 分配器语义 (轻量, 先跑)
        remaining, stage0 = self._phase_allocator_semantics(remaining)
        report.stages.append(stage0)

        # Phase 1 — 路径约束收集
        constraints_map: Dict[str, List[Any]] = {}
        if pseudocode:
            remaining, stage1, constraints_map = self._phase_path_constraints(
                remaining, pseudocode,
            )
            report.stages.append(stage1)

        # Phase 2 — 堆布局推断
        if pseudocode:
            remaining, stage2 = self._phase_heap_layout(remaining, pseudocode)
            report.stages.append(stage2)

        # Phase 3 — Z3 约束证明
        if constraints_map:
            remaining, stage3 = self._phase_z3_prove(
                remaining, constraints_map,
            )
            report.stages.append(stage3)

        # Phase 4 — Strided Interval 验证
        remaining, stage4 = self._phase_strided_interval(remaining, ir_lines)
        report.stages.append(stage4)

        report.final_candidates = len(remaining)
        report.total_filtered = len(candidates) - len(remaining)
        last_mid = self._estimates(remaining) if remaining else 0.0
        report.fp_rate_after = min(0.95, max(0.0, last_mid))
        report.execution_time_ms = (time.time() - t0) * 1000

        return report

    # Phase implementations (delegated to fp_filter_phases)

    def _phase_allocator_semantics(self, candidates: list) -> Tuple[list, FilterStage]:
        """Phase 0: 分配器语义过滤."""
        from analysis.fp_filter_phases import phase_allocator_semantics
        return phase_allocator_semantics(candidates, platform=self._platform)

    def _phase_path_constraints(
        self, candidates: list, pseudocode: str,
    ) -> Tuple[list, FilterStage, Dict[str, List[Any]]]:
        """Phase 1: 路径约束收集."""
        from analysis.fp_filter_phases import phase_path_constraints
        return phase_path_constraints(
            candidates, pseudocode=pseudocode, platform=self._platform)

    def _phase_heap_layout(
        self, candidates: list, pseudocode: str,
    ) -> Tuple[list, FilterStage]:
        """Phase 2: 堆布局推断."""
        from analysis.fp_filter_phases_late import phase_heap_layout
        return phase_heap_layout(candidates, pseudocode=pseudocode, platform=self._platform)

    def _phase_z3_prove(
        self, candidates: list, constraints_map: Dict[str, List[Any]],
    ) -> Tuple[list, FilterStage]:
        """Phase 3: Z3 约束证明."""
        from analysis.fp_filter_phases_late import phase_z3_prove
        return phase_z3_prove(
            candidates, constraints_map=constraints_map, platform=self._platform)

    def _phase_strided_interval(
        self, candidates: list, ir_lines: List[str],
    ) -> Tuple[list, FilterStage]:
        """Phase 4: Strided Interval 验证."""
        from analysis.fp_filter_phases_late import phase_strided_interval
        return phase_strided_interval(
            candidates, ir_lines=ir_lines, platform=self._platform)

    # 辅助方法

    @staticmethod
    def _estimates(candidates: list) -> float:
        """估计候选列表中的平均误报概率."""
        if not candidates:
            return 0.0
        total = 0.0
        for c in candidates:
            conf = getattr(c, 'confidence', 0.5)
            total += 1.0 - conf
        return total / len(candidates)


__all__ = ['FilterStage', 'FilterReport', 'UnifiedFPFilter']
