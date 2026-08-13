"""增强型误报过滤器 — 五维联合过滤管线.

创建: 2024-12-09
用途: 这是堆溢出检测误报过滤的"集成管线"——将五个分析维度
      (分配器语义 + 可控性 + 路径约束 + 循环边界 + 过程间上下文)
      串接为统一的过滤决议。

管线流程:
  原始告警 → 维度1(分配器语义) → 维度2(可控性分析) →
  维度3(路径约束) → 维度4(循环边界) → 维度5(过程间上下文) →
  最终决议: SAFE(可过滤) | SUSPICIOUS(保留) | CONFIRMED(高置信告警)

设计原则:
  - 短路求值: 任一维度证明SAFE → 立即过滤, 不检查后续维度
  - 保守放行: 所有维度都是 UNCERTAIN → 保留告警 (宁可误报不漏报)
  - 增量精度: 前序维度先做快检查, 后序维度做深分析
    分配器/可控性 O(1), 路径约束 O(|constraints|), 循环 O(|loops|)

与现有模块集成:
  - 输入来自 HeapOverflowDetector 的发现列表
  - 使用 Ptmalloc2Model 做分配器语义检查
  - 使用 ControllabilityFilter 做可控性分析
  - 新增: 使用 LinearConstraintEngine + PathConditionCollector +
    LoopIntervalAnalyzer + InterprocContextTracker 做深度分析
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple
from enum import Enum


class FilterVerdict(Enum):
    FILTER_SAFE = "filter_safe"           # 可证明安全, 过滤
    RETAIN_SUSPICIOUS = "retain_suspicious"  # 无法证明安全, 保留
    RETAIN_CONFIRMED = "retain_confirmed"    # 高置信度告警


@dataclass
class FilteredFinding:
    """经过过滤的发现."""
    original: dict                    # 原始发现 (来自 HeapOverflowDetector)
    verdict: FilterVerdict
    filtering_dimension: str          # 哪个维度触发了过滤/保留
    evidence: str                     # 判定理由
    original_confidence: float = 0.5
    adjusted_confidence: float = 0.5

    @property
    def is_filtered(self) -> bool:
        return self.verdict == FilterVerdict.FILTER_SAFE


@dataclass
class FilterReport:
    """一次过滤运行的完整报告."""
    total_raw: int = 0
    filtered_safe: int = 0
    retained_suspicious: int = 0
    retained_confirmed: int = 0
    fp_reduction_pct: float = 0.0
    by_dimension: Dict[str, int] = field(default_factory=dict)
    findings: List[FilteredFinding] = field(default_factory=list)


class EnhancedFPFilter:
    """五维联合误报过滤器.

    使用方式:
      ef = EnhancedFPFilter()
      report = ef.filter(raw_findings, alloc_info, cs_map, loop_map, ic_tracker)
      print(f"FP reduced by {report.fp_reduction_pct:.1f}%")
    """

    def __init__(self):
        from .allocator_model import Ptmalloc2Model
        from .controllability_filter import ControllabilityFilter
        from .safety_prover import SafetyProver
        self._alloc_model = Ptmalloc2Model()
        self._ctrl_filter = ControllabilityFilter()
        self._safety_prover = SafetyProver()

    def filter(self, raw_findings: List[dict],
               alloc_info: Dict[int, Tuple[int, str]] = None,
               constraint_sets: Dict[int, any] = None,
               loop_summaries: Dict[int, any] = None,
               ic_tracker: any = None) -> FilterReport:
        """执行五维联合过滤.

        raw_findings: 来自 HeapOverflowDetector.detect() 的发现列表
        alloc_info: {insn_addr: (alloc_size, ptr_reg)}
        constraint_sets: {insn_addr: ConstraintSet}  (可选)
        loop_summaries: {loop_addr: LoopSummary}     (可选)
        ic_tracker: InterprocContextTracker 实例     (可选)
        """
        if alloc_info is None:
            alloc_info = {}
        if constraint_sets is None:
            constraint_sets = {}
        if loop_summaries is None:
            loop_summaries = {}
        report = FilterReport(total_raw=len(raw_findings))
        report.by_dimension = {
            'allocator': 0, 'controllability': 0,
            'path_constraint': 0, 'loop_bound': 0,
            'interproc': 0}

        for finding in raw_findings:
            filtered = self._filter_one(
                finding, alloc_info, constraint_sets,
                loop_summaries, ic_tracker, report.by_dimension)
            report.findings.append(filtered)

            if filtered.is_filtered:
                report.filtered_safe += 1
            elif filtered.verdict == FilterVerdict.RETAIN_CONFIRMED:
                report.retained_confirmed += 1
            else:
                report.retained_suspicious += 1

        if report.total_raw > 0:
            report.fp_reduction_pct = round(
                report.filtered_safe / report.total_raw * 100, 1)

        return report

    def _filter_one(self, finding: dict, alloc_info: dict,
                    constraint_sets: dict, loop_summaries: dict,
                    ic_tracker, dim_counts: dict) -> FilteredFinding:
        """对单个发现执行五维过滤."""
        offset = finding.get('offset', 0)
        if isinstance(offset, str):
            try:
                offset = int(offset, 0)
            except ValueError:
                offset = 256  # 保守假设大偏移

        alloc_size = finding.get('allocated_size', 0)
        access_size = finding.get('access_size', 4)
        insn_addr = finding.get('insn_addr', 0)
        ptr_var = finding.get('ptr_register', '')
        func_name = finding.get('function_name', '')
        orig_conf = finding.get('confidence', 0.5)

        # 维度1: 分配器语义 (O(1), 最快)
        constraint = self._alloc_model.model_alloc(alloc_size)
        if offset + access_size <= constraint.usable_size:
            dim_counts['allocator'] += 1
            return FilteredFinding(
                original=finding, verdict=FilterVerdict.FILTER_SAFE,
                filtering_dimension='allocator',
                evidence=f'usable_size={constraint.usable_size} >= {offset}+{access_size}',
                original_confidence=orig_conf, adjusted_confidence=0.0)

        # 维度2: 可控性分析 (O(1), 模式匹配)
        if isinstance(finding.get('user_controlled'), bool):
            user_ctrl = finding['user_controlled']
            if not user_ctrl:
                dim_counts['controllability'] += 1
                return FilteredFinding(
                    original=finding, verdict=FilterVerdict.FILTER_SAFE,
                    filtering_dimension='controllability',
                    evidence='offset is constant, not user-controlled',
                    original_confidence=orig_conf, adjusted_confidence=0.0)

        # 维度3: 路径约束 (O(|constraints|))
        cs = constraint_sets.get(insn_addr) if constraint_sets else None
        if cs is not None and ptr_var:
            from .linear_constraint import LinearConstraintEngine
            engine = LinearConstraintEngine()
            if engine.prove_access_safe(cs, ptr_var, offset,
                                        alloc_size, access_size):
                dim_counts['path_constraint'] += 1
                return FilteredFinding(
                    original=finding, verdict=FilterVerdict.FILTER_SAFE,
                    filtering_dimension='path_constraint',
                    evidence=f'{ptr_var} constrained by path conditions to ≤ {alloc_size}',
                    original_confidence=orig_conf, adjusted_confidence=0.0)

        # 维度4: 循环边界 (O(|loops|))
        loop = loop_summaries.get(insn_addr) if loop_summaries else None
        if loop is not None:
            from .loop_interval import LoopClass
            if loop.loop_class == LoopClass.BOUNDED:
                if loop.max_iterations <= alloc_size:
                    dim_counts['loop_bound'] += 1
                    return FilteredFinding(
                        original=finding, verdict=FilterVerdict.FILTER_SAFE,
                        filtering_dimension='loop_bound',
                        evidence=f'loop bounded to {loop.max_iterations} ≤ {alloc_size}',
                        original_confidence=orig_conf, adjusted_confidence=0.0)

        # 维度5: 过程间上下文 (O(|contexts|))
        if ic_tracker is not None and func_name:
            # 尝试从过程间上下文获取参数约束
            for param_idx in range(4):  # 检查前4个参数
                bound = ic_tracker.get_arg_bound(func_name, param_idx)
                if bound is not None:
                    _, hi = bound
                    if hi <= alloc_size:
                        dim_counts['interproc'] += 1
                        return FilteredFinding(
                            original=finding,
                            verdict=FilterVerdict.FILTER_SAFE,
                            filtering_dimension='interproc',
                            evidence=f'caller constrains arg{param_idx} ≤ {hi} ≤ {alloc_size}',
                            original_confidence=orig_conf,
                            adjusted_confidence=0.0)

        # 所有维度都无法证明安全 → 保留
        # 若有部分证据支持溢出 → 升高置信度
        adjusted_conf = orig_conf
        verdict = FilterVerdict.RETAIN_SUSPICIOUS
        if offset > constraint.usable_size * 2:
            verdict = FilterVerdict.RETAIN_CONFIRMED
            adjusted_conf = min(0.95, orig_conf + 0.2)

        return FilteredFinding(
            original=finding, verdict=verdict,
            filtering_dimension='none',
            evidence='cannot prove safe across any dimension',
            original_confidence=orig_conf,
            adjusted_confidence=adjusted_conf)

    def stats(self) -> dict:
        return {
            'alloc_model': self._alloc_model.stats(),
            'ctrl_filter': self._ctrl_filter.stats(),
            'safety_prover': self._safety_prover.stats(),
        }
