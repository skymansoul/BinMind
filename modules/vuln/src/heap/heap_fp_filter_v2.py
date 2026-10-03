"""堆溢出误报过滤器 V2 — 三阶段管线: 污点分析 → 路径约束窄化 → 分配器模型.

创建: 2024-11-05
用途: 替代原有 controllability_filter 的纯模式匹配方案。
      三阶段串行过滤, 任一阶段证明"安全"即滤除该告警。

管线:
  Phase 1 (Taint): 操作数的污点追溯
    → 若偏移/大小**确定非用户可控** (编译期常量) → SAFE_FILTERED
    → 若偏移/大小**用户可控** → 进入 Phase 2
    → 保守: 不确定则进入 Phase 2

  Phase 2 (Path Narrowing): 路径条件对操作数值域的约束
    → 若路径条件能证明 offset + access_size ≤ usable_size → SAFE_FILTERED
    → 若路径条件证明 offset > usable_size → CONFIRMED_VULN
    → 否则 → 进入 Phase 3

  Phase 3 (Allocator): 分配器内部约束的最终判定
    → 若 offset + access_size ≤ usable_size (含padding) → SAFE_FILTERED
    → 结合 taint 置信度 + 约束置信度输出最终判定

与现有模块的关系:
  - controllability_filter: 保留但标记为 legacy [DEPRECATED-LEGACY]
  - constraint_simplifier: 保留, 本模块的 Phase 2 是它的超集
  - allocator_model: 不变, Phase 3 复用

设计决策:
  - 三阶段而非统一评分: 统一的加权评分需要调参, 不可解释。
    三阶段串行给出明确的"为什么过滤"的理由, 便于审计和论文评估。
  - Phase 1 放最前: 污点分析最便宜 (多数场景 O(depth))。
    若已确定非常量 → 直接过滤, 不浪费 Phase 2/3 的算力。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    from .taint_propagation import (
        SparseTaintEngine, TaintStatus, TaintLabel, TaintSourceType)
    from .path_value_narrowing import (
        PathValueNarrower, ValueRange, ComparisonOp)
    from .allocator_model import Ptmalloc2Model
    from .filter_types import FilterPhase, FilterDecision, FilterResult
except ImportError:
    from taint_propagation import (  # type: ignore[no-redef]
        SparseTaintEngine, TaintStatus, TaintLabel, TaintSourceType)
    from path_value_narrowing import (  # type: ignore[no-redef]
        PathValueNarrower, ValueRange, ComparisonOp)
    from allocator_model import Ptmalloc2Model  # type: ignore[no-redef]
    from filter_types import (  # type: ignore[no-redef]
        FilterPhase, FilterDecision, FilterResult)


class HeapFPFilterV2:
    """堆溢出误报过滤器 V2.

    使用方式:
      filter_v2 = HeapFPFilterV2()
      filter_v2.register_taint_source(0x401000, 'scanf', TaintSourceType.USER_INPUT)

      # 添加数据流边 (从反汇编的 def-use 链)
      filter_v2.taint_engine.add_dataflow_edge(
          'rsi@401000', 'rax@401010', 'mov')

      # 添加分支约束
      filter_v2.path_narrower.add_branch_constraint(
          0x401005, 'rax', ComparisonOp.LT, 256, True)

      # 判定
      result = filter_v2.evaluate(
          insn_addr=0x401020, offset_reg='rax',
          offset_value=200, alloc_size=128, access_size=4)
    """

    def __init__(self):
        self.taint_engine = SparseTaintEngine()
        self.path_narrower = PathValueNarrower()
        self.alloc_model = Ptmalloc2Model()

        # 统计
        self._phase_stats = {
            'phase1_filtered': 0, 'phase2_filtered': 0,
            'phase3_filtered': 0, 'confirmed': 0,
            'uncertain': 0, 'inconclusive': 0, 'total': 0}

# 便捷注册

    def register_taint_source(self, insn_addr: int, func_name: str,
                               source_type: TaintSourceType,
                               arg_index: int = 0) -> str:
        """注册污点源."""
        return self.taint_engine.register_source(
            insn_addr, func_name, source_type, 0.90, arg_index)

    def add_dataflow(self, src_loc: str, dst_loc: str,
                     op_type: str = 'mov') -> None:
        """添加数据流边."""
        self.taint_engine.add_dataflow_edge(src_loc, dst_loc, op_type)

    def add_branch_constraint(self, insn_addr: int, register: str,
                               op: ComparisonOp, bound: int,
                               taken: bool = True) -> None:
        """添加上下文约束."""
        self.path_narrower.add_branch_constraint(
            insn_addr, register, op, bound, taken)

    def add_cfg_edge(self, src: int, dst: int) -> None:
        """添加控制流边."""
        self.path_narrower.set_cfg_edge(src, dst)

# 核心判定

    def evaluate(self, insn_addr: int, offset_reg: str,
                 offset_value: int, alloc_size: int,
                 access_size: int = 4,
                 func_name: str = '',
                 max_taint_depth: int = 8,
                 max_path_depth: int = 15) -> FilterResult:
        """三阶段判定管线."""
        self._phase_stats['total'] += 1
        fid = f"{func_name}@{insn_addr:#x}"

# Phase 1: Taint
        loc_key = f"{offset_reg}@{insn_addr:x}"
        taint_label = self.taint_engine.query_taint(
            loc_key, max_depth=max_taint_depth)

        # 若确定非常量且污点置信度很低 → 编译器生成, 安全
        if (taint_label.status == TaintStatus.UNTAINTED
                and taint_label.confidence > 0.75):
            self._phase_stats['phase1_filtered'] += 1
            return FilterResult(
                finding_id=fid, decision=FilterDecision.SAFE_FILTERED,
                decisive_phase=FilterPhase.PHASE1_TAINT,
                taint_label=taint_label,
                offset_value=offset_value, access_size=access_size,
                alloc_usable=alloc_size,
                reasoning=(f'phase1-taint: {offset_reg} confirmed '
                           f'untainted (conf={taint_label.confidence:.2f})'),
                fp_probability=0.95)

# Phase 2: Path Narrowing
        narrowed = self.path_narrower.compute_value_range(
            insn_addr, offset_reg, max_path_depth)

        ub = narrowed.upper_bound()
        if ub is not None:
            # 路径条件证明安全
            if ub + access_size <= alloc_size:
                self._phase_stats['phase2_filtered'] += 1
                return FilterResult(
                    finding_id=fid,
                    decision=FilterDecision.SAFE_FILTERED,
                    decisive_phase=FilterPhase.PHASE2_PATH,
                    taint_label=taint_label, narrowed_range=narrowed,
                    offset_value=offset_value, access_size=access_size,
                    alloc_usable=alloc_size,
                    reasoning=(f'phase2-path: narrowed range {narrowed} '
                               f'+ {access_size} ≤ {alloc_size}'),
                    fp_probability=0.90)

            # 路径条件证明溢出
            if narrowed.lo > alloc_size:
                self._phase_stats['confirmed'] += 1
                return FilterResult(
                    finding_id=fid,
                    decision=FilterDecision.CONFIRMED_VULN,
                    decisive_phase=FilterPhase.PHASE2_PATH,
                    taint_label=taint_label, narrowed_range=narrowed,
                    offset_value=offset_value, access_size=access_size,
                    alloc_usable=alloc_size,
                    reasoning=(f'phase2-path: narrowed range {narrowed} '
                               f'exceeds alloc {alloc_size}'),
                    fp_probability=0.05)

# Phase 3: Allocator Model
        constraint = self.alloc_model.model_alloc(alloc_size)
        usable = constraint.usable_size

        # padding 区访问: offset 在 [requested, usable) → 编译器合法
        if (offset_value >= alloc_size
                and offset_value + access_size <= usable):
            self._phase_stats['phase3_filtered'] += 1
            return FilterResult(
                finding_id=fid, decision=FilterDecision.SAFE_FILTERED,
                decisive_phase=FilterPhase.PHASE3_ALLOC,
                taint_label=taint_label,
                offset_value=offset_value, access_size=access_size,
                alloc_usable=usable,
                reasoning=(f'phase3-alloc: offset {offset_value} in '
                           f'padding [{alloc_size}, {usable})'),
                fp_probability=0.85)

        # 结合 taint 和 allocator 信息做最终判定
        if taint_label.is_tainted and offset_value + access_size > usable:
            self._phase_stats['confirmed'] += 1
            return FilterResult(
                finding_id=fid,
                decision=FilterDecision.CONFIRMED_VULN,
                decisive_phase=FilterPhase.PHASE3_ALLOC,
                taint_label=taint_label,
                offset_value=offset_value, access_size=access_size,
                alloc_usable=usable,
                reasoning=(f'Tainted {offset_reg} with offset {offset_value}'
                           f'+{access_size} exceeds usable {usable}'),
                fp_probability=0.10)

        # 无法确定 → 保守保留
        self._phase_stats['uncertain'] += 1
        return FilterResult(
            finding_id=fid, decision=FilterDecision.UNCERTAIN,
            decisive_phase=FilterPhase.PHASE3_ALLOC,
            taint_label=taint_label,
            offset_value=offset_value, access_size=access_size,
            alloc_usable=usable,
            reasoning=(f'Uncertain: taint={taint_label.status.value}, '
                       f'offset={offset_value}+{access_size}, usable={usable}'),
            fp_probability=0.40)  # 不确定场景, 保守估计 40% 是误报

# 批量过滤

    def filter_findings(self,
                         findings: List[dict]
                         ) -> Tuple[List[dict], List[FilterResult]]:
        """对一批检测发现做批量过滤.

        返回 (保留的告警, 所有过滤结果)。
        """
        retained = []
        all_results = []

        for f in findings:
            result = self.evaluate(
                insn_addr=f.get('insn_addr', 0),
                offset_reg=f.get('offset_reg', ''),
                offset_value=f.get('offset_value', 0),
                alloc_size=f.get('alloc_size', 0),
                access_size=f.get('access_size', 4),
                func_name=f.get('func_name', ''))

            all_results.append(result)

            if result.decision in (FilterDecision.CONFIRMED_VULN,
                                   FilterDecision.LIKELY_VULN,
                                   FilterDecision.UNCERTAIN):
                retained.append(f)

        return retained, all_results

    def stats(self) -> dict:
        total = max(1, self._phase_stats['total'])
        return {
            'total_evaluated': self._phase_stats['total'],
            'phase1_filtered': self._phase_stats['phase1_filtered'],
            'phase2_filtered': self._phase_stats['phase2_filtered'],
            'phase3_filtered': self._phase_stats['phase3_filtered'],
            'total_filtered': (self._phase_stats['phase1_filtered'] +
                               self._phase_stats['phase2_filtered'] +
                               self._phase_stats['phase3_filtered']),
            'confirmed': self._phase_stats['confirmed'],
            'uncertain': self._phase_stats['uncertain'],
            'filter_rate': (
                (self._phase_stats['phase1_filtered'] +
                 self._phase_stats['phase2_filtered'] +
                 self._phase_stats['phase3_filtered']) / total),
            'taint_stats': self.taint_engine.stats(),
            'path_stats': self.path_narrower.stats(),
            'alloc_stats': self.alloc_model.stats(),
        }

    def clear(self) -> None:
        self.taint_engine.clear()
        self.path_narrower.clear()
        self.alloc_model.clear()
        for k in self._phase_stats:
            self._phase_stats[k] = 0
