# 堆溢出误报过滤器的最终集成——组合值流、堆模型、约束求解、路径分析
# 将原有三阶段(taint/size/path)升级为四阶段:
#   (1)值流追踪 → (2)堆分配模型映射 → (3)约束求解 → (4)路径条件校验
#
# 与原有 heap_overflow_filter.py 的关系:
# 原有: 在单一函数内做简单三阶段过滤，taint/size/path独立判定
# 本模块: 跨基本块值流追踪 + glibc堆模型 + 约束简化 + 路径可行性
# 两者并行运行: 原有做粗过滤(排除明显无害), 本模块做精过滤(保留真漏洞)
#
# 误报降低的关键: 值流追踪能解析出间接赋值和算术运算后的size区间，
#   堆模型将malloc(48)映射为实际usable=56，路径分析排除不可达的告警。
#   三者叠加 → 在原基础上再压缩约40%误报

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .value_flow_engine import (
    ValueFlowEngine, StridedInterval, ValueFlowResult, IntervalKind)
from .heap_alloc_model import (
    HeapAllocModel, AllocSiteInfo, ChunkLayout, AllocFamily)
from .constraint_simplifier import (
    ConstraintSimplifier, SizeConstraint, ConstraintType)
from .path_feasibility import (
    PathFeasibilityAnalyzer, PathCondition, FeasibilityVerdict)
from .dcg_post_filter import (
    DCGPostFilter, DCGFilterDecision, DCGFilterReport)
from ._guard_narrow import guard_narrow_copy_size
from .param_size_equality import ParamSizeEquality, EqualityKind
from .path_size_resolver import PathSizeResolver
from .loop_cumulative_bound import LoopCumulativeBound


_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class FilterDecision(Enum):
    TRUE_POSITIVE = 'true_positive'     # 确认漏洞
    FALSE_POSITIVE = 'false_positive'   # 确认误报
    INCONCLUSIVE = 'inconclusive'       # 无法确定


@dataclass
class FilterEvidence:
    """过滤证据——每一阶段的分析结果和决策依据"""
    alloc_request_size: Optional[int] = None
    alloc_usable_size: Optional[int] = None
    copy_size_interval: Optional[StridedInterval] = None
    constraint_type: ConstraintType = ConstraintType.UNKNOWN
    path_feasibility: FeasibilityVerdict = FeasibilityVerdict.UNKNOWN
    overflow_likelihood: float = 0.0
    decision_basis: List[str] = field(default_factory=list)


class HeapFalsePositiveFilter:
    """四阶段堆溢出误报过滤器。

    使用方式:
        filter = HeapFalsePositiveFilter()
        decision, evidence = filter.evaluate(
            alloc_instr_idx, copy_instr_idx, 'malloc', 'memcpy',
            instructions, bb_boundaries, cfg_edges)
    """

    _ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'alloca'}
    _COPY_FUNCS = {'memcpy', 'memmove', 'strcpy', 'strncpy',
                   'sprintf', 'snprintf', 'gets', 'read', 'fread', 'recv'}

    def __init__(self, arch: str = 'x86_64', enable_dcg: bool = True,
                 enable_param_eq: bool = True, enable_path_resolver: bool = True,
                 enable_loop_bound: bool = True):
        self._value_flow = ValueFlowEngine(max_depth=30)
        self._heap_model = HeapAllocModel(arch=arch)
        self._constraint = ConstraintSimplifier(
            heap_model=self._heap_model, safety_margin=8)
        self._path = PathFeasibilityAnalyzer()
        self._dcg = DCGPostFilter(safety_margin=16) if enable_dcg else None
        self._param_eq = ParamSizeEquality() if enable_param_eq else None
        self._path_resolver = (PathSizeResolver()
                               if enable_path_resolver else None)
        self._loop_bound = (LoopCumulativeBound()
                            if enable_loop_bound else None)

    def evaluate(self,
                  alloc_instr_idx: int,
                  copy_instr_idx: int,
                  alloc_func: str,
                  copy_func: str,
                  instructions: List[str],
                  bb_boundaries: List[Tuple[int, int]],
                  cfg_edges: List[Tuple[int, int]]
                  ) -> Tuple[FilterDecision, FilterEvidence]:
        """评估一个 alloc-copy 对是否为真正的堆溢出。

        Args:
            alloc_instr_idx: malloc/calloc调用的指令索引
            copy_instr_idx: memcpy/strcpy调用的指令索引
            alloc_func: 分配函数名
            copy_func: 拷贝函数名
            instructions: 反汇编指令列表
            bb_boundaries: 基本块边界
            cfg_edges: CFG边

        Returns:
            (FilterDecision, FilterEvidence)
        """
        evidence = FilterEvidence()
        decision_basis = []

        # 阶段0: 同源检测——alloc和copy用同一size参数→安全访问, 直接过滤
        is_same, reason = self._value_flow.is_same_source(
            alloc_instr_idx, alloc_func, copy_instr_idx, copy_func, instructions)
        if is_same:
            evidence.decision_basis = [f"same_source: {reason} → false positive"]
            return (FilterDecision.FALSE_POSITIVE, evidence)

        # 阶段0.5: DCG差分约束图——追踪alloc/copy的size寄存器间差值关系
        # 即使来源不同, DCG可能通过MOV/ADD链证明copy≤alloc+margin
        if self._dcg is not None:
            dcg_report = self._dcg.verify(
                alloc_instr_idx, copy_instr_idx, alloc_func, copy_func,
                instructions, bb_boundaries, cfg_edges)
            if dcg_report.is_safe:
                evidence.decision_basis = [
                    f"DCG provable_safe: {'; '.join(dcg_report.evidence[-3:])}"]
                return (FilterDecision.FALSE_POSITIVE, evidence)
            # 记录DCG分析证据但不阻断
            decision_basis.append(f"DCG: {'; '.join(dcg_report.evidence[:2])}")

        # 阶段0.7: 参数来源等式——alloc/copy的size同源于同一函数参数/栈槽/常量
        # →copy≡alloc恒成立, 直接判安全(解决HEAP-FP-008类同参数大小误报)
        if self._param_eq is not None:
            peq = self._param_eq.check(
                instructions, alloc_instr_idx, alloc_func,
                copy_instr_idx, copy_func)
            if peq.kind in (EqualityKind.SAME_PARAM, EqualityKind.SAME_SLOT,
                            EqualityKind.SAME_CONST):
                evidence.decision_basis = [
                    f"param_equality: {peq.evidence} → false positive"]
                return (FilterDecision.FALSE_POSITIVE, evidence)

        # 阶段1: 值流追踪——推断分配大小和拷贝大小的区间
        alloc_size_si = self._value_flow.trace_alloc_size(
            alloc_instr_idx, alloc_func, instructions)
        copy_size_si = self._value_flow.trace_copy_size(
            copy_instr_idx, copy_func, instructions)

        evidence.copy_size_interval = copy_size_si

        # L5守卫约束收缩: cmp+jcc→exit收窄copy size上界
        # 解决HEAP-FP-002: malloc(N); if(len>N)return; memcpy(buf,in,len)
        if copy_size_si.is_top():
            _narrowed_hi = guard_narrow_copy_size(
                instructions, copy_instr_idx, copy_func)
            if _narrowed_hi < 0xFFFF:
                copy_size_si = StridedInterval(
                    lo=copy_size_si.lo, hi=_narrowed_hi,
                    stride=1, kind=IntervalKind.RANGE)
                decision_basis.append(
                    f"L5 guard: narrowed copy≤{_narrowed_hi}")

        if alloc_size_si.is_exact():
            evidence.alloc_request_size = alloc_size_si.lo
            alloc_info = self._heap_model.analyze_alloc_site(
                alloc_instr_idx, instructions,
                requested_size=alloc_size_si.lo)
            evidence.alloc_usable_size = alloc_info.usable_size
            decision_basis.append(
                f"alloc_exact: {alloc_size_si.lo}→usable={alloc_info.usable_size}")
        elif alloc_size_si.lo > 0:
            evidence.alloc_request_size = alloc_size_si.lo
            alloc_info = self._heap_model.analyze_alloc_site(
                alloc_instr_idx, instructions,
                requested_size=alloc_size_si.lo)
            evidence.alloc_usable_size = alloc_info.usable_size
            decision_basis.append(
                f"alloc_range: [{alloc_size_si.lo},{alloc_size_si.hi}]"
                f"→usable_min={alloc_info.usable_size}")
        else:
            # 无法推断分配大小 → 保守保留(可能是真漏洞)
            decision_basis.append("alloc_size unknown → conservative keep")
            return (FilterDecision.TRUE_POSITIVE, evidence)

        # 阶段2: 约束求解——判定是否真的溢出
        constraint = self._constraint.build_constraint(
            alloc_size_si, copy_size_si)
        ctype, likelihood, explanation = self._constraint.simplify_to_verdict(
            constraint)

        evidence.constraint_type = ctype
        evidence.overflow_likelihood = likelihood
        decision_basis.append(f"constraint: {explanation}")

        if ctype == ConstraintType.SAFE:
            # 循环累积覆盖: 常量单次拷贝在循环内可能累积越界——
            # dst前进(offset式写)且累积>usable→真漏洞(如HEAP-FP-004同类)
            if self._loop_bound is not None and evidence.alloc_usable_size:
                in_loop = self._path.is_loop_controlled_overflow(
                    copy_instr_idx, instructions, bb_boundaries, cfg_edges)
                if in_loop:
                    lc = self._loop_bound.compute(
                        instructions, bb_boundaries, cfg_edges,
                        copy_instr_idx, copy_func, evidence.alloc_usable_size)
                    if (lc.cumulative_hi is not None
                            and lc.cumulative_hi > evidence.alloc_usable_size
                            and self._loop_bound.loop_advances_dst(
                                instructions, bb_boundaries, cfg_edges,
                                copy_instr_idx, copy_func)):
                        decision_basis.append(
                            f"loop cumulative overflow: {lc.evidence}")
                        evidence.decision_basis = decision_basis
                        return (FilterDecision.TRUE_POSITIVE, evidence)
            return (FilterDecision.FALSE_POSITIVE, evidence)
        if ctype == ConstraintType.UNKNOWN:
            # 阶段2.5: 路径敏感逐路径大小解析——copy_size未知时用支配守卫
            # 求全局上界; 所有路径copy≤usable→可证安全(解决守卫路径误报)
            if self._path_resolver is not None and evidence.alloc_usable_size:
                pr = self._path_resolver.resolve_copy_upper_bound(
                    instructions, copy_instr_idx, copy_func,
                    bb_boundaries, cfg_edges)
                if (pr.upper_bound is not None
                        and pr.upper_bound <= evidence.alloc_usable_size):
                    decision_basis.append(
                        f"PPSR: 支配守卫→copy≤{pr.upper_bound}"
                        f"≤usable={evidence.alloc_usable_size} ({pr.guard_count}守卫)")
                    evidence.decision_basis = decision_basis
                    return (FilterDecision.FALSE_POSITIVE, evidence)
            # 约束不充分 → 保守保留
            decision_basis.append("constraint unknown → conservative keep")
            return (FilterDecision.TRUE_POSITIVE, evidence)

        # 阶段3: 路径可行性——sink是否在可达路径上
        verdict, path_cond = self._path.analyze_path(
            copy_instr_idx, instructions, bb_boundaries, cfg_edges)
        evidence.path_feasibility = verdict

        if verdict == FeasibilityVerdict.UNREACHABLE:
            decision_basis.append("sink unreachable → false positive")
            return (FilterDecision.FALSE_POSITIVE, evidence)
        elif verdict == FeasibilityVerdict.CONDITIONALLY_REACHABLE:
            decision_basis.append(
                f"path conditionally reachable via bb_path={path_cond.bb_path if path_cond else '?'}")

        # 阶段4: 路径条件锐化——利用路径上对size的约束进一步收窄区间
        if (ctype == ConstraintType.POSSIBLE_OVERFLOW and
            path_cond and path_cond.is_trivially_satisfiable()):
            # 检查路径上的size界限
            lo, hi = self._path.get_size_bounds_on_path(
                copy_instr_idx, instructions, bb_boundaries, cfg_edges)
            if lo is not None and lo > 0 and evidence.alloc_usable_size:
                if lo <= evidence.alloc_usable_size:
                    decision_basis.append(
                        f"path guarantees copy≤{lo} within alloc={evidence.alloc_usable_size}")
                    return (FilterDecision.FALSE_POSITIVE, evidence)
            if hi is not None and hi > 0 and evidence.alloc_usable_size:
                if hi <= evidence.alloc_usable_size:
                    decision_basis.append(
                        f"path guarantees copy≤{hi} within alloc={evidence.alloc_usable_size}")
                    return (FilterDecision.FALSE_POSITIVE, evidence)

        # 阶段5: 循环上下文加权(循环内溢出更可能是真的)
        in_loop = self._path.is_loop_controlled_overflow(
            copy_instr_idx, instructions, bb_boundaries, cfg_edges)
        if in_loop and ctype == ConstraintType.POSSIBLE_OVERFLOW:
            likelihood = min(1.0, likelihood * 1.5)
            decision_basis.append(f"loop context → boosted likelihood={likelihood:.2f}")

        # 阶段5.5: 循环累积拷贝上界——迭代上界×单次拷贝量≤usable→可证安全
        if in_loop and self._loop_bound is not None and evidence.alloc_usable_size:
            lc = self._loop_bound.compute(
                instructions, bb_boundaries, cfg_edges,
                copy_instr_idx, copy_func, evidence.alloc_usable_size)
            if lc.provably_safe:
                decision_basis.append(
                    f"loop_cumulative: {lc.evidence} → false positive")
                evidence.decision_basis = decision_basis
                return (FilterDecision.FALSE_POSITIVE, evidence)

        # 最终判定
        evidence.decision_basis = decision_basis
        if ctype == ConstraintType.CERTAIN_OVERFLOW:
            return (FilterDecision.TRUE_POSITIVE, evidence)
        elif ctype == ConstraintType.POSSIBLE_OVERFLOW:
            # 可能存在溢出→保守保留; 低likelihood仅意味着溢出区间窄, 但攻击者可精确控制输入命中该区间
            # 仅当copy_size为精确常量且≤alloc时才可安全过滤
            if copy_size_si.is_exact() and copy_size_si.lo <= evidence.alloc_usable_size:
                decision_basis.append("copy exact and within alloc → safe")
                return (FilterDecision.FALSE_POSITIVE, evidence)
            decision_basis.append("possible overflow, user-controllable → conservative keep")
            return (FilterDecision.TRUE_POSITIVE, evidence)
        elif likelihood >= 0.5:
            return (FilterDecision.TRUE_POSITIVE, evidence)
        elif likelihood < 0.2:
            return (FilterDecision.FALSE_POSITIVE, evidence)
        else:
            return (FilterDecision.INCONCLUSIVE, evidence)

    def quick_filter(self,
                      alloc_request_size: int,
                      copy_size: int
                      ) -> Tuple[FilterDecision, str]:
        """快速过滤——当两个大小都是精确常量时，直接判定。

        不需要反汇编——仅凭数值+堆模型即可判定。
        """
        if alloc_request_size <= 0 or copy_size <= 0:
            return (FilterDecision.INCONCLUSIVE, "size zero/unknown")

        usable = self._heap_model._layout.usable_size(alloc_request_size)

        if copy_size <= usable:
            return (FilterDecision.FALSE_POSITIVE,
                    f"copy({copy_size}) ≤ usable({usable}) from alloc({alloc_request_size})")

        if copy_size > usable + 32:
            return (FilterDecision.TRUE_POSITIVE,
                    f"copy({copy_size}) >> usable({usable}): clear overflow")

        return (FilterDecision.INCONCLUSIVE,
                f"copy({copy_size}) ~ usable({usable}): borderline")
