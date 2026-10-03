"""
三态判定引擎 — 汇合污点/守卫/边界证据, 输出 SAFE/POTENTIAL/OVERFLOW。

二值判定 (溢出/不溢出) 无法表达证据强度, 是误报与漏报的结构性
来源。本引擎把判定细化为三态:
  SAFE        — 写终点 ≤ 分配器可用空间, 且有守卫或常量证据 → 抑制告警
  OVERFLOW    — 写终点下界 > 可用空间, 证据充分 → 保留
  POTENTIAL   — 证据冲突或缺失 → 降置信度保留 (宁错杀不漏报)
置信度由证据链综合: 对齐松弛 + 守卫窄化 + 同源污点 各提供
一个抑制因子; 溢出幅度与污点等级提供一个增强因子。
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional

from .alloc_aware_allocator import AllocBound, AllocKind
from .alloc_aware_interval import Interval
from .alloc_aware_taint import TaintLevel, TaintFact


class Verdict(Enum):
    SAFE = 'SAFE'
    POTENTIAL = 'POTENTIAL'
    OVERFLOW = 'OVERFLOW'


@dataclass
class Evidence:
    """单条判定证据 — 供审计与论文复现."""
    kind: str            # allocator_relax / guard_narrow / same_source_taint
    detail: str


@dataclass
class VerdictResult:
    """一条写点的最终判定."""
    verdict: Verdict
    confidence: float
    write_interval: Interval
    usable: int
    evidence: List[Evidence] = field(default_factory=list)


@dataclass
class HfpFinding:
    """最终判定结果 (分配点 + 写点 + 三态 + 证据)."""
    alloc: 'object'
    write: 'object'
    verdict: Verdict
    confidence: float
    evidence: List[Evidence] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'alloc': {'var': self.alloc.var,
                      'kind': getattr(self.alloc.kind, 'value', ''),
                      'size_expr': self.alloc.size_expr},
            'write': {'base': self.write.base_var,
                      'offset': self.write.offset,
                      'write_lo': self.write.write_iv.lo,
                      'write_hi': self.write.write_iv.hi},
            'verdict': self.verdict.value,
            'confidence': self.confidence,
            'evidence': [e.detail for e in self.evidence],
        }


def _reduce_confidence(base: float, factors: List[float]) -> float:
    """多因子抑制: 各抑制因子相乘, 下界 0.05."""
    conf = base
    for f in factors:
        conf *= f
    return max(0.05, round(conf, 3))


def judge_write(
    alloc_bound: AllocBound,
    write_iv: Interval,
    offset: int,
    alloc_taint: Optional[TaintFact],
    write_taint: Optional[TaintFact],
) -> VerdictResult:
    """对单个写点做三态判定."""
    evidence: List[Evidence] = []
    usable = alloc_bound.usable if not alloc_bound.symbolic else 0

    # 起点: 溢出幅度越大置信度越高
    overflow = write_iv.lo + offset - usable
    base_conf = 0.92 if overflow > 64 else (0.80 if overflow > 8 else 0.70)

    # 证据1: 分配器对齐松弛 — 写终点落入 slack 内则显著抑制
    if not alloc_bound.symbolic:
        slack = usable - alloc_bound.requested
        if slack > 0 and write_iv.hi + offset <= usable:
            evidence.append(Evidence(
                'allocator_relax',
                f'usable={usable}B > requested={alloc_bound.requested}B '
                f'(slack={slack}B), write_end={write_iv.hi + offset}B'))
            base_conf *= 0.30

    # 证据2: 同源污点 — write_size 与 alloc_size 同源且无缩放差异
    if (alloc_taint is not None and write_taint is not None
            and alloc_taint.src_expr and alloc_taint.src_expr == write_taint.src_expr
            and alloc_taint.scale == write_taint.scale):
        evidence.append(Evidence(
            'same_source_taint',
            f'alloc/write 同源于 {alloc_taint.src_expr} (scale={alloc_taint.scale})'))
        base_conf *= 0.40

    # 证据3: 写区间上界受守卫约束 — 写终点明确 ≤ usable
    if not alloc_bound.symbolic and write_iv.hi + offset <= usable:
        evidence.append(Evidence(
            'guard_narrow',
            f'write_hi={write_iv.hi}B+off={offset}B <= usable={usable}B'))
        base_conf *= 0.25
    # 判定
    if alloc_bound.symbolic:
        # 符号分配: 同源不构成安全证据 — 分配大小本身不可解析,
        # 无法证明等大 (可能双双异常大或截断), 保守保留
        if (alloc_taint is not None and write_taint is not None
                and alloc_taint.src_expr == write_taint.src_expr
                and alloc_taint.scale == write_taint.scale):
            evidence.append(Evidence(
                'same_source_taint_symbolic',
                f'symbolic alloc/write 同源 {alloc_taint.src_expr}, '
                '不可证明等大'))
            return VerdictResult(Verdict.POTENTIAL, 0.55, write_iv, 0,
                                 evidence)
        # 写区间有界且可求值 → 降级保留
        if write_iv.hi != Interval.top().hi:
            return VerdictResult(Verdict.POTENTIAL, base_conf,
                                 write_iv, usable, evidence)
        return VerdictResult(Verdict.POTENTIAL, 0.55, write_iv, usable,
                             evidence)

    if write_iv.lo + offset > usable:
        verdict = Verdict.OVERFLOW
        conf = min(0.97, base_conf * (1.0 if overflow > 0 else 0.85))
    elif write_iv.hi + offset <= usable:
        verdict = Verdict.SAFE
        conf = max(0.05, base_conf)
    else:
        # 区间跨越边界: 证据支持安全则 POTENTIAL 降级, 否则保留
        verdict = Verdict.POTENTIAL
        conf = base_conf * 0.80

    return VerdictResult(verdict, round(conf, 3), write_iv, usable, evidence)


def suppress_safe(candidates: List, ir_lines: List) -> List:
    """对候选列表应用判定, 移除 SAFE 项, 重排置信度.

    兼容既有调用方 (heap_overflow_pipeline 风格): 候选对象需含
    alloc_site / overflow_store 属性。此为桥接函数, 内部用
    judge_write 的保守版本。
    """
    kept = []
    for c in candidates:
        bound = AllocBound(c.alloc_site.size_arg,
                           c.alloc_site.size_arg, False,
                           AllocKind.MALLOC)
        wlo = max(0, c.overflow_store.offset)
        whi = wlo + max(1, c.overflow_store.store_size)
        iv = Interval(wlo, whi)
        res = judge_write(bound, iv, c.overflow_store.offset,
                          None, None)
        if res.verdict == Verdict.SAFE:
            continue
        if res.verdict == Verdict.POTENTIAL:
            c.confidence = min(c.confidence, 0.45)
        else:
            c.confidence = max(c.confidence, res.confidence)
        c._verdict = res.verdict.value
        c._evidence = [e.detail for e in res.evidence]
        kept.append(c)
    return kept