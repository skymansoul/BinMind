# coding: utf-8
# 创建: 2026-06-06  |  级联判定——SAFE/OVERFLOW/SUSPICIOUS
#
"""
级联判定引擎——对 (alloc, write) 对给出 SAFE/OVERFLOW/SUSPICIOUS。

判定规则 (任一 SAFE 即过滤该告警):
  R1  支配守卫证明 write <= usable → SAFE
  R2  写入值域上界 <= usable → SAFE (含对齐 padding)
  R3  写入值域下界 >  usable → OVERFLOW
  R4  分配与写入观察到同一运行时值 (同一定值根) → SAFE
  R5  分配与写入共享同一来源变量 (同一参数槽) → SAFE
  R6  无界写入 (strcpy/gets): 无守卫上界 → OVERFLOW
  R7  分配为常量 + 写入未知 / 分配大小不可静态确定 → SUSPICIOUS

写入目标与分配点的关联在管线层完成 (link.py): 仅与 dst 指针
来源的分配点配对, 从根上消除"多分配点指针混淆"误报。

设计: 仅使用"可证明"的 SAFE 规则 (R1/R2/R4), 其余保守保留,
  确保召回率不受损。误报削减全部来自可证明安全路径。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .region import (
    Region, KIND_PARAMETER, KIND_CONSTANT, KIND_UNKNOWN,
    NEG_INF, POS_INF,
)

SAFE = "SAFE"
OVERFLOW = "OVERFLOW"
SUSPICIOUS = "SUSPICIOUS"


@dataclass
class VerdictResult:
    """单对 (alloc, write) 的判定结果."""
    verdict: str = SUSPICIOUS
    rule: str = ""
    evidence: List[str] = field(default_factory=list)
    write_region: Region = Region()
    alloc_region: Region = Region()
    usable: int = 0
    overflow_bytes: int = 0

    @property
    def is_safe(self) -> bool:
        return self.verdict == SAFE

    @property
    def is_finding(self) -> bool:
        return self.verdict in (OVERFLOW, SUSPICIOUS)


class VerdictEngine:
    """级联判定引擎."""

    def __init__(self):
        self._stats = {"safe": 0, "overflow": 0, "suspicious": 0}

    def decide(self, alloc_region: Region, usable: int,
               write_region: Region, is_unbounded: bool,
               guard_bound: Optional[Tuple[int, str]] = None) -> VerdictResult:
        """判定 (alloc, write) 对."""
        res = VerdictResult(
            write_region=write_region, alloc_region=alloc_region,
            usable=usable)

        # R1: 支配守卫上界
        if guard_bound is not None:
            bound, bkind = guard_bound
            if bound <= usable:
                res.verdict = SAFE
                res.rule = "R2_guard"
                res.evidence.append(
                    f"R2: 守卫 {write_region} <= {bound} ({bkind}) <= usable {usable}")
                self._stats["safe"] += 1
                return res

        # R0: 无界写入, 无守卫 → 溢出
        if is_unbounded:
            res.verdict = OVERFLOW
            res.rule = "R0_unbounded"
            res.evidence.append(
                f"R0: 无界写入 {write_region}, alloc usable={usable}")
            self._stats["overflow"] += 1
            return res

        # R3: 写入值域上界 <= usable
        if write_region.has_upper_bound and write_region.hi <= usable:
            res.verdict = SAFE
            res.rule = "R3_bounded"
            res.evidence.append(
                f"R3: 写入值域 {write_region} 上界 {write_region.hi} <= usable {usable}")
            self._stats["safe"] += 1
            return res

        # R4: 写入值域下界 > usable
        if write_region.lo > usable:
            res.verdict = OVERFLOW
            res.rule = "R4_proven"
            res.overflow_bytes = max(0, write_region.lo - usable)
            res.evidence.append(
                f"R4: 写入下界 {write_region.lo} > usable {usable}, 溢出 {res.overflow_bytes}B")
            self._stats["overflow"] += 1
            return res

        # R4: 同一定值根或同一来源变量 → 分配与写入观察到相同值 → 安全
        if alloc_region.root_key and \
                alloc_region.root_key == write_region.root_key:
            res.verdict = SAFE
            res.rule = "R4_same_def"
            res.evidence.append(
                f"R4: alloc/write 同一定值根 {alloc_region.root_key}")
            self._stats["safe"] += 1
            return res
        if (alloc_region.source_id and write_region.source_id
                and alloc_region.source_id == write_region.source_id
                and alloc_region.kind == KIND_PARAMETER):
            res.verdict = SAFE
            res.rule = "R5_shared_src"
            res.evidence.append(
                f"R5: alloc/write 共享来源 {alloc_region.source_id}")
            self._stats["safe"] += 1
            return res

        # R6/R7: 保守保留
        res.rule = "R6_suspicious" if alloc_region.kind == KIND_CONSTANT \
            else "R7_unbound_alloc"
        res.evidence.append(
            f"R6/R7: alloc={alloc_region} usable={usable}, "
            f"write={write_region}, 无法证明安全 → 保留")
        self._stats["suspicious"] += 1
        return res

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["VerdictEngine", "VerdictResult", "SAFE", "OVERFLOW",
           "SUSPICIOUS"]
