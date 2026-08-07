# coding: utf-8
# 创建: 2026-06-24  |  UAF 生命周期与重分配感知判定
#
"""
生命周期时间线 + 重分配感知判定。

判定规则 (每个 free→use 对):
  R1  双方来源均未解析 → SUSPICIOUS (保守保留)
  R2  use 解析到不同对象 → SAFE (非同一对象, 非 UAF)
  R3  free 与 use 间发生同槽重分配 → SAFE (对象被 malloc 复用)
  R4  free 与 use 解析到同一对象且无重分配 → UAF
  R5  use 未解析但 free 已解析 → SUSPICIOUS (保守保留, 召回保障)

重分配检测 (R3): 在 (free_idx, use_idx) 窗口内, 若存在
  call <alloc>; mov [slot]/<reg>, rax
且槽/寄存器与 free 的来源键一致 → 该对象被复用, 旧指针悬垂但已换新对象。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from heapver.insn import Instruction, callee_name
from heapver.abi import find_alloc
from heapver.defuse import DefUseResolver
from heapver.link import DstAllocLinker

from .provenance import FreeSite, DerefSite

UAF = "UAF"
SAFE = "SAFE"
SUSPICIOUS = "SUSPICIOUS"


@dataclass
class UafPairVerdict:
    verdict: str = SUSPICIOUS
    rule: str = ""
    free_idx: int = -1
    use_idx: int = 0
    free_alloc: int = -1
    use_alloc: int = -1
    base_reg: str = ""
    evidence: List[str] = field(default_factory=list)
    func: str = ""

    @property
    def is_finding(self) -> bool:
        return self.verdict in (UAF, SUSPICIOUS)


class LifetimeVerifier:
    """生命周期时间线判定器."""

    def __init__(self):
        self._linker = DstAllocLinker()
        self._resolver = DefUseResolver()
        self._stats = {"uaf": 0, "safe": 0, "suspicious": 0}

    def decide(self, func: str, free: FreeSite, use: DerefSite,
               insns: List[Instruction]) -> UafPairVerdict:
        res = UafPairVerdict(free_idx=free.idx, use_idx=use.idx,
                             base_reg=use.base_reg, func=func,
                             free_alloc=free.alloc_idx,
                             use_alloc=use.alloc_idx)

        # R1: 双方均未解析 → 无法归因, 保守保留
        if not free.resolved and not use.resolved:
            res.verdict = SUSPICIOUS
            res.rule = "R1_both_unknown"
            res.evidence.append(
                "R1: free/use 来源均不可解析, 保守保留")
            self._stats["suspicious"] += 1
            return res

        # R5: use 未解析但 free 已解析 → 保守保留
        if free.resolved and not use.resolved:
            res.verdict = SUSPICIOUS
            res.rule = "R5_use_unknown"
            res.evidence.append(
                f"R5: free→obj@{free.alloc_idx} 已解析, use 未解析, 保守保留")
            self._stats["suspicious"] += 1
            return res

        if not free.resolved:
            res.verdict = SUSPICIOUS
            res.rule = "R5_free_unknown"
            res.evidence.append(
                f"R5: free 未解析, use→obj@{use.alloc_idx}, 保守保留")
            self._stats["suspicious"] += 1
            return res

        # R3: 重分配检测
        if self._reallocated(insns, free, use):
            res.verdict = SAFE
            res.rule = "R3_realloc"
            res.evidence.append(
                f"R3: free@{free.idx} 与 use@{use.idx} 间发生同源重分配")
            self._stats["safe"] += 1
            return res

        # R2: 不同对象
        if free.alloc_idx != use.alloc_idx:
            res.verdict = SAFE
            res.rule = "R2_diff_obj"
            res.evidence.append(
                f"R2: free→obj@{free.alloc_idx} != use→obj@{use.alloc_idx}")
            self._stats["safe"] += 1
            return res

        # R4: 同一对象
        res.verdict = UAF
        res.rule = "R4_same_obj"
        res.evidence.append(
            f"R4: free 与 use 均指向 obj@{free.alloc_idx}, 无重分配 → UAF")
        self._stats["uaf"] += 1
        return res

    def _reallocated(self, insns: List[Instruction], free: FreeSite,
                     use: DerefSite) -> bool:
        """检测 (free, use) 窗口内同源重分配."""
        window = insns[free.idx + 1:use.idx]
        for j, insn in enumerate(window):
            if not insn.is_call:
                continue
            if not find_alloc(callee_name(insn)):
                continue
            abs_j = free.idx + 1 + j
            # call <alloc> 后的 3 条内, 返回值写入 free 的来源键
            for k in range(abs_j + 1, min(abs_j + 4, use.idx)):
                nxt = insns[k]
                if nxt.mnem != "mov" or len(nxt.ops) < 2:
                    continue
                if self._writes_source(nxt, free):
                    return True
        return False

    def _writes_source(self, insn: Instruction, free: FreeSite) -> bool:
        """mov 指令是否把 rax 写入 free 的来源键 (寄存器或栈槽)."""
        op0 = insn.op(0)
        op1 = insn.op(1)
        if not op0 or "rax" not in op1:
            return False
        src = free.src_key
        if src.startswith("stk:"):
            slot = src[4:]
            return slot in op0
        return free.link is not None and self._reg_in(op0, free.link.root)

    @staticmethod
    def _reg_in(op: str, reg: str) -> bool:
        if not reg:
            return False
        parts = op.lower().split()
        return any(p == reg for p in parts)

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["LifetimeVerifier", "UafPairVerdict", "UAF", "SAFE",
           "SUSPICIOUS"]
