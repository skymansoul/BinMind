# coding: utf-8
# 创建: 2026-07-20  |  UAF 对象身份与指针来源归因
#
"""
对象身份与指针来源归因。

UAF 检测的误报根源:
  F1 以寄存器名为键: 同一寄存器在 free 后被新对象重用 → 误报
  F2 无对象身份: 无法区分 free 的指针与 use 的指针是否为同一对象
  F3 无重分配感知: free 后 malloc 复用同一栈槽/寄存器 → 合法, 误报

方法: 用对象身份 (alloc call 索引 + 来源槽) 代替寄存器名。
  free 参数与 use 解引用寄存器均解析到对象身份, 仅身份相同
  且无重分配时才判定 UAF。

复用 heapver.link.DstAllocLinker 做指针→分配点解析;
复用 heapver.defuse.DefUseResolver 获取来源槽键。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from heapver.insn import Instruction, parse_disasm, callee_name
from heapver.abi import find_alloc, find_free
from heapver.link import DstAllocLinker, LinkResult
from heapver.defuse import DefUseResolver


@dataclass(frozen=True)
class ObjectId:
    """对象身份: 分配点索引 + 来源键 (栈槽或寄存器)."""
    alloc_idx: int
    src_key: str = ""

    def __str__(self) -> str:
        return f"obj@{self.alloc_idx}:{self.src_key}"


@dataclass
class FreeSite:
    """free 调用点."""
    idx: int
    addr: int
    func: str
    link: LinkResult = None  # type: ignore
    src_key: str = ""
    alloc_idx: int = -1

    @property
    def resolved(self) -> bool:
        return self.alloc_idx >= 0


@dataclass
class DerefSite:
    """解引用点 (use)."""
    idx: int
    addr: int
    func: str
    base_reg: str
    kind: str = "mem"          # mem / call_via
    link: LinkResult = None  # type: ignore
    src_key: str = ""
    alloc_idx: int = -1

    @property
    def resolved(self) -> bool:
        return self.alloc_idx >= 0


class ProvenanceResolver:
    """指针来源归因器."""

    def __init__(self):
        self._linker = DstAllocLinker()
        self._resolver = DefUseResolver()
        self._stats = {"frees": 0, "derefs": 0, "freed_resolved": 0,
                       "deref_resolved": 0}

# 内部: 来源键

    def _src_key(self, insns: List[Instruction], idx: int,
                 cand_regs: List[str]) -> str:
        """解析寄存器在当前点的来源键 (栈槽 'stk:...' / 寄存器)."""
        region = self._resolver.resolve(insns, idx, cand_regs)
        sid = region.source_id
        if sid:
            return sid
        return cand_regs[0] if cand_regs else "?"

# 分配点索引列表

    @staticmethod
    def alloc_idxs(insns: List[Instruction]) -> List[int]:
        return [i for i, insn in enumerate(insns)
                if insn.is_call and find_alloc(callee_name(insn))]

# free 点

    def scan_free(self, insns: List[Instruction], idx: int,
                  func: str) -> Optional[FreeSite]:
        callee = callee_name(insns[idx])
        cand = _free_arg_regs(callee)
        if not cand:
            return None
        allocs = self.alloc_idxs(insns)
        link = self._linker.link(insns, idx, cand, allocs)
        self._stats["frees"] += 1
        key = self._src_key(insns, idx, cand)
        site = FreeSite(idx=idx, addr=insns[idx].addr, func=func,
                        link=link, src_key=key,
                        alloc_idx=link.alloc_call_idx)
        if site.resolved:
            self._stats["freed_resolved"] += 1
        return site

# 解引用点

    def scan_deref(self, insns: List[Instruction], idx: int,
                   base_reg: str, func: str,
                   kind: str = "mem") -> DerefSite:
        allocs = self.alloc_idxs(insns)
        link = self._linker.link(insns, idx, [base_reg], allocs)
        self._stats["derefs"] += 1
        key = self._src_key(insns, idx, [base_reg])
        site = DerefSite(idx=idx, addr=insns[idx].addr, func=func,
                         base_reg=base_reg, kind=kind, link=link,
                         src_key=key, alloc_idx=link.alloc_call_idx)
        if site.resolved:
            self._stats["deref_resolved"] += 1
        return site

    def stats(self) -> dict:
        return dict(self._stats)


# 每个 free 函数: ABI → 指针参数寄存器候选
_FREE_ARG = {
    "free": {"win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "_ZdlPv": {"win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "_ZdaPv": {"win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
    "realloc": {"win64": ["rcx", "ecx"], "sysv": ["rdi", "edi"]},
}


def _free_arg_regs(callee: str) -> List[str]:
    for key, sig in _FREE_ARG.items():
        if key in callee:
            # 返回两 ABI 候选 (解析器尝试取首个有定值者)
            return sig["win64"] + sig["sysv"]
    return []


__all__ = [
    "ObjectId", "FreeSite", "DerefSite", "ProvenanceResolver",
]
