# coding: utf-8
# 创建: 2026-06-06  |  UAF 站点扫描——free 点与解引用点
#
"""
函数内 UAF 站点扫描。

free 点: call <free/_ZdlPv> → 解析指针来源对象身份。
解引用点: 含 [reg] 内存操作且基寄存器为通用指针寄存器 (排除
  rbp/rsp/rip 栈帧与 rip 相对寻址) → 解析来源对象身份;
  以及 `call *reg` 间接调用 (悬垂指针→控制流)。

仅返回能解析到堆对象身份的 free/解引用点——未归因到堆的
栈访问自动滤除, 减少噪音。
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from heapver.insn import Instruction, callee_name
from heapver.abi import find_free

from .provenance import ProvenanceResolver, FreeSite, DerefSite

_FRAME_REGS = frozenset({"rbp", "rsp", "rip", "ebp", "esp"})

# 通用指针寄存器 (含 32 位别名)
_PTR_REGS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
})

_MEM_BASE = re.compile(r"\[([a-z0-9]+)")


class SiteScanner:
    """UAF 站点扫描器."""

    def __init__(self, prov: Optional[ProvenanceResolver] = None):
        self._prov = prov or ProvenanceResolver()
        self._stats = {"functions": 0, "frees": 0, "derefs": 0}

    def scan_function(self, insns: List[Instruction],
                      func: str) -> Tuple[List[FreeSite], List[DerefSite]]:
        """扫描单函数, 返回 (frees, derefs)."""
        frees: List[FreeSite] = []
        derefs: List[DerefSite] = []
        if len(insns) < 3:
            return frees, derefs
        self._stats["functions"] += 1

        for i, insn in enumerate(insns):
            if insn.is_call:
                callee = callee_name(insn)
                if find_free(callee) or "realloc" in callee:
                    # realloc 可能移动对象 → 旧指针失效, 按释放处理
                    site = self._prov.scan_free(insns, i, func)
                    if site is not None and site.resolved:
                        frees.append(site)
                        self._stats["frees"] += 1
                # 间接调用: call <reg> / call QWORD PTR [reg] → 悬垂指针
                for base in self._indirect_call_bases(insn):
                    site = self._prov.scan_deref(insns, i, base, func,
                                                 "call_via")
                    if site.resolved:
                        derefs.append(site)
                        self._stats["derefs"] += 1
                continue
            for base in self._mem_bases(insn):
                site = self._prov.scan_deref(insns, i, base, func, "mem")
                if site.resolved:
                    derefs.append(site)
                    self._stats["derefs"] += 1
        return frees, derefs

    @staticmethod
    def _indirect_call_bases(insn: Instruction) -> List[str]:
        """间接调用目标寄存器: call rbx / call QWORD PTR [rbx]."""
        op0 = insn.op(0) or ""
        bases = SiteScanner._mem_bases(insn)  # 内存形式 [reg]
        for token in op0.split():
            if token in _PTR_REGS and token not in bases:
                bases.append(token)
        return bases

    @staticmethod
    def _mem_bases(insn: Instruction) -> List[str]:
        """提取指令中所有 [reg] 内存基寄存器 (排除栈帧/rip)."""
        bases = []
        for op in insn.ops:
            m = _MEM_BASE.search(op)
            if not m:
                continue
            reg = m.group(1)
            if reg in _FRAME_REGS or reg not in _PTR_REGS:
                continue
            if reg not in bases:
                bases.append(reg)
        return bases

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["SiteScanner"]
