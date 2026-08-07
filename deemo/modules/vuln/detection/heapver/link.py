# coding: utf-8
# 创建: 2026-07-27  |  写入目标→分配点关联——堆不相交性判定
#
"""
写入目标指针与分配点的关联 (pointer provenance linking)。

堆溢出检测的核心误报来源之二: 两次 malloc 返回不重叠区域,
若 memcpy 的 dst 指向分配#2 而 size 比较沿用分配#1 的信息,
则该 pair 无意义——纯 size 比较会报 FP。

方法: 从 write call 的 dst 参数寄存器反向追踪指针来源, 支持
  直接链   mov rcx, rax                → rax
  栈槽链   mov [rbp-8], rax; mov rcx,[rbp-8]  → rax
  间接链   mov rcx, rbx; mov rbx, rax   → rax
  跨函数   dst 来自参数寄存器且无 alloc 定义 → 外部传入 (unknowable)

当指针根为 rax 时, 回溯最近的 alloc call 索引即关联分配点。
根为另一 alloc 的返回或其他来源 → 无法关联当前分配点。
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .insn import Instruction, normalize_reg, callee_name
from .abi import find_alloc

_WINDOW = 30
_STACK_SLOT = re.compile(r"\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]")


@dataclass
class LinkResult:
    """写入 dst 的关联结果."""
    alloc_call_idx: int = -1     # -1 = 未关联到 alloc
    root: str = ""               # 指针根寄存器/来源
    via_stack: bool = False      # 是否经由栈槽
    reason: str = ""


class DstAllocLinker:
    """写入目标→分配点关联器."""

    def __init__(self):
        self._stats = {"linked": 0, "unlinked": 0, "stack_via": 0}

    def link(self, insns: List[Instruction], write_idx: int,
             dst_cand_regs: List[str],
             alloc_call_idxs: List[int]) -> LinkResult:
        """为 write 调用关联其 dst 指针来源的 alloc call 索引.

        当指针根为 rax 且追溯到 alloc call 时返回该精确 call 索引;
        其它来源返回 -1 (无法关联 → 保守保留)。
        """
        for reg in dst_cand_regs:
            reg64 = normalize_reg(reg)
            root_idx, via_stack, reason = self._walk(
                insns, write_idx - 1, reg64, 12)
            if root_idx is None:
                continue
            self._stats["unlinked"] += 1
            if root_idx in alloc_call_idxs:
                self._stats["linked"] += 1
                if via_stack:
                    self._stats["stack_via"] += 1
                return LinkResult(alloc_call_idx=root_idx, root="rax",
                                  via_stack=via_stack,
                                  reason=f"linked to alloc@{root_idx}")
            return LinkResult(alloc_call_idx=-1, root="rax",
                              via_stack=via_stack,
                              reason=f"alloc@{root_idx} not in list")
        return LinkResult(alloc_call_idx=-1, root="unknown",
                          reason="dst unresolvable")

    def _walk(self, insns: List[Instruction], start: int, reg: str,
              hops: int) -> Tuple[Optional[int], bool, str]:
        """反向追踪 reg 的来源根, 返回产生指针的 alloc call 索引.

        终止性: 每次递归 start 严格递减且 hops 递减。
        """
        if hops <= 0 or start < 0:
            return None, False, "hop-limit"
        stack_slot = None

        for j in range(start, max(-1, start - _WINDOW), -1):
            insn = insns[j]
            if insn.mnem == "call":
                # 已从栈槽解析: 槽值跨调用稳定, 继续寻找存储点
                if stack_slot is not None:
                    continue
                if reg == "rax":
                    # 当前值即本调用返回值
                    if find_alloc(callee_name(insn)):
                        return j, False, "alloc-ret"
                    return None, False, "call-clobbered"
                # 其它寄存器: 按被调函数保留寄存器建模 (与编译器
                # 将指针保存跨调用的代码生成一致)
                continue
            if insn.mnem == "ret":
                break
            # cmp/test/jcc 不定义目标寄存器
            if insn.mnem in ("cmp", "test") or insn.is_jump:
                continue
            dst = self._dst(insn)
            if not dst or normalize_reg(dst) != reg:
                # 匹配栈槽: mov [rbp-8], rax
                if stack_slot and insn.mnem == "mov" and len(insn.ops) >= 2:
                    m = _STACK_SLOT.search(insn.op(0))
                    if m and self._slot_key(m) == stack_slot:
                        src = self._src_reg(insn)
                        if src:
                            return self._walk(insns, j - 1, src, hops - 1)
                continue
            # 找到 reg 的定义; 若已从栈槽解析, 该更早定义为死定义
            if stack_slot is not None:
                continue
            mnem = insn.mnem
            ops = insn.ops
            if mnem == "mov" and len(ops) >= 2:
                src = self._src_reg(insn)
                if src:
                    return self._walk(insns, j - 1, src, hops - 1)
                # mov reg, [mem]
                for o in ops:
                    m = _STACK_SLOT.search(o)
                    if m:
                        stack_slot = self._slot_key(m)
                        # 继续向前找存储到该槽的指令
                        break
                continue
            if mnem == "lea" and len(ops) >= 2:
                src = self._src_reg(insn)
                if src:
                    return self._walk(insns, j - 1, src, hops - 1)
            return None, stack_slot is not None, f"def-{mnem}"
        return None, stack_slot is not None, "no-def"

    @staticmethod
    def _dst(insn: Instruction) -> str:
        op0 = insn.op(0)
        if not op0:
            return ""
        parts = op0.split()
        for p in parts:
            if p in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"):
                return p
        return ""

    @staticmethod
    def _src_reg(insn: Instruction) -> str:
        if len(insn.ops) < 2:
            return ""
        op1 = insn.op(1)
        parts = op1.split()
        for p in parts:
            if p in ("rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                     "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                     "eax", "ebx", "ecx", "edx", "esi", "edi"):
                return p
        return ""

    @staticmethod
    def _slot_key(m) -> str:
        base = m.group(1)
        sign = m.group(2)
        val = m.group(3)
        return f"{base}{sign}{val}"

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["LinkResult", "DstAllocLinker"]
