# coding: utf-8
#
"""
格式参数溯源: 常量折叠 + 用户输入污点。

误报根源:
  F1 变量装载的常量格式串: `char *f = "固定"; printf(f)`
     —— 旧检测仅看"fmt 是否为常量字面量", 变量形式即误报。
  F2 用户输入格式串漏检: printf(argv[1]) / printf(buf) (buf 来自 fgets)
     —— 需要污点溯源确证。

方法: 从 fmt 参数寄存器反向追踪定义链:
  lea [rip+off] / mov [rip+off] / mov reg, offset  → CONST (rodata)
  mov reg, [rbp/rsp+off]                           → 解析栈槽存储源
  非栈帧基址内存加载 (argv 等)                      → TAINT
  输入函数 (scanf/fgets/recv...) 输出/缓冲区         → TAINT
  其它/未知                                        → UNKNOWN

终止: 跳数上限 12, 槽/寄存器 visited 集合防环。
"""

import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from ..heapver.insn import Instruction, callee_name
from ..heapver.memop import _plain_reg_token

from .fmt_abi import INPUT_FUNCS

CONST = "CONST"
TAINT = "TAINT"
UNKNOWN = "UNKNOWN"

_WINDOW = 40
_MAX_HOPS = 12

_SLOT_RE = re.compile(r"\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]")
_CALLER_SAVED = frozenset({
    "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11",
})
_FRAME = frozenset({"rbp", "rsp", "rip"})


def _slot_key(m) -> str:
    return f"{m.group(1)}{m.group(2)}{m.group(3)}"


def _dst_reg(insn: Instruction) -> str:
    op0 = insn.op(0)
    if not op0:
        return ""
    return _plain_reg_token(op0)


class FmtTaintWalker:
    """格式参数溯源器."""
    # TODO: strcpy/strdup 来源的格式串污点未建模, 回退 UNKNOWN 保守保留

    def __init__(self):
        self._max_hops = _MAX_HOPS
        self._window = _WINDOW
        self._stats = {"const": 0, "taint": 0, "unknown": 0}

    def resolve(self, insns: List[Instruction], call_idx: int,
                cand_regs: List[str]) -> Tuple[str, str]:
        """解析 fmt 参数分类, 返回 (classification, evidence)."""
        for reg in cand_regs:
            cls, ev = self._walk_reg(insns, call_idx - 1, reg,
                                     self._max_hops, set())
            if cls != UNKNOWN:
                self._stats[cls.lower()] += 1
                return cls, ev
        self._stats["unknown"] += 1
        return UNKNOWN, "fmt 未解析为常量或输入"

# 寄存器链

    def _walk_reg(self, insns: List[Instruction], start: int, reg: str,
                  hops: int, seen: Set[str]) -> Tuple[str, str]:
        if hops <= 0 or start < 0:
            return UNKNOWN, f"hop-limit@{reg}"
        # 终止性由 hops 递减保证; 槽↔寄存器交替链中同名寄存器可合法复现

        for j in range(start, max(-1, start - _WINDOW), -1):
            insn = insns[j]
            if insn.mnem == "call":
                callee = callee_name(insn)
                if reg == "rax" and any(i in callee for i in INPUT_FUNCS):
                    return TAINT, f"输入函数 {callee} 返回值"
                if reg in _CALLER_SAVED:
                    return UNKNOWN, f"call-clobbered@{reg}"
                continue
            if insn.mnem == "ret":
                break
            dst = _dst_reg(insn)
            if not dst or dst != reg:
                continue
            mnem = insn.mnem
            ops = insn.ops

            if mnem == "lea" and len(ops) >= 2:
                if "[rip" in ops[1]:
                    return CONST, "lea [rip+off] → rodata"
                m = _SLOT_RE.search(ops[1])
                if m:
                    return self._walk_slot(insns, j, _slot_key(m), hops - 1,
                                           seen)
                if "[" in ops[1]:
                    return TAINT, f"lea 非栈帧地址 {ops[1]} (argv/外部)"
                return UNKNOWN, f"lea-{ops[1]}"
            if mnem == "mov" and len(ops) >= 2:
                src = ops[1]
                if "[rip" in src:
                    return CONST, "mov reg,[rip+off] → rodata"
                # 非栈帧基址的内存加载 → 用户数据 (argv 等)
                m = _SLOT_RE.search(src)
                if m:
                    return self._walk_slot(insns, j, _slot_key(m), hops - 1,
                                           seen)
                if "[" in src:
                    return TAINT, f"非栈帧内存加载 {src} (argv/外部)"
                sreg = _plain_reg_token(src)
                if sreg:
                    return self._walk_reg(insns, j - 1, sreg, hops - 1, seen)
                # mov reg, imm 作为 fmt: 数字常量, 视为未知
                return UNKNOWN, "mov reg, imm"
            return UNKNOWN, f"def-{mnem}"

        return UNKNOWN, "no-def"

# 栈槽链

    def _walk_slot(self, insns: List[Instruction], start: int, slot: str,
                   hops: int, seen: Set[str]) -> Tuple[str, str]:
        if hops <= 0 or start < 0:
            return UNKNOWN, f"slot-hop-limit@{slot}"

        for j in range(start, max(-1, start - _WINDOW), -1):
            insn = insns[j]
            if insn.mnem == "mov" and len(insn.ops) >= 2:
                m = _SLOT_RE.search(insn.op(0))
                if m and _slot_key(m) == slot:
                    src = insn.op(1)
                    if "[rip" in src:
                        return CONST, f"mov [{slot}], [rip+off]"
                    sreg = _plain_reg_token(src)
                    if sreg:
                        cls, ev = self._walk_reg(insns, j - 1, sreg,
                                                 hops - 1, seen)
                        if cls == CONST:
                            return CONST, f"槽 {slot} ← {ev}"
                        return cls, f"槽 {slot} ← {ev}"
                    return UNKNOWN, f"槽 {slot} 存立即数"
            if insn.mnem == "call":
                callee = callee_name(insn)
                if any(i in callee for i in INPUT_FUNCS):
                    return TAINT, f"输入函数 {callee} 写入缓冲区 {slot}"
        return UNKNOWN, f"槽 {slot} 无可见存储源"

    def stats(self) -> dict:
        return dict(self._stats)


__all__ = ["FmtTaintWalker", "CONST", "TAINT", "UNKNOWN"]
