# coding: utf-8
# 创建: 2026-05-18  |  内存操作数共享助手
#
"""
反汇编操作数解析共享助手——供 defuse / guards / link 复用。

职责:
  _imm_val       立即数解析
  _mem_off       [base+off] 内存操作数拆解
  _plain_reg_token  操作数中的纯寄存器 token
  _dest_reg      指令目标寄存器
"""

import re
from typing import Optional, Tuple

_REGS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
})


def _imm_val(token: str) -> Optional[int]:
    """解析立即数: 0x... / 十进制."""
    t = token.strip()
    try:
        if t.lower().startswith("0x"):
            return int(t, 16)
        return int(t, 10)
    except ValueError:
        return None


def _mem_off(mem: str) -> Tuple[Optional[str], Optional[int]]:
    """解析 [rbp+0x10] / [rsp-0x8] / [rax] 形式, 返回 (基寄存器, 偏移).

    兼容带类型前缀的操作数: "DWORD PTR [rbp+0x10]"。
    """
    m = re.search(r"\[(.*?)\]", mem)
    if not m:
        return None, None
    inner = m.group(1).strip()
    if not inner:
        return None, None
    if inner.startswith("rip"):
        return "rip", 0
    m = re.match(r"^([a-z0-9]+)([+-])(0x[0-9a-fA-F]+|\d+)$", inner)
    if m:
        base = m.group(1)
        val = _imm_val(m.group(3))
        if val is None:
            return base, None
        if m.group(2) == "-":
            val = -val
        return base, val
    if re.match(r"^[a-z0-9]+$", inner):
        return inner, 0
    return None, None


def _plain_reg_token(op: str) -> str:
    """操作数若为纯寄存器返回其名 (忽略类型前缀), 否则 ''."""
    parts = op.split()
    for p in parts:
        if p in _REGS:
            return p
    return ""


def _dest_reg(insn) -> str:
    """指令目标寄存器 (纯寄存器形式), 否则返回 ''."""
    op0 = insn.op(0)
    if not op0:
        return ""
    return _plain_reg_token(op0)


__all__ = ["_imm_val", "_mem_off", "_plain_reg_token", "_dest_reg", "_REGS"]
