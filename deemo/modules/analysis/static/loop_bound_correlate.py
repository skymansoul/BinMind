# -*- coding: utf-8 -*-
# 循环上界-分配同源判定: 判断循环上界是否与分配 size 参数同源

import re
from typing import List, Optional

from .disasm_util import norm_reg


def loop_bound_equals_alloc(instructions: List[dict],
                            body_start: int,
                            alloc_addr: int,
                            arg_regs) -> bool:
    """判断循环上界是否与分配大小同源.

    保守实现: 上界栈槽与分配 size 参数栈槽相同才判 True.
    """
    if not instructions:
        return False
    start_idx = None
    for i, ins in enumerate(instructions):
        if ins.get("address", 0) == body_start:
            start_idx = i
            break
    if start_idx is None:
        return False
    for j in range(start_idx, min(start_idx + 40, len(instructions))):
        ins_j = instructions[j]
        if ins_j.get("mnemonic", "").lower() != "cmp":
            continue
        ops = ins_j.get("operands", [])
        if len(ops) < 2:
            return False
        bound_op = bound_operand(ops)
        if bound_op is None:
            return False
        alloc_src = alloc_size_source(instructions, alloc_addr, arg_regs)
        if alloc_src is None:
            return False
        return same_source(bound_op, alloc_src)
    return False


def bound_operand(cmp_ops: List[str]) -> Optional[str]:
    """提取 cmp 中的上界操作数 (非计数器操作数).

    计数器是循环体内被 add/inc 修改的寄存器; 上界是另一个操作数.
    """
    if len(cmp_ops) < 2:
        return None
    ops = [o.strip().lower() for o in cmp_ops]
    counter = norm_cmp_counter(ops)
    for op in ops:
        if op != counter:
            return op
    return None


def norm_cmp_counter(ops: List[str]) -> Optional[str]:
    """识别 cmp 操作数中的纯寄存器作为计数器."""
    for op in ops:
        m = re.search(r"^([a-z][a-z0-9]*)$", op.strip())
        if m:
            return m.group(1)
    return None


def alloc_size_source(instructions: List[dict],
                      alloc_addr: int,
                      arg_regs) -> Optional[str]:
    """提取分配点 size 参数的来源 (栈槽或寄存器).

    支持多跳寄存器链: mov rcx, rax; mov rax, [rbp+0x10] →
    归约到 [rbp+0x10]. 仅当链能归约为栈槽/参数时返回.
    """
    if not instructions:
        return None
    cur_reg = arg_regs[0] if arg_regs else "rcx"
    alloc_idx = None
    for i, ins in enumerate(instructions):
        if ins.get("address", 0) == alloc_addr:
            alloc_idx = i
            break
    if alloc_idx is None:
        return None
    for _hop in range(8):
        src = None
        for j in range(alloc_idx - 1, max(0, alloc_idx - 20) - 1, -1):
            ins_j = instructions[j]
            mnem = ins_j.get("mnemonic", "").lower()
            ops = ins_j.get("operands", [])
            if mnem == "call":
                return None
            if mnem in ("mov", "movsxd", "movzx", "movsx") \
                    and len(ops) >= 2 and norm_reg(ops[0]) == cur_reg:
                src = ops[1].strip()
                break
        if src is None:
            return None
        src_l = src.lower()
        if "[" in src_l:
            slot = re.search(r"(r[bs]p[+-]0x[0-9a-f]+)", src_l)
            if slot:
                return f"[{slot.group(1)}]"
            return src_l
        if parse_imm(src_l) is not None:
            return src_l
        cur_reg = norm_reg(src)
        alloc_idx = alloc_idx - 1
    return None


def same_source(a: str, b: str) -> bool:
    """比较两个来源 (栈槽/寄存器) 是否同源."""
    def norm(s: str) -> str:
        s = s.lower().replace(" ", "")
        if "ptr" in s:
            s = s.split("ptr")[-1]
        s = s.replace("[", "").replace("]", "")
        m = re.search(r"(r[bs]p[+-]0x[0-9a-f]+)", s)
        if m:
            return m.group(1)
        m = re.search(r"^[a-z][a-z0-9]*$", s)
        if m:
            return m.group(0)
        return s
    return norm(a) == norm(b)


def parse_imm(op: str) -> Optional[int]:
    s = op.strip().lower().lstrip("%").replace("$", "")
    s = s.split("#")[0].strip()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
            return int(s)
    except ValueError:
        pass
    return None


def parse_target(op: str) -> Optional[int]:
    s = op.strip().lower().lstrip("%").replace("$", "")
    if "<" in s:
        s = s.split("<")[0].strip()
    s = s.split("#")[0].strip()
    try:
        if s.startswith("0x"):
            return int(s, 16)
        if len(s) >= 6 and all(c in "0123456789abcdef" for c in s):
            return int(s, 16)
        return int(s)
    except ValueError:
        return None


def extract_base_reg(op: str) -> Optional[str]:
    """从 [reg+off] 形式操作数提取基址寄存器."""
    m = re.search(r"\[([a-z][a-z0-9]*)", op)
    if m:
        return m.group(1)
    return None


def infer_write_size_from_prefix(op: str) -> int:
    """从操作数前缀推断写入字节数."""
    if "byte" in op:
        return 1
    if "qword" in op:
        return 8
    if "dword" in op:
        return 4
    if "word" in op:
        return 2
    return 1


__all__ = ["loop_bound_equals_alloc", "bound_operand",
           "alloc_size_source", "same_source", "parse_imm", "parse_target",
           "extract_base_reg", "infer_write_size_from_prefix"]
