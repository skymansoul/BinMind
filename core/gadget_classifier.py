"""ROP gadget 语义分类器 — 用具体解释将汇编片段映射为参数化语义类型.
支持跨编译器/跨优化级别的 gadget 互用; 传统工具 (ROPgadget/ropper) 纯正则匹配会漏语义等价 (如 "mov eax,[esp+8];ret" vs "pop eax;ret");
语义类型 (参考 MAJORCA, arXiv 2111.05781): MoveReg/LoadConst/LoadMem/StoreMem/ArithOp/Syscall; 具体解释约 0.1ms/gadget, 适合批量分类, 精确链构造请用 angrop."""

import logging
import re
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

class SemType(Enum):
    MoveReg = auto()
    LoadConst = auto()
    LoadMem = auto()
    StoreMem = auto()
    ArithOp = auto()
    Syscall = auto()
    Unknown = auto()

@dataclass
class GadgetSemantic:
    """带参数化操作类型与操作数的 gadget 语义描述."""

    stype: SemType
    operands: List[str] = field(default_factory=list)
    raw_asm: str = ""
    clobbers: List[str] = field(default_factory=list)

    def template(self) -> str:
        """生成跨架构匹配的语义模板字符串."""
        if self.stype == SemType.MoveReg and len(self.operands) >= 2:
            return f"MoveReg({self.operands[0]}, {self.operands[1]})"
        if self.stype == SemType.LoadConst and len(self.operands) >= 2:
            return f"LoadConst({self.operands[0]}, {self.operands[1]})"
        if self.stype == SemType.LoadMem and len(self.operands) >= 2:
            return f"LoadMem({self.operands[0]}, {self.operands[1]})"
        if self.stype == SemType.StoreMem and len(self.operands) >= 2:
            return f"StoreMem({self.operands[0]}, {self.operands[1]})"
        if self.stype == SemType.ArithOp and len(self.operands) >= 3:
            return f"ArithOp({self.operands[0]}, {self.operands[1]}, {self.operands[2]})"
        if self.stype == SemType.Syscall:
            return "Syscall"
        return "Unknown"

# x86_64 寄存器集合 (含子寄存器)
_X86_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "ah", "bh", "ch", "dh",
    "rip", "eip",
}

# 规范寄存器名映射 (子寄存器 → 父 64 位寄存器)
_REG_CANONICAL = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
    "al": "rax", "bl": "rbx", "cl": "rcx", "dl": "rdx",
    "sil": "rsi", "dil": "rdi", "bpl": "rbp", "spl": "rsp",
    "ah": "rax", "bh": "rbx", "ch": "rcx", "dh": "rdx",
    "eip": "rip",
}

def _canon_reg(reg: str) -> str:
    """规范化寄存器名: 32/16/8 位子寄存器 → 64 位父寄存器."""
    return _REG_CANONICAL.get(reg.lower(), reg.lower())

def classify_gadget(asm_lines: str) -> GadgetSemantic:
    """
    语义分类单个 gadget 的汇编指令序列.

    仅分析最终 ret/call/jmp 之前的关键指令 (通常 1-3 条), 用启发式规则与操作数模式匹配.
    """
    # 拆分为单条指令行
    lines = [l.strip() for l in re.split(r'[;\n]+', asm_lines) if l.strip()]
    if not lines:
        return GadgetSemantic(SemType.Unknown)

    # 优先检查 syscall/int (最高优先级)
    last_mnems = []
    for line in reversed(lines):
        m = line.split()[0] if line.split() else ""
        if m in ("ret", "retn", "call", "jmp", "nop"):
            continue
        last_mnems.append(m)
        if len(last_mnems) >= 2:
            break
    if "syscall" in last_mnems or "int" in last_mnems:
        return GadgetSemantic(SemType.Syscall, raw_asm=asm_lines[:80])

    # 提取关键指令 (最后 1-3 条, 跳过控制流转移)
    key_insns = []
    for line in reversed(lines):
        mnemonic = line.split()[0] if line.split() else ""
        if mnemonic in ("ret", "retn", "call", "jmp", "je", "jne",
                         "jg", "jl", "jge", "jle", "jz", "jnz",
                         "ja", "jb", "jae", "jbe", "nop"):
            continue
        key_insns.insert(0, line)
        if len(key_insns) >= 3:
            break

    if not key_insns:
        return GadgetSemantic(SemType.Unknown, raw_asm=asm_lines[:80])

    # 按优先级匹配分类
    clobbers = []
    result = GadgetSemantic(SemType.Unknown, raw_asm=asm_lines[:80])

    for insn in key_insns:
        parts = insn.replace(",", " ").split()
        if len(parts) < 2:
            continue
        mnemonic = parts[0]
        operands = parts[1:]

        # syscall / int 0x80 处理
        if mnemonic in ("syscall", "int"):
            return GadgetSemantic(
                SemType.Syscall,
                operands=[operands[0]] if operands else ["0x80"],
                clobbers=clobbers, raw_asm=asm_lines[:80],
            )

        # pop reg → LoadConst
        if mnemonic == "pop" and len(operands) >= 1:
            reg = _canon_reg(operands[0])
            clobbers.append(reg)
            result = GadgetSemantic(
                SemType.LoadConst, operands=[reg, "stack"],
                clobbers=list(clobbers), raw_asm=asm_lines[:80],
            )
            continue

        # xor reg, reg → LoadConst(reg, "0")
        if mnemonic == "xor" and len(operands) >= 2:
            r1 = _canon_reg(operands[0])
            r2 = _canon_reg(operands[1])
            if r1 == r2:
                clobbers.append(r1)
                result = GadgetSemantic(
                    SemType.LoadConst, operands=[r1, "0"],
                    clobbers=list(clobbers), raw_asm=asm_lines[:80],
                )
                continue

        # mov reg, reg → MoveReg
        if mnemonic == "mov" and len(operands) >= 2:
            dst = _canon_reg(operands[0])
            src = operands[1]
            if src in _X86_REGS:
                src = _canon_reg(src)
                clobbers.append(dst)
                result = GadgetSemantic(
                    SemType.MoveReg, operands=[dst, src],
                    clobbers=list(clobbers), raw_asm=asm_lines[:80],
                )
                continue
            if "[" in src:
                clobbers.append(dst)
                result = GadgetSemantic(
                    SemType.LoadMem, operands=[dst, src],
                    clobbers=list(clobbers), raw_asm=asm_lines[:80],
                )
                continue

        # mov [addr], reg → StoreMem
        if mnemonic == "mov" and len(operands) >= 2 and "[" in operands[0]:
            addr = operands[0]
            src = _canon_reg(operands[1]) if operands[1] in _X86_REGS else operands[1]
            result = GadgetSemantic(
                SemType.StoreMem, operands=[addr, src],
                clobbers=list(clobbers), raw_asm=asm_lines[:80],
            )
            continue

        # xchg reg, reg -> MoveReg (bidirectional)
        if mnemonic == "xchg" and len(operands) >= 2:
            r1 = _canon_reg(operands[0])
            r2 = _canon_reg(operands[1]) if operands[1] in _X86_REGS else operands[1]
            clobbers.extend([r1, r2])
            result = GadgetSemantic(
                SemType.MoveReg, operands=[r1, r2],
                clobbers=list(clobbers), raw_asm=asm_lines[:80],
            )

        # add/sub/or/and reg, imm → ArithOp
        if mnemonic in ("add", "sub", "or", "and", "xor", "shl", "shr"):
            if len(operands) >= 2:
                dst = _canon_reg(operands[0])
                clobbers.append(dst)
                result = GadgetSemantic(
                    SemType.ArithOp,
                    operands=[mnemonic, dst, operands[1]],
                    clobbers=list(clobbers), raw_asm=asm_lines[:80],
                )

    return result

def classify_gadget_batch(
    gadgets: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    批量分类 gadget 列表.

    输入格式为 rop_tools.find_gadgets() 的输出, 为每条记录追加 semantic 与 semantic_template 字段.
    """
    enriched = []
    for g in gadgets:
        raw = g.get("raw_line", g.get("description", ""))
        sem = classify_gadget(raw)
        g = dict(g)
        g["semantic"] = sem.stype.name
        g["semantic_template"] = sem.template()
        g["semantic_clobbers"] = sem.clobbers
        enriched.append(g)

    # 按语义类型分组, 用于诊断
    by_type: Dict[str, int] = {}
    for g in enriched:
        t = g.get("semantic", "Unknown")
        by_type[t] = by_type.get(t, 0) + 1

    _log.debug("Gadget classification: %s", by_type)
    return enriched

def find_semantic_equivalent(
    target_template: str,
    gadget_pool: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """
    在 gadget 池中查找语义等价的 gadget.

    例: target_template="LoadConst(rdi, stack)" 匹配所有 pop rdi; ...; ret, 忽略中间指令差异.
    """
    return [g for g in gadget_pool
            if g.get("semantic_template") == target_template]
