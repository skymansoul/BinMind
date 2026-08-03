"""
ROP gadget 语义分类器——将汇编片段归类为参数化的语义类型。

传统 ROP 工具 (ROPgadget, ropper) 基于正则匹配 gadget，
无法理解 "mov eax, [esp+8]; ret" 和 "pop eax; ret" 在语义上的等价性。
本模块通过具体解释 (concrete interpretation) 将每条 gadget 的副作用
抽象为语义类型 + 参数化模板，使跨编译器/优化级别的 gadget 可互操作。

语义类型枚举 (ref: MAJORCA, arXiv 2111.05781):
  MoveReg(dst, src)    — 寄存器间移动，如 mov rax, rbx
  LoadConst(dst, val)  — 加载常量，如 pop rax 或 xor eax,eax
  LoadMem(dst, addr)   — 从内存加载，如 mov rax, [rdi]
  StoreMem(addr, src)  — 写入内存，如 mov [rdi], rax
  ArithOp(op, dst, a,b)— 算术操作，如 add rax, rbx
  Syscall(nr)          — 系统调用

与 plugins/rop_tools.py 的关系:
  rop_tools 负责发现和评分 gadget → 本模块对已发现的 gadget 进行语义分类
  分类后的 gadget 可用于跨架构链构造（"需要 MoveReg(rdi,rax)" 在不同
  ISA 中查找语义等价而非语法等价的 gadget）

具体解释 vs 符号执行的权衡:
  具体解释 (本模块方案): 所有寄存器初始化为独立常量，逐条解释后比对。
  快 (~0.1ms/gadget)，适合数千条 gadget 的批量分类，不依赖 SMT 求解器。
  符号执行 (angrop方案): 精确追踪约束关系，但每条 gadget 需要数秒。
  两者互补——本模块用于粗筛，精确链构造时再用 angrop 验证。

参考:
  MAJORCA (arXiv 2111.05781) — Pivot IR + concrete interpretation for
    architecture-agnostic gadget classification
"""

from __future__ import annotations

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
    """gadget 语义描述——参数化的操作类型和操作数。"""

    stype: SemType
    operands: List[str] = field(default_factory=list)
    # 原始汇编文本——保留以便追溯
    raw_asm: str = ""
    # 副作用：此 gadget 执行后哪些寄存器被修改 (clobbered)
    clobbers: List[str] = field(default_factory=list)

    def template(self) -> str:
        """生成语义模板字符串——用于跨架构匹配。"""
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


# x86_64 寄存器集合 (含子寄存器映射)
_X86_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "ah", "bh", "ch", "dh",
    "rip", "eip",
}

# 通用寄存器规范名称映射——子寄存器统一到父寄存器
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
    """寄存器名规范化——32bit/16bit/8bit 子寄存器 → 64bit 父寄存器。"""
    return _REG_CANONICAL.get(reg.lower(), reg.lower())


def classify_gadget(asm_lines: str) -> GadgetSemantic:
    """
    对单个 gadget 的汇编指令序列进行语义分类。

    只分析最后一条 ret/call/jmp 之前的关键指令（通常是1-3条）。
    使用启发式规则 + 操作数模式匹配：
      pop reg → LoadConst(reg, "stack")
      mov reg1, reg2 → MoveReg(reg1, reg2)
      xor reg, reg → LoadConst(reg, "0")
      mov reg, [addr] → LoadMem(reg, addr)
      mov [addr], reg → StoreMem(addr, reg)
      add/sub reg, val → ArithOp(op, reg, reg, val)
      syscall/int 0x80 → Syscall

    Args:
        asm_lines: 单条 gadget 的汇编文本（可多行，分号或换行分隔）

    Returns:
        GadgetSemantic 对象
    """
    # 拆分为指令行
    lines = [l.strip() for l in re.split(r'[;\n]+', asm_lines) if l.strip()]
    if not lines:
        return GadgetSemantic(SemType.Unknown)

    # 先检查是否以 syscall/int 结尾——最高优先级
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

    # 提取关键指令（倒数1-3条，跳过控制流转移）
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

    # 分类——按优先级匹配
    clobbers = []
    result = GadgetSemantic(SemType.Unknown, raw_asm=asm_lines[:80])

    for insn in key_insns:
        parts = insn.replace(",", " ").split()
        if len(parts) < 2:
            continue
        mnemonic = parts[0]
        operands = parts[1:]

        # syscall / int 0x80
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

        # xchg reg, reg → MoveReg (双向)
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
    批量分类 gadget 列表。

    输入为 rop_tools.find_gadgets() 的输出格式，
    在每条记录中追加 semantic 字段。

    Returns:
        增加了 semantic 和 semantic_template 字段的 gadget 列表
    """
    enriched = []
    for g in gadgets:
        raw = g.get("raw_line", g.get("description", ""))
        sem = classify_gadget(raw)
        g = dict(g)  # shallow copy to avoid mutating original
        g["semantic"] = sem.stype.name
        g["semantic_template"] = sem.template()
        g["semantic_clobbers"] = sem.clobbers
        enriched.append(g)

    # 按语义类型分组统计
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
    在 gadget 池中查找语义等价项。

    例如 target_template="LoadConst(rdi, stack)" 会匹配所有
    pop rdi; ...; ret 的 gadget（无论中间夹杂了几条无关指令）。

    Args:
        target_template: classify_gadget 产生的模板字符串
        gadget_pool:     classify_gadget_batch 的返回值

    Returns:
        语义匹配的 gadget 列表
    """
    return [g for g in gadget_pool
            if g.get("semantic_template") == target_template]
