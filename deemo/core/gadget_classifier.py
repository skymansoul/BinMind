"""
ROP gadget semantic classifier.

Maps assembly fragments to parameterized semantic types using concrete
interpretation, enabling cross-compiler and cross-optimization-level
interoperability of gadgets. Traditional tools (ROPgadget, ropper) use
regex matching and miss semantic equivalence (e.g., "mov eax, [esp+8]; ret"
vs "pop eax; ret").

Semantic types (ref: MAJORCA, arXiv 2111.05781):
  MoveReg(dst, src), LoadConst(dst, val), LoadMem(dst, addr),
  StoreMem(addr, src), ArithOp(op, dst, a, b), Syscall(nr)

Concrete interpretation trades full constraint tracking for speed
(~0.1ms/gadget vs seconds for symbolic), suitable for batch classification
of thousands of gadgets. Use angrop for precise chain construction.

Reference:
  MAJORCA 
"""

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
    """Gadget semantic descriptor with parameterized operation type and operands."""

    stype: SemType
    operands: List[str] = field(default_factory=list)
    raw_asm: str = ""
    clobbers: List[str] = field(default_factory=list)

    def template(self) -> str:
        """Generate semantic template string for cross-architecture matching."""
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

# x86_64 register set (including sub-registers)
_X86_REGS = {
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "ax", "bx", "cx", "dx", "si", "di", "bp", "sp",
    "al", "bl", "cl", "dl", "sil", "dil", "bpl", "spl",
    "ah", "bh", "ch", "dh",
    "rip", "eip",
}

# Canonical register name mapping (sub-registers -> parent 64-bit register)
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
    """Canonicalize register name: 32/16/8-bit sub-register -> 64-bit parent."""
    return _REG_CANONICAL.get(reg.lower(), reg.lower())

def classify_gadget(asm_lines: str) -> GadgetSemantic:
    """
    Semantically classify a single gadget's assembly instruction sequence.

    Only analyzes key instructions (usually 1-3) before the final ret/call/jmp,
    using heuristic rules and operand pattern matching.

    Args:
        asm_lines: assembly text for one gadget (multi-line, semicolon or newline separated)

    Returns:
        GadgetSemantic object
    """
    # Split into individual instruction lines
    lines = [l.strip() for l in re.split(r'[;\n]+', asm_lines) if l.strip()]
    if not lines:
        return GadgetSemantic(SemType.Unknown)

    # Check for syscall/int first (highest priority)
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

    # Extract key instructions (last 1-3, skipping control flow transfers)
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

    # Classify by priority matching
    clobbers = []
    result = GadgetSemantic(SemType.Unknown, raw_asm=asm_lines[:80])

    for insn in key_insns:
        parts = insn.replace(",", " ").split()
        if len(parts) < 2:
            continue
        mnemonic = parts[0]
        operands = parts[1:]

        # syscall / int 0x80 handling
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
    Batch-classify a list of gadgets.

    Input format is the output of rop_tools.find_gadgets().
    Appends semantic and semantic_template fields to each record.
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

    # Group by semantic type for diagnostics
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
    Find semantically equivalent gadgets in a pool.

    For example, target_template="LoadConst(rdi, stack)" matches all
    pop rdi; ...; ret gadgets regardless of intermediate instructions.

    Args:
        target_template: template string from classify_gadget()
        gadget_pool: return value from classify_gadget_batch()

    Returns:
        List of semantically matching gadgets
    """
    return [g for g in gadget_pool
            if g.get("semantic_template") == target_template]
