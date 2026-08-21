"""格式串溯源分类 - 判定 printf 的格式串参数是否攻击者可控.

误报根源: binary_fmt_scanner 把"非 .rdata 来源"一律视为用户可控 -
  栈槽常量初始化 (char fmt[] = "val=%d") 与堆缓冲常量复制被误报.
本模块沿 fmt 寄存器 def-use 链分类 5 类来源:
  RDATA      - lea [rip+off] / mov r, imm(.rdata地址) / mov r, [rip+off]
  STACK_CONST- 栈槽被立即数序列初始化 (编译器内联字符串)
  HEAP_CONST - malloc 后 strcpy/memcpy 自常量源
  USER       - argv 参数 / gets/recv/read 写入 / 栈参数无初始化
  UNKNOWN    - 无法判定, 保守
槽/堆内容溯源由 fmt_content_trace.SlotContentTracer 承担 (委派).
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from ..heap_analysis.instruction_parser import InstructionParser
from .fmt_content_trace import (
    SlotContentTracer, FmtSource, _INPUT_FUNCS, _COPY_FUNCS)


_WINDOW = 20
_MAX_HOPS = 6


class FmtProvenance:
    """格式串溯源分类器 - 一次分类, 携带证据链."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}
        self._tracer = SlotContentTracer(insns, self._chase)

    def classify(self, call_idx: int,
                 fmt_reg: str = "rcx") -> Tuple[FmtSource, str]:
        """分类 call 点格式串参数的来源."""
        return self._chase(call_idx, fmt_reg, _MAX_HOPS, set())

    # 内部: def-use 链追迹

    def _chase(self, idx: int, reg: str, hops_left: int,
               seen: set) -> Tuple[FmtSource, str]:
        if hops_left <= 0 or (idx, reg) in seen:
            return FmtSource.UNKNOWN, "chain depth exceeded"
        seen.add((idx, reg))
        start = max(0, idx - _WINDOW)
        for j in range(idx - 1, start - 1, -1):
            ins = self._insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst != reg:
                continue
            src = ins.operands[1].strip()
            if mn in ("lea",):
                # rip 不在解析器 KNOWN_REGS — 直接检测操作数字面
                if "rip" in src.lower():
                    return FmtSource.RDATA, \
                        f"lea {reg},[rip+off]@{hex(ins.address)}"
                base, _, _, _ = \
                    InstructionParser.parse_memory_operand_full(src)
                if base in ("rbp", "rsp"):
                    return self._chase(j, reg, hops_left - 1, seen)
                return FmtSource.UNKNOWN, "lea without rip"
            if mn in ("mov", "movabs"):
                imm = InstructionParser._try_parse_int(src)
                if imm is not None:
                    return FmtSource.RDATA, \
                        f"mov {reg},imm@{hex(ins.address)}"
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase(j, src_reg, hops_left - 1, seen)
                base, _, _, off = \
                    InstructionParser.parse_memory_operand_full(src)
                if base == "rip":
                    return FmtSource.RDATA, \
                        f"mov {reg},[rip+off]@{hex(ins.address)}"
                if base in ("rbp", "rsp"):
                    return self._tracer.classify_slot(j, base, off, seen)
                if base:
                    # 间接寻址: mov rdx, [rax] — 追基址寄存器
                    return self._chase(j, base, hops_left - 1, seen)
                return FmtSource.UNKNOWN, "mov from memory"
            if mn == "call":
                callee = InstructionParser.extract_callee(ins)
                if callee in _INPUT_FUNCS:
                    return FmtSource.USER, f"{callee}() writes buffer"
                if callee in _COPY_FUNCS:
                    return self._tracer.classify_copy(j, callee, seen)
                return FmtSource.UNKNOWN, f"call {callee} result"
            # 算术/逻辑指令是偏移或位运算定义 — 指针链语义保留,
            # 继续扫描更早的定义
            if mn in ("add", "sub", "and", "or", "xor", "inc", "dec",
                      "shl", "shr", "neg", "not", "imul", "cdqe",
                      "cdq", "movzx", "movsx", "movsxd"):
                continue
            break
        return FmtSource.UNKNOWN, "no def in window"


# smoke test
def _check():
    class _I:
        def __init__(self, addr, mn, ops, raw=""):
            self.address = addr
            self.mnemonic = mn
            self.operands = ops
            self.raw_line = raw

    # printf(argv[1]): rcx ← [rbp+0x18] 参数槽 → USER
    asm = [
        _I(0x1000, "mov", ["rcx", "QWORD PTR [rbp+0x18]"]),
        _I(0x1005, "call", ["printf"]),
    ]
    p = FmtProvenance(asm)
    s, e = p.classify(1)
    assert s == FmtSource.USER, f"argv slot should be USER, got {s}"
    # printf(fmt): rcx ← lea [rip+off] → RDATA
    asm2 = [
        _I(0x1010, "lea", ["rcx", "[rip+0x9830]"]),
        _I(0x1017, "call", ["printf"]),
    ]
    p2 = FmtProvenance(asm2)
    s2, _ = p2.classify(1)
    assert s2 == FmtSource.RDATA, f"lea rip should be RDATA, got {s2}"
    print("[OK] fmt_provenance: USER/RDATA 分类通过")


if __name__ == "__main__":
    _check()
