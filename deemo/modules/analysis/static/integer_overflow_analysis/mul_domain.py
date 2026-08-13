"""位宽感知乘法域 — 判定 imul/shl 结果是否可能溢出.

误报根源: binary_int_overflow_scanner 对 imul/shl 一律标记 —
  常量缩放 (imul r,r,0x30)、掩码约束 (and r,0xFFF 后乘法)、
  窄位扩展 (movzx 16 位) 均被当作溢出源.
本模块沿操作数 def-use 链分类其数值域:
  CONST_SMALL — 立即数 (≤ 0xFFFF)
  MASKED      — and r, imm 掩码 (上界 = imm)
  NARROW      — movzx/movsx 窄位扩展 (上界 0xFFFF 或 0xFFFFFFFF)
  RUNTIME     — 内存/参数/调用来源, 无静态上界
乘积上界可静态确定且 < 2^32 → 安全; 含 RUNTIME 且结果流入
分配 → 可疑.
"""

import re
from dataclasses import dataclass
from enum import Enum, auto
from typing import Dict, Optional, Tuple

from ..heap_analysis.instruction_parser import InstructionParser

_WINDOW = 12


class OperandKind(Enum):
    CONST_SMALL = auto()
    MASKED = auto()
    NARROW = auto()
    RUNTIME = auto()


@dataclass
class OperandDomain:
    kind: OperandKind
    upper: int = 0          # 静态上界 (0 表示无界)
    evidence: str = ""


@dataclass
class MulResult:
    can_overflow: bool
    reason: str
    dst_width: int = 64
    product_upper: Optional[int] = None


class MulDomainAnalyzer:
    """乘法域分析器 — 逐调用点判定 imul/shl 可溢出性."""

    def __init__(self, insns: list):
        self._insns = insns
        self._addr_to_idx = {ins.address: i for i, ins in enumerate(insns)}

    def analyze_imul(self, ins) -> MulResult:
        """imul 指令的可溢出性: 操作数域乘积 vs 目标位宽."""
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        width = 32 if (dst or "").startswith("e") else 64
        idx = self._addr_to_idx.get(ins.address, 0)
        if len(ops) == 3:
            # imul r, r2, imm — 常量乘数
            imm = InstructionParser._try_parse_int(ops[2])
            if imm is not None:
                d1 = self._classify_operand(idx, ops[1])
                return self._product(d1, OperandDomain(
                    OperandKind.CONST_SMALL, upper=abs(imm),
                    evidence=f"imm {hex(imm)}"), width, ins)
        # imul r, src — src 乘 dst 或乘 rax
        src = ops[1] if len(ops) >= 2 else ""
        d2 = self._classify_operand(idx, src)
        if len(ops) >= 2:
            return self._product(d2, d2, width, ins)
        return MulResult(True, f"imul {dst} implicit rax operand", width)

    def analyze_shl(self, ins) -> MulResult:
        """shl 指令: 移位量 ≥ 32 或 大移位 + RUNTIME 操作数 → 可疑."""
        ops = ins.operands
        dst = InstructionParser.normalize_reg(ops[0])
        width = 32 if (dst or "").startswith("e") else 64
        idx = self._addr_to_idx.get(ins.address, 0)
        shift = None
        if len(ops) >= 2:
            shift = InstructionParser._try_parse_int(ops[1])
        if shift is not None:
            if shift >= 32:
                return MulResult(True, f"shl {shift} >= 32", width)
            if shift <= 4:
                d = self._classify_operand(idx, ops[0])
                if d.kind in (OperandKind.CONST_SMALL, OperandKind.MASKED,
                              OperandKind.NARROW):
                    upper = d.upper << shift
                    if upper < (1 << 32):
                        return MulResult(False,
                                         f"shl {shift} bounded (<= {hex(upper)})",
                                         width, upper)
                return MulResult(True, f"shl {shift} on unbounded operand",
                                 width)
            return MulResult(True, f"shl {shift} large shift", width)
        # 寄存器移位量 — 不可静态确定
        d = self._classify_operand(idx, ops[0])
        if d.kind != OperandKind.RUNTIME:
            return MulResult(False, "shl with bounded operand", width,
                             d.upper << 8)
        return MulResult(True, "shl variable shift", width)

    # 内部

    def _product(self, d1: OperandDomain, d2: OperandDomain,
                 width: int, ins) -> MulResult:
        u1 = d1.upper
        u2 = d2.upper
        if d1.kind == OperandKind.RUNTIME or d2.kind == OperandKind.RUNTIME:
            if d1.kind != OperandKind.RUNTIME and u1 > 0 and \
                    u1 < (1 << 32):
                # 常量/掩码 × RUNTIME — 需 RUNTIME 侧上界, 无界则可疑
                if d2.kind != OperandKind.RUNTIME:
                    pass
            return MulResult(
                True,
                f"imul with runtime operand ({d1.evidence or d2.evidence})",
                width)
        if u1 > 0 and u2 > 0:
            prod = u1 * u2
            limit = (1 << 32) if width == 32 else (1 << 64)
            if prod < limit:
                return MulResult(False,
                                 f"bounded product <= {hex(prod)}",
                                 width, prod)
            return MulResult(True,
                             f"product may reach {hex(prod)} >= 2^{width}",
                             width, prod)
        return MulResult(True, "operand upper bound unknown", width)

    def _classify_operand(self, idx: int, op: str) -> OperandDomain:
        """沿 def-use 链分类操作数的数值域."""
        op = op.strip()
        imm = InstructionParser._try_parse_int(op)
        if imm is not None:
            return OperandDomain(OperandKind.CONST_SMALL, upper=abs(imm),
                                 evidence=f"imm {hex(imm)}")
        reg = InstructionParser.normalize_reg(op)
        if reg is None:
            return OperandDomain(OperandKind.RUNTIME, evidence=op)
        for j in range(idx - 1, max(0, idx - _WINDOW), -1):
            ins = self._insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]) != reg:
                continue
            src = ins.operands[1].strip()
            if mn == "and":
                m = InstructionParser._try_parse_int(src)
                if m is not None:
                    return OperandDomain(OperandKind.MASKED, upper=m,
                                         evidence=f"and {hex(m)}")
                return OperandDomain(OperandKind.RUNTIME,
                                     evidence="and reg")
            if mn in ("movzx",):
                return OperandDomain(OperandKind.NARROW, upper=0xFFFF,
                                     evidence="movzx 16-bit")
            if mn in ("movsx", "movsxd"):
                return OperandDomain(OperandKind.NARROW, upper=0xFFFF,
                                     evidence="movsx 16-bit")
            if mn in ("mov", "movabs"):
                m = InstructionParser._try_parse_int(src)
                if m is not None:
                    return OperandDomain(OperandKind.CONST_SMALL, upper=abs(m),
                                         evidence=f"imm {hex(m)}")
                base, _, _, off = \
                    InstructionParser.parse_memory_operand_full(src)
                if base in ("rbp", "rsp"):
                    # 栈槽来源: 追槽的 and 掩码/立即数写入
                    return self._classify_slot(idx=j, base=base,
                                               off=off)
                if base == "rip":
                    return OperandDomain(OperandKind.RUNTIME,
                                         evidence=f"mem [{base}]")
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._classify_operand(j, src_reg)
                return OperandDomain(OperandKind.RUNTIME, evidence="mem")
            if mn == "lea":
                return OperandDomain(OperandKind.RUNTIME, evidence="lea")
            if mn == "add":
                # add rax, rdx — 追源操作数, 上界保守放大 2 倍
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    d = self._classify_operand(j, src_reg)
                    if d.upper > 0:
                        d.upper *= 2
                        d.evidence += " (add-chain)"
                    return d
                return OperandDomain(OperandKind.RUNTIME, evidence="add imm")
            break
        return OperandDomain(OperandKind.RUNTIME, evidence="no def")

    def _classify_slot(self, idx: int, base: str,
                       off: int) -> OperandDomain:
        """栈槽数值域: 无条件路径上的最近修改.

        条件分支内的写入 (默认值初始化 / atoi 分支) 不构成
        实际约束 — 仅接受: 非 jcc target 且与读取点之间无 jcc
        的 and 掩码 / 立即数写入.
        """
        jcc_targets = set()
        for ins in self._insns:
            # 仅条件跳转的 target 是条件执行; jmp target 为
            # 无条件汇合点 (两条路径均可达)
            if ins.mnemonic.startswith("j") and \
                    ins.mnemonic != "jmp" and ins.operands:
                addr_part = ins.operands[0].strip().split()[0]
                try:
                    jcc_targets.add(int(addr_part, 16))
                except ValueError:
                    continue
        for j in range(idx - 1, max(0, idx - 12), -1):
            ins = self._insns[j]
            if len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]):
                continue
            wbase, _, _, woff = \
                InstructionParser.parse_memory_operand_full(ins.operands[0])
            if (wbase, woff) != (base, off):
                continue
            # 条件分支内写入 → 跳过 (另一路径可能覆盖)
            if ins.address in jcc_targets:
                continue
            has_jcc_between = any(
                self._insns[k].mnemonic.startswith("j")
                and self._insns[k].address > ins.address
                and self._insns[k].address < self._insns[idx].address
                for k in range(j + 1, idx))
            if has_jcc_between:
                continue
            src = ins.operands[1].strip()
            if ins.mnemonic == "and":
                m = InstructionParser._try_parse_int(src)
                if m is not None:
                    return OperandDomain(
                        OperandKind.MASKED, upper=m,
                        evidence=f"slot and {hex(m)}")
                return OperandDomain(OperandKind.RUNTIME,
                                     evidence="slot and reg")
            if ins.mnemonic == "mov":
                m = InstructionParser._try_parse_int(src)
                if m is not None:
                    return OperandDomain(
                        OperandKind.CONST_SMALL, upper=abs(m),
                        evidence=f"slot imm {hex(m)}")
                return OperandDomain(OperandKind.RUNTIME,
                                     evidence="slot <- reg")
            return OperandDomain(OperandKind.RUNTIME,
                                 evidence=f"slot [{base}+{hex(off)}]")
        return OperandDomain(OperandKind.RUNTIME, evidence="slot no write")


# smoke test
def _check():
    class _I:
        def __init__(self, addr, mn, ops):
            self.address = addr
            self.mnemonic = mn
            self.operands = ops

    # imul rax, rax, 0x30 — 常量乘数但被乘数无 def → 不可证 (保留)
    insns = [_I(0x1000, "imul", ["rax", "rax", "0x30"])]
    m = MulDomainAnalyzer(insns)
    r = m.analyze_imul(insns[0])
    assert r.can_overflow, "无 def 链的被乘数应保守判定"
    # and 掩码后 imul
    insns2 = [
        _I(0x1000, "mov", ["rax", "QWORD PTR [rbp+0x10]"]),
        _I(0x1004, "and", ["rax", "0xFFF"]),
        _I(0x1008, "imul", ["rax", "rax", "0x4"]),
    ]
    m2 = MulDomainAnalyzer(insns2)
    r2 = m2.analyze_imul(insns2[2])
    assert not r2.can_overflow, f"掩码约束应安全, got {r2.reason}"
    print("[OK] mul_domain: 掩码约束判定通过 (无def链保守保留)")


if __name__ == "__main__":
    _check()
