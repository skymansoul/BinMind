"""写入大小界定 — def-use 链逆向追迹, 为危险调用点计算写入大小上界.

误报根源: absint_adjudicator 对静态未知的写入大小 (size_val=0) 一律报告.
本模块沿 def-use 链逆向追迹 (mov 传递 / and 掩码 / sub 下移 / 移位),
配合反向守卫窄化 (backward_constraint), 得到写入大小的 (lo, hi) 上界;
并为 strcpy 家族估计源字符串长度 (.rodata 定位, 需二进制路径).

设计决策:
  - 追迹窗口 25 条指令, 寄存器链 8 跳 — 覆盖常见 size = f(imm) 形态
  - 遇到 imul/mul/call/内存加载 → 放弃链式追迹 (不可安全界定)
  - 上界无法界定且无守卫 → 返回 UNBOUNDED, 交由融合判定器处理
"""

import re
import subprocess
from dataclasses import dataclass
from typing import Dict, List, Optional, Set, Tuple

from .instruction_parser import InstructionParser, ParsedInstruction
from .backward_constraint import BackwardConstraintNarrower

_WINDOW = 25
_MAX_HOPS = 8
_UNBOUNDED = 2 ** 63 - 1

# 危险调用 → 大小参数寄存器 (SysV 优先, 兼容 Win64)
_SIZE_REGS_BY_FUNC = {
    "memcpy": ("rdx", "r8"), "memmove": ("rdx", "r8"),
    "memset": ("rdx", "r8"), "strncpy": ("rdx", "r8"),
    "snprintf": ("rdx", "r8"), "__memcpy_chk": ("rdx", "r8"),
    "read": ("rdx", "r8"), "fread": ("rdx", "r8"),
    "recv": ("rdx", "r8"), "strcat": (), "strcpy": (),
    "sprintf": (), "gets": (),
}

# 无显式大小的函数 → 需源长度估计
_LEN_ESTIMATED = {"strcpy", "strcat", "sprintf", "gets"}

_STRIP_RE = re.compile(r"\s+")
_HEXDUMP_RE = re.compile(r"^\s*([0-9a-f]+)\s+((?:[0-9a-f]{2,8}\s+)+)")


@dataclass
class BoundResult:
    """写入大小界定结果."""
    lo: int = 0
    hi: int = _UNBOUNDED
    bounded: bool = False
    depth: int = 0
    source_kind: str = "unbounded"   # immediate / chain / guard / rodata / unbounded


class WriteSizeBounder:
    """写入大小界定器 — 逆向 def-use 链 + 守卫窄化 + 源长度估计."""

    def __init__(self, binary_path: Optional[str] = None):
        self._binary_path = binary_path
        self._narrower = BackwardConstraintNarrower()
        self._rodata: Optional[Dict[int, bytes]] = None

    # 公共入口

    def bound(self, insns: List[ParsedInstruction], call_idx: int,
              func: str) -> BoundResult:
        """对危险调用点计算写入大小上界."""
        size_regs = _SIZE_REGS_BY_FUNC.get(func, ())
        if not size_regs:
            return BoundResult()
        for reg in size_regs:
            res = self._chase(insns, call_idx, reg, _MAX_HOPS)
            if res.bounded:
                return res
            if res.source_kind == "immediate":
                return res
        # 链式追迹失败 → 守卫窄化
        for reg in size_regs:
            lo, hi = self._narrower.narrow(insns, call_idx, reg)
            if hi < _UNBOUNDED:
                return BoundResult(lo=max(0, lo), hi=hi, bounded=True,
                                   source_kind="guard")
        return BoundResult()

    def source_len(self, insns: List[ParsedInstruction],
                   call_idx: int, src_reg: str) -> Optional[int]:
        """估计无大小参数函数的源字符串长度 (rodata 定位)."""
        addr = self._resolve_src_addr(insns, call_idx, src_reg)
        if addr is None:
            return None
        data = self._load_rodata()
        if not data:
            return None
        length = 0
        while addr + length in data and length < 1024:
            if data[addr + length] == 0:
                break
            length += 1
        return length + 1 if length < 1024 else None

    # def-use 链追迹

    def _chase(self, insns: List[ParsedInstruction], call_idx: int,
               reg: str, hops_left: int) -> BoundResult:
        if hops_left <= 0:
            return BoundResult()
        start = max(0, call_idx - _WINDOW)
        for j in range(call_idx - 1, start - 1, -1):
            ins = insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst != reg:
                continue
            src = ins.operands[1].strip()
            if mn in ("mov", "movabs"):
                imm = InstructionParser._try_parse_int(src)
                if imm is not None:
                    return BoundResult(lo=imm, hi=imm, bounded=True,
                                       depth=_MAX_HOPS - hops_left,
                                       source_kind="immediate")
                src_reg = InstructionParser.normalize_reg(src)
                if src_reg:
                    return self._chase(insns, j, src_reg, hops_left - 1)
                return BoundResult()          # 内存加载 → 不可界定
            if mn == "and":
                imm = InstructionParser._try_parse_int(src)
                if imm is not None:
                    return BoundResult(lo=0, hi=imm, bounded=True,
                                       depth=_MAX_HOPS - hops_left,
                                       source_kind="chain")
                return BoundResult()
            if mn == "sub":
                imm = InstructionParser._try_parse_int(src)
                src_reg = InstructionParser.normalize_reg(src)
                if imm is not None:
                    base = self._chase(insns, j, reg, hops_left - 1)
                    if base.bounded:
                        base.lo = max(0, base.lo - imm)
                        base.hi = base.hi - imm
                        base.depth += 1
                    return base
                if src_reg:
                    return BoundResult()      # reg-reg sub → 不可界定
            if mn == "shr":
                imm = InstructionParser._try_parse_int(src)
                if imm is not None:
                    base = self._chase(insns, j, reg, hops_left - 1)
                    if base.bounded:
                        base.hi >>= imm
                        base.lo >>= imm
                        base.depth += 1
                    return base
            if mn in ("movzx", "movsx"):
                return BoundResult(lo=0, hi=0xFF, bounded=True,
                                   depth=_MAX_HOPS - hops_left,
                                   source_kind="chain")
            if mn == "lea":
                base, _, _, off = InstructionParser.parse_memory_operand_full(src)
                if base:
                    base_res = self._chase(insns, j, base, hops_left - 1)
                    if base_res.bounded:
                        base_res.lo += off
                        base_res.hi += off
                        base_res.depth += 1
                    return base_res
                return BoundResult()
            if mn in ("imul", "mul", "shl", "call", "add"):
                return BoundResult()          # 乘法/调用 → 不可安全界定
            break
        return BoundResult()

    # 源地址解析 + rodata 加载

    def _resolve_src_addr(self, insns: List[ParsedInstruction],
                          call_idx: int, src_reg: str) -> Optional[int]:
        """解析源寄存器指向的字符串地址."""
        start = max(0, call_idx - _WINDOW)
        for j in range(call_idx - 1, start - 1, -1):
            ins = insns[j]
            mn = ins.mnemonic
            if len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if dst != src_reg:
                continue
            src = ins.operands[1].strip()
            imm = InstructionParser._try_parse_int(src)
            if imm is not None:
                return imm
            base, _, _, off = InstructionParser.parse_memory_operand_full(src)
            if base == "rip":
                next_addr = ins.address + self._insn_len(ins)
                return next_addr + off
            if base:
                return self._resolve_src_addr(insns, j, base)
            src_reg2 = InstructionParser.normalize_reg(src)
            if src_reg2:
                return self._resolve_src_addr(insns, j, src_reg2)
            break
        return None

    @staticmethod
    def _insn_len(ins: ParsedInstruction) -> int:
        m = re.match(r"^\s*[0-9a-f]+:\s+((?:[0-9a-f]{2}\s+)+)", ins.raw_line)
        if m:
            return len(m.group(1).split())
        return 0

    def _load_rodata(self) -> Optional[Dict[int, bytes]]:
        """objdump -s 加载只读数据段 → {虚拟地址: 字节}."""
        if self._rodata is not None:
            return self._rodata
        if not self._binary_path:
            self._rodata = {}
            return self._rodata
        try:
            r = subprocess.run(
                ["objdump", "-s", "-j", ".rodata", self._binary_path],
                capture_output=True, text=True, timeout=20)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            self._rodata = {}
            return self._rodata
        data: Dict[int, bytes] = {}
        for line in r.stdout.split("\n"):
            m = _HEXDUMP_RE.match(line)
            if not m:
                continue
            try:
                addr = int(m.group(1), 16)
            except ValueError:
                continue
            blob = bytearray()
            for hexgrp in m.group(2).split():
                try:
                    blob.extend(bytes.fromhex(hexgrp))
                except ValueError:
                    continue
            for k, b in enumerate(blob):
                data[addr + k] = b
        self._rodata = data
        return data


# smoke test
def _check():
    asm = """
    1100:       b8 00 01 00 00          mov    eax,0x100
    1105:       48 89 c2                mov    rdx,rax
    1108:       83 ea 10                sub    edx,0x10
    110b:       e8 f0 fe ff ff          call   memcpy
    """
    insns = InstructionParser.parse(asm)
    call_idx = next(i for i, x in enumerate(insns) if x.mnemonic == "call")
    b = WriteSizeBounder()
    res = b.bound(insns, call_idx, "memcpy")
    assert res.bounded and res.hi == 0xF0, f"expected hi=0xf0, got {res}"
    print(f"[OK] write_size_bound: memcpy size bounded to 0x{res.hi:x}")


if __name__ == "__main__":
    _check()
