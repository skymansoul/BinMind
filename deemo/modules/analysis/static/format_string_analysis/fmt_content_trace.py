"""槽/堆内容溯源 — 栈槽常量初始化与堆内容写入链分类.

  _classify_slot   栈槽分类: 立即数序列初始化 → STACK_CONST;
                   参数槽 (rbp+0x10 起) → USER
  _heap_content    堆指针内容: mov [堆reg], imm 内联写入 →
                   HEAP_CONST; snprintf/sprintf 调用链 → 源参数分类
  _classify_copy   复制/格式化函数源参数: 任一 USER → USER
"""

import re
from enum import Enum, auto
from typing import Tuple

from ..heap_analysis.instruction_parser import InstructionParser


class FmtSource(Enum):
    RDATA = auto()
    STACK_CONST = auto()
    HEAP_CONST = auto()
    USER = auto()
    UNKNOWN = auto()

_COPY_FUNCS = {"strcpy", "strncpy", "strcat", "memcpy", "memmove",
               "sprintf", "snprintf", "strdup", "strndup",
               "__mingw_sprintf", "__mingw_snprintf", "__mingw_vsprintf",
               "__mingw_vsnprintf", "__mingw_memcpy"}
_INPUT_FUNCS = {"gets", "fgets", "recv", "read", "fread", "getline",
                "scanf", "fscanf"}


class SlotContentTracer:
    """槽内容与堆内容溯源 — 由 FmtProvenance 委派调用."""

    def __init__(self, insns: list, chase):
        self._insns = insns
        self._chase = chase  # FmtProvenance._chase 绑定方法

    def classify_slot(self, def_idx: int, base: str, off: int,
                      seen: set) -> Tuple[FmtSource, str]:
        """栈槽分类: 立即数初始化序列 → STACK_CONST; 参数槽 → USER."""
        # 参数槽 (rbp+0x10 起为栈参数)
        if base == "rbp" and off >= 0x10:
            return FmtSource.USER, f"stack arg slot [rbp+{hex(off)}]"
        const_writes = 0
        for j in range(def_idx - 1, max(0, def_idx - 12), -1):
            ins = self._insns[j]
            if ins.mnemonic != "mov" or len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]):
                continue
            dbase, _, _, doff = \
                InstructionParser.parse_memory_operand_full(ins.operands[0])
            if (dbase, doff) != (base, off):
                continue
            src = ins.operands[1].strip()
            if InstructionParser._try_parse_int(src) is not None:
                const_writes += 1
            elif InstructionParser.normalize_reg(src) is not None:
                r = InstructionParser.normalize_reg(src)
                s, _ = self._chase(j, r, 3, seen)
                if s == FmtSource.RDATA:
                    return FmtSource.STACK_CONST, \
                        f"slot [{base}+{hex(off)}] <- .rdata reg"
                if s != FmtSource.UNKNOWN:
                    return s, f"slot [{base}+{hex(off)}] <- reg"
                # 寄存器来源未解析 (malloc 返回) → 落到堆内容检查
            else:
                break
        if const_writes >= 2:
            return FmtSource.STACK_CONST, \
                f"slot [{base}+{hex(off)}] inlined string const"
        if const_writes == 1:
            return FmtSource.STACK_CONST, \
                f"slot [{base}+{hex(off)}] single imm init"
        return self.heap_content(def_idx, base, off, seen)

    def heap_content(self, def_idx: int, base: str, off: int,
                     seen: set) -> Tuple[FmtSource, str]:
        """堆指针内容的常量性: mov [堆reg], imm 连续写入 或
        格式化/复制函数调用链 (snprintf 源参数分类)."""
        heap_reg = None
        load_idx = -1
        for j in range(def_idx - 1, max(0, def_idx - 12), -1):
            ins = self._insns[j]
            if ins.mnemonic != "mov" or len(ins.operands) < 2:
                continue
            dst = InstructionParser.normalize_reg(ins.operands[0])
            if not dst:
                continue
            sbase, _, _, soff = \
                InstructionParser.parse_memory_operand_full(ins.operands[1])
            if (sbase, soff) == (base, off):
                heap_reg = dst
                load_idx = j
                break
        if heap_reg is None:
            return FmtSource.UNKNOWN, "heap ptr load not found"
        for j in range(load_idx + 1, min(load_idx + 20, len(self._insns))):
            ins = self._insns[j]
            if ins.mnemonic != "mov" or len(ins.operands) < 2:
                continue
            if InstructionParser.normalize_reg(ins.operands[0]):
                continue
            tbase, _, _, _ = \
                InstructionParser.parse_memory_operand_full(ins.operands[0])
            if tbase != heap_reg:
                continue
            src = ins.operands[1].strip()
            imm = InstructionParser._try_parse_int(src)
            if imm is not None:
                return FmtSource.HEAP_CONST, \
                    f"heap content imm-write @{hex(ins.address)}"
            src_reg = InstructionParser.normalize_reg(src)
            if src_reg:
                s, _ = self._chase(j, src_reg, 3, seen)
                if s == FmtSource.RDATA:
                    return FmtSource.HEAP_CONST, \
                        f"heap content <- .rdata reg @{hex(ins.address)}"
                return s, f"heap content <- reg @{hex(ins.address)}"
            break
        # 无直接 mov 写入 → 查找对堆的格式化/复制函数调用.
        # 写入调用可能早于最后一次指针加载 — 窗口覆盖调用前 24 条
        lo = max(0, load_idx - 24)
        hi = min(load_idx + 8, len(self._insns))
        for j in range(lo, hi):
            ins = self._insns[j]
            if ins.mnemonic != "call":
                continue
            callee = InstructionParser.extract_callee(ins)
            if callee not in _COPY_FUNCS:
                continue
            s, _ = self.classify_copy(j, callee, seen)
            if s != FmtSource.UNKNOWN:
                return s, f"heap content via {callee} @{hex(ins.address)}"
        return FmtSource.UNKNOWN, "heap content writes unresolved"

    def classify_copy(self, call_idx: int, callee: str,
                      seen: set) -> Tuple[FmtSource, str]:
        """复制/格式化函数源参数分类.

        strcpy/strncpy: 源=rsi/rdx; snprintf 家族: 格式串=r8,
        数据参数=r9 起 — 任一源参数为 USER → 目标内容用户可控.
        """
        src_regs = ("rsi", "rdx")
        if "snprintf" in callee or "sprintf" in callee \
                or "vsnprintf" in callee:
            src_regs = ("r8", "r9", "rsi", "rdx")
        candidate = None
        candidate_ev = ""
        for r in src_regs:
            src_op = None
            for j in range(call_idx - 1, max(0, call_idx - 14), -1):
                ins = self._insns[j]
                if ins.mnemonic not in ("mov", "movabs", "lea") or \
                        len(ins.operands) < 2:
                    continue
                if InstructionParser.normalize_reg(ins.operands[0]) == r:
                    src_op = ins.operands[1].strip()
                    break
            if src_op is None:
                continue
            base, _, _, _ = \
                InstructionParser.parse_memory_operand_full(src_op)
            if base == "rip":
                continue  # .rdata 常量源, 继续查其它参数
            if base in ("rbp", "rsp"):
                if base == "rbp" and self._slot_off(src_op) >= 0x10:
                    return FmtSource.USER, \
                        f"{callee} arg{r} <- stack param slot"
                s, _ = self.classify_slot(call_idx, base,
                                          self._slot_off(src_op), seen)
                if s != FmtSource.UNKNOWN:
                    candidate = s
                    candidate_ev = f"{callee} arg{r} slot"
                continue
            reg = InstructionParser.normalize_reg(src_op)
            if reg:
                s, _ = self._chase(j, reg, 3, seen)
                if s == FmtSource.USER:
                    return FmtSource.USER, f"{callee} arg{r} <- user"
                if s != FmtSource.UNKNOWN:
                    candidate = s
                    candidate_ev = f"{callee} arg{r} <- {s.name}"
        if candidate is not None:
            return candidate, candidate_ev
        return FmtSource.UNKNOWN, f"{callee} sources unresolved"

    @staticmethod
    def _slot_off(op: str) -> int:
        m = re.search(r"\[(?:rbp|rsp)\s*([+-]\s*0x[0-9a-f]+)\]", op)
        if m:
            try:
                return int(m.group(1).replace(" ", ""), 16)
            except ValueError:
                return 0
        return 0


# smoke test
def _check():
    class _I:
        def __init__(self, addr, mn, ops, raw=""):
            self.address = addr
            self.mnemonic = mn
            self.operands = ops
            self.raw_line = raw

    insns = [
        _I(0x1000, "mov", ["[rbp-0x8]", "0x6c6c6568"]),
        _I(0x1008, "mov", ["[rbp-0x4]", "0x6f"]),
    ]
    tracer = SlotContentTracer(insns, lambda *a, **k: (FmtSource.UNKNOWN, ""))
    s, e = tracer.classify_slot(1, "rbp", -8, set())
    assert s == FmtSource.STACK_CONST, f"内联字符串应 STACK_CONST, got {s}"
    print("[OK] fmt_content_trace: 槽常量识别通过")


if __name__ == "__main__":
    _check()
