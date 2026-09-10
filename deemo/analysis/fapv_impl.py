# FAPV — Format-Argument Provenance Verifier (格式串来源验证器).
#
# 决策逻辑:
#   格式化字符串误报源于"非 .rdata 来源一律视为用户可控"的粗判:
#     栈槽常量初始化 (char fmt[]="val=%d") 与只读字面量指针被误报.
#   本模块沿格式串寄存器的后向定义链分类来源, 输出三级判定:
#     BENIGN     — 定义链到达 lea [rip+off] / mov r, imm(字面量地址)
#                  或常量初始化的栈槽 → 字面量.
#     CONFIRMED  — 定义链到达参数槽/参数派生内存/输入与复制函数
#                  填充缓冲 → 用户可控.
#     SUSPECTED  — call 返回值或不可解析内存加载 → 无法确认, 降级.
#   仅 CONFIRMED 计入检出, 与 PcWBI/ULPR 三级判定同机制.
#
#   本文件实现 FAPV 核心管线: 共享常量 → 定义链追踪 → 验证器.


import re
from typing import Dict, List, Optional, Tuple


# 共享常量

class FmtVerdict:
    CONFIRMED = "confirmed"
    SUSPECTED = "suspected"
    BENIGN = "benign"


# puts 不解析格式串, 非格式化字符串汇点.
PRINTF_FAMILY = {
    "printf", "fprintf", "sprintf", "snprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf",
    "dprintf", "vdprintf",
    "__mingw_printf", "__mingw_fprintf", "__mingw_sprintf",
    "__mingw_snprintf", "__mingw_vprintf", "__mingw_vfprintf",
    "__mingw_vsprintf", "__mingw_vsnprintf",
}

# 格式串参数索引: printf=0, fprintf/dprintf=1, snprintf/vsnprintf=2.
FMT_ARG_IDX = {
    "printf": 0, "vprintf": 0, "dprintf": 0, "vdprintf": 0,
    "sprintf": 1, "fprintf": 1, "vfprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}

ARG_REGS_WIN64 = ("rcx", "rdx", "r8", "r9")
ARG_REGS_SYSV = ("rdi", "rsi", "rdx", "rcx")

# 输入函数: 返回值/写入缓冲为攻击者可控.
INPUT_FUNCS = {"gets", "scanf", "__isoc99_scanf", "recv", "recvfrom",
               "read", "fgets", "fread", "getenv", "strtok"}

# 定义链追踪

_COPY_FUNCS = {"strcpy", "strncpy", "memcpy", "memmove", "strcat",
               "sprintf", "snprintf", "strdup", "strndup"}
_WINDOW = 60


class FmtChainMixin:
    """定义链追踪方法, 由 FmtArgVerifier 继承."""

    def _chase(self, idx: int, reg: str, hops: int,
               seen: set) -> Tuple[str, str]:
        if hops <= 0 or (idx, reg) in seen:
            return FmtVerdict.SUSPECTED, "chain depth exceeded"
        seen.add((idx, reg))
        start = max(0, idx - _WINDOW)
        for j in range(idx - 1, start - 1, -1):
            ins = self._insns[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            dst = self._norm(ops[0])
            if dst != reg:
                continue
            src = ops[1].strip()
            a = ins.get("address", 0)

            if mnem in ("lea",):
                if "rip" in src.lower():
                    return FmtVerdict.BENIGN, f"lea {reg},[rip+off]@{a:x}"
                slot = self._slot_key(src)
                if slot:
                    return self._chase_stack_buffer(j, slot, hops - 1, seen)
                return FmtVerdict.SUSPECTED, f"lea {reg},{src}@{a:x}"

            if mnem in ("mov", "movabs", "movzx", "movsx", "movsxd"):
                imm = self._parse_imm(src)
                if imm is not None:
                    return FmtVerdict.BENIGN, f"mov {reg},const@{a:x}"
                src_reg = self._norm(src)
                if src_reg:
                    if self._is_arg_slot(src):
                        return FmtVerdict.CONFIRMED, \
                            f"from arg slot {src}@{a:x}"
                    return self._chase(j, src_reg, hops - 1, seen)
                if "rip" in src.lower():
                    return FmtVerdict.BENIGN, f"mov {reg},[rip+off]@{a:x}"
                if self._is_arg_slot(src):
                    return FmtVerdict.CONFIRMED, f"from arg slot {src}@{a:x}"
                slot = self._slot_key(src)
                if slot:
                    return self._chase_slot(j, slot, hops - 1, seen)
                base = self._mem_base(src)
                if base:
                    if self._is_param_derived(j, base):
                        return FmtVerdict.CONFIRMED, \
                            f"from param-derived mem {src}@{a:x}"
                    return self._chase(j, base, hops - 1, seen)
                return FmtVerdict.SUSPECTED, f"mov {reg} from mem@{a:x}"

            if mnem == "call":
                callee = self._callee(ops[0])
                if callee in INPUT_FUNCS:
                    return FmtVerdict.CONFIRMED, f"{callee}()@{a:x}"
                if reg in ("rax", "eax"):
                    return FmtVerdict.SUSPECTED, f"call {callee} result@{a:x}"
                continue

            # 算术/地址运算保留指针链语义.
            if mnem in ("add", "sub", "and", "or", "xor", "shl", "shr",
                       "inc", "dec", "imul", "neg", "not", "cdqe", "cdq"):
                continue
            break
        if reg in self._args:
            return FmtVerdict.CONFIRMED, f"function parameter {reg}"
        return FmtVerdict.SUSPECTED, f"no def in window for {reg}"

    def _is_param_derived(self, idx: int, reg: str) -> bool:
        """判定寄存器是否经拷贝链派生自函数入口参数."""
        cur = reg
        for j in range(idx - 1, max(0, idx - _WINDOW) - 1, -1):
            ins = self._insns[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            if self._norm(ops[0]) != cur:
                continue
            if mnem in ("mov", "movabs", "movzx", "movsx", "movsxd"):
                src_reg = self._norm(ops[1].strip())
                if src_reg:
                    cur = src_reg
                    continue
                return False
            return False
        return cur in self._args

    def _chase_slot(self, store_idx: int, slot: str, hops: int,
                    seen: set) -> Tuple[str, str]:
        """栈槽内容的来源: 找该槽最近一次写入, 判定其初始化来源."""
        if hops <= 0:
            return FmtVerdict.SUSPECTED, "slot chain depth exceeded"
        for j in range(store_idx - 1, -1, -1):
            ins = self._insns[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            dst = ops[0].strip()
            if "[" not in dst.lower() or mnem != "mov":
                continue
            if self._slot_key(dst) != slot:
                continue
            src = ops[1].strip()
            a = ins.get("address", 0)
            src_reg = self._norm(src)
            if src_reg:
                if self._is_arg_slot(src):
                    return FmtVerdict.CONFIRMED, f"slot {slot}<-argv@{a:x}"
                return self._chase(j, src_reg, hops - 1, seen)
            if "rip" in src.lower():
                return FmtVerdict.BENIGN, f"slot {slot}<-rdata@{a:x}"
            if self._parse_imm(src) is not None:
                return FmtVerdict.BENIGN, f"slot {slot}<-const@{a:x}"
            return FmtVerdict.SUSPECTED, f"slot {slot}<-mem@{a:x}"
        return FmtVerdict.SUSPECTED, f"slot {slot} write not found"

    def _chase_stack_buffer(self, idx: int, slot: str, hops: int,
                            seen: set) -> Tuple[str, str]:
        """栈缓冲内容来源: 全为常量写入则 BENIGN, 输入/复制填充则 CONFIRMED."""
        if hops <= 0:
            return FmtVerdict.SUSPECTED, "buffer chain depth exceeded"
        start = max(0, idx - _WINDOW)
        const_seen = False
        uncertain = False
        for j in range(idx - 1, start - 1, -1):
            ins = self._insns[j]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call" and ops:
                bv = self._buffer_call_verdict(j, slot, hops, seen)
                if bv is not None:
                    return bv
                continue
            if len(ops) < 2:
                continue
            dst = ops[0].strip()
            if "[" not in dst.lower():
                continue
            if self._slot_key(dst) != slot:
                continue
            if mnem not in ("mov", "movabs", "movzx", "movsx"):
                continue
            src = ops[1].strip()
            a = ins.get("address", 0)
            if self._parse_imm(src) is not None:
                const_seen = True
                continue
            src_reg = self._norm(src)
            if src_reg:
                if self._is_arg_slot(src):
                    return FmtVerdict.CONFIRMED, f"buf {slot}<-argv@{a:x}"
                v, r = self._chase(j, src_reg, hops - 1, seen)
                if v == FmtVerdict.CONFIRMED:
                    return v, r
                if v == FmtVerdict.BENIGN:
                    const_seen = True
                else:
                    uncertain = True
                continue
            uncertain = True
        if const_seen and not uncertain:
            return FmtVerdict.BENIGN, f"buf {slot} constant-initialized"
        return FmtVerdict.SUSPECTED, f"buf {slot} init not resolvable"

    def _buffer_call_verdict(self, idx: int, slot: str, hops: int,
                             seen: set):
        """判定缓冲是否被输入/复制调用写入: arg0 指向缓冲."""
        ins = self._insns[idx]
        ops = ins.get("operands", [""])
        if not ops:
            return None
        callee = self._callee(ops[0])
        if callee not in INPUT_FUNCS and callee not in _COPY_FUNCS:
            return None
        arg1 = self._args[1] if len(self._args) > 1 else ""
        if not self._arg0_is_buffer(idx, slot):
            return None
        if callee in INPUT_FUNCS:
            return FmtVerdict.CONFIRMED, \
                f"buf filled by {callee}@{hex(ins.get('address', 0))}"
        if arg1:
            return self._chase(idx, arg1, hops - 1, seen)
        return FmtVerdict.SUSPECTED, "copy source unknown"

    def _arg0_is_buffer(self, idx: int, slot: str) -> bool:
        """判定调用 arg0 (rcx/rdi) 是否指向缓冲: 跟随 lea/mov 链."""
        cur = self._args[0]
        for k in range(idx - 1, max(0, idx - 12) - 1, -1):
            k_ins = self._insns[k]
            km = k_ins.get("mnemonic", "").lower()
            ko = k_ins.get("operands", [])
            if len(ko) < 2:
                continue
            if self._norm(ko[0]) != cur:
                continue
            src = ko[1].strip()
            if self._slot_key(src) == slot:
                return True
            if km == "lea":
                return "rip" in src.lower()
            src_reg = self._norm(src)
            if src_reg:
                cur = src_reg
                continue
            return False
        return False

    @staticmethod
    def _callee(op: str) -> str:
        t = op.strip().lower()
        for p in ("call ", "callq "):
            if t.startswith(p):
                t = t[len(p):]
        if "<" in t and ">" in t:
            t = t.split("<")[1].split(">")[0]
        return t.split("@")[0].split("(")[0].split(".")[-1]

    @staticmethod
    def _norm(op: str) -> str:
        o = op.strip().lower().lstrip("%").lstrip("$")
        if "[" in o or "(" in o:
            return ""
        return o

    @staticmethod
    def _parse_imm(s: str) -> Optional[int]:
        s = s.strip().lower().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None

    @staticmethod
    def _slot_key(operand: str) -> Optional[str]:
        op = operand.strip().lower()
        op = re.sub(r"(qword|dword|word|byte)\s+ptr\s+", "", op)
        m = re.search(r"\[(r[bs]p[+-]0x[0-9a-f]+)\]", op.replace(" ", ""))
        return m.group(1) if m else None

    def _is_arg_slot(self, operand: str) -> bool:
        """正偏移 rbp/rsp 槽为调用方参数区 (含帧重定位后的 argv 槽).

        O0 常见 lea rbp,[rsp+0x80] 后 argc/argv 驻留 rbp+0xb0/0xb8.
        """
        slot = self._slot_key(operand)
        if slot is None:
            return False
        if slot in self._arg_slots:
            return True
        m = re.match(r"rbp\+0x([0-9a-f]+)", slot)
        if m and int(m.group(1), 16) >= 0x8:
            return True
        m = re.match(r"rsp\+0x([0-9a-f]+)", slot)
        if m and int(m.group(1), 16) >= 0x20:
            return True
        return False

    @staticmethod
    def _mem_base(operand: str) -> str:
        op = operand.strip().lower()
        m = re.search(r"\[([a-z0-9]+)", op)
        return m.group(1) if m else ""


# 验证器

_MAX_HOPS = 8


class FmtArgVerifier(FmtChainMixin):
    """格式串参数来源验证器."""

    def __init__(self, instructions: List[dict], use_win64: bool = False):
        self._insns = instructions
        self._args = ARG_REGS_WIN64 if use_win64 else ARG_REGS_SYSV
        self._idx_map = {ins.get("address", i): i
                         for i, ins in enumerate(instructions)}
        self._arg_slots = ("rbp+0x10", "rbp+0x18", "rsp+0x10", "rsp+0x18")

    def verify(self, addr: int, func: str) -> Tuple[str, str]:
        """对 printf 调用点验证格式串参数来源."""
        base = func.replace("__mingw_", "")
        base = base[1:] if base.startswith("v") and base != "vfprintf" \
            else base
        fmt_idx = FMT_ARG_IDX.get(base, 0)
        if fmt_idx >= len(self._args):
            return FmtVerdict.SUSPECTED, "fmt arg beyond tracked regs"
        fmt_reg = self._args[fmt_idx]
        idx = self._idx_map.get(addr)
        if idx is None:
            return FmtVerdict.SUSPECTED, "call address not in stream"
        return self._chase(idx, fmt_reg, _MAX_HOPS, set())


__all__ = ["FmtVerdict", "PRINTF_FAMILY", "FMT_ARG_IDX",
           "ARG_REGS_WIN64", "ARG_REGS_SYSV", "INPUT_FUNCS",
           "FmtChainMixin", "FmtArgVerifier"]
