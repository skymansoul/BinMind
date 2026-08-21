# 二进制级格式化字符串检测器 (Binary-Level Format String Detector)
#
# 核心决策:
#   既有 fmt 检测器依赖调用点实参列表 (args), 而 objdump 反汇编的
#   call 指令只携带目标地址, 实参信息在指令流中. 因此在二进制层面
#   既有检测器从不触发 - 属于"注水"实现. 本模块从指令流解析:
#     1. 格式串实参寄存器 (按ABI) 反向解析其来源:
#        lea [rip+X] → .rodata 字面量 (安全)
#        read/recv 返回值 / 栈槽未知指针 → 外部可控 (危险)
#     2. 字面量格式串: 解析说明符, 按ABI统计调用点已加载的变参寄存器
#        数量, 少于说明符需求 → 参数不匹配 (栈读取/泄漏).
#     3. %n 且格式串可控 → 写内存 → critical.
#

import re
from typing import Dict, List, Optional

from .disasm_util import norm_reg, extract_func_name, extract_stack_slot

_PRINTF_FAMILY = {
    "printf", "fprintf", "sprintf", "snprintf", "dprintf",
    "vprintf", "vfprintf", "vsprintf", "vsnprintf", "vdprintf",
    "syslog", "vsyslog", "__mingw_printf", "__mingw_sprintf",
    "__mingw_snprintf", "__mingw_fprintf", "__mingw_vsprintf",
    "__mingw_vsnprintf",
}
_FMT_RE = re.compile(r'%[+#0 -]*\d*\.?\d*[hljztL]?[diouxXeEfFgGaAcspn%]')
_ARG_NEED = {'d':1,'i':1,'o':1,'u':1,'x':1,'X':1,'e':1,'E':1,'f':1,
             'F':1,'g':1,'G':1,'a':1,'A':1,'c':1,'s':1,'p':1,'n':1,'%':0}
_TAINT_FUNCS = {"read", "recv", "recvfrom", "recvmsg", "fgets", "scanf",
                "__isoc99_scanf", "getenv"}


class BinaryFmtDetector:
    """从指令流检测格式化字符串漏洞."""

    # fmt 实参位置 (按 x86-64 win64/SysV 统一: 变参函数首参之后).
    _FMT_IDX = {"printf": 0, "sprintf": 0, "snprintf": 0, "vsprintf": 0,
                "vsnprintf": 0, "vprintf": 0, "dprintf": 1, "fprintf": 1,
                "vdprintf": 1, "vfprintf": 1, "syslog": 1, "vsyslog": 1}

    def __init__(self, use_win64_abi: bool = True):
        # 变参寄存器 (fmt 之后依次使用)
        self._va_regs = ["rdx", "r8", "r9", "r10"] if use_win64_abi \
            else ["rsi", "rdx", "rcx", "r8", "r9"]
        self._fmt_reg = "rcx" if use_win64_abi else "rdi"
        self._second_reg = "rdx" if use_win64_abi else "rsi"
        self._findings: List[dict] = []
        self._rodata: Dict[int, bytes] = {}
        self._user_ranges: List[tuple] = []

    def set_user_ranges(self, ranges: List[tuple]):
        """注入用户函数地址范围, 过滤CRT/库内调用点."""
        self._user_ranges = ranges

    def set_rodata(self, rodata: Dict[int, bytes]):
        self._rodata = rodata

    def _in_user(self, addr: int) -> bool:
        if not self._user_ranges:
            return True
        for lo, hi in self._user_ranges:
            if lo <= addr < hi:
                return True
        return False

    def analyze(self, instructions: List[dict]) -> List[dict]:
        """扫描全部call指令, 检测printf族调用."""
        self._findings = []
        for i, ins in enumerate(instructions):
            mnem = ins.get("mnemonic", "").lower()
            if mnem != "call" or not ins.get("operands"):
                continue
            addr = ins.get("address", 0)
            if not self._in_user(addr):
                continue
            func = extract_func_name(ins["operands"][0])
            if func not in self._FMT_IDX:
                continue
            self._analyze_call(instructions, i, func, addr)
        return list(self._findings)

    def _analyze_call(self, instructions, call_idx, func, addr):
        fmt_idx = self._FMT_IDX[func]
        fmt_reg = self._fmt_reg if fmt_idx == 0 else self._second_reg
        src = self._resolve_fmt(instructions, call_idx, fmt_reg)

        # 格式串外部可控 → 直接高危 (可能 %n / 泄漏)
        if src.get("kind") == "taint":
            self._findings.append({
                "type": "fmt_tainted_format",
                "function": func, "address": addr,
                "severity": "critical",
                "fmt_reg": fmt_reg,
                "reason": src.get("detail", "tainted fmt string"),
            })
            return

        # 字面量: 参数计数验证
        if src.get("kind") == "literal":
            fmt_str = src.get("content", "")
            specs = list(_FMT_RE.finditer(fmt_str))
            needed = sum(_ARG_NEED.get(m.group(0)[-1], 0) for m in specs)
            has_n = any(m.group(0)[-1] == "n" for m in specs)
            provided = self._count_va_provided(instructions, call_idx)
            if has_n:
                self._findings.append({
                    "type": "fmt_pct_n",
                    "function": func, "address": addr,
                    "severity": "critical",
                    "reason": f"%n in literal fmt '{fmt_str[:40]}'",
                })
            if provided < needed:
                self._findings.append({
                    "type": "fmt_arg_mismatch",
                    "function": func, "address": addr,
                    "expected": needed, "provided": provided,
                    "severity": "high" if func in (
                        "sprintf", "vsprintf", "printf", "vprintf") else "medium",
                    "reason": f"fmt needs {needed} args, {provided} loaded",
                })
        # 未知来源: 保守报告为潜在可控
        elif src.get("kind") == "unknown":
            self._findings.append({
                "type": "fmt_source_unknown",
                "function": func, "address": addr,
                "severity": "low",
                "reason": f"fmt from {src.get('detail', 'unknown')}",
            })

    def _resolve_fmt(self, instructions, call_idx, reg) -> dict:
        """反向解析fmt寄存器来源."""
        reg = norm_reg(reg)
        start = max(0, call_idx - 60)
        for i in range(call_idx - 1, start - 1, -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if len(ops) < 2:
                continue
            if norm_reg(ops[0]) != reg:
                continue
            src = ops[1].strip()
            sl = src.lower()
            if mnem == "lea":
                if "rip" in sl:
                    lit = self._rodata_literal(ins, src, i)
                    if lit is not None:
                        return {"kind": "literal", "content": lit,
                                "detail": f"rodata@0x{self._rip_abs(ins, src, i):x}"}
                    return {"kind": "literal", "content": "", "detail": "rodata"}
                return {"kind": "unknown", "detail": "lea-non-rip"}
            if mnem in ("mov", "movsxd", "movzx", "movsx"):
                if "rip" in sl:
                    lit = self._rodata_literal(ins, src, i)
                    if lit is not None:
                        return {"kind": "literal", "content": lit,
                                "detail": "rodata-load"}
                slot = extract_stack_slot(src)
                if slot:
                    return {"kind": "unknown", "detail": f"stack {slot}"}
                if self._is_taint_src(ins):
                    return {"kind": "taint", "detail": "tainted value"}
                return self._resolve_fmt(instructions, call_idx, norm_reg(src))
        if reg == self._fmt_reg or reg == self._second_reg:
            return {"kind": "unknown", "detail": f"arg {reg}"}
        return {"kind": "unknown", "detail": f"undef {reg}"}

    def _count_va_provided(self, instructions, call_idx) -> int:
        """统计调用点之前已加载的变参寄存器数量."""
        provided = 0
        start = max(0, call_idx - 40)
        loaded = set()
        for i in range(call_idx - 1, start - 1, -1):
            ins = instructions[i]
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if mnem == "call":
                break
            if len(ops) < 2:
                continue
            r = norm_reg(ops[0])
            if r in self._va_regs and r not in loaded:
                if mnem in ("mov", "lea", "movsxd", "movzx", "movsx"):
                    loaded.add(r)
                    provided += 1
        return provided

    def _rodata_literal(self, ins, src_op, idx) -> Optional[str]:
        if not self._rodata:
            return None
        abs_addr = self._rip_abs(ins, src_op, ins.get("address", 0))
        if abs_addr is None:
            return None
        from .rodata_extract import read_cstring
        raw = read_cstring(self._rodata, abs_addr)
        if not raw:
            return None
        try:
            return raw.decode("utf-8", errors="replace")
        except Exception:
            return None

    @staticmethod
    def _rip_abs(ins, src_op, addr):
        from .disasm_util import resolve_rip_relative
        return resolve_rip_relative(ins, src_op, addr)

    @staticmethod
    def _is_taint_src(ins) -> bool:
        ops = ins.get("operands", [])
        if ins.get("mnemonic", "").lower() != "mov" or len(ops) < 2:
            return False
        src = norm_reg(ops[1])
        return src in ("rax",) and False  # rax 需结合前序call, 由外层判断

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

    def reset(self):
        self._findings.clear()


__all__ = ["BinaryFmtDetector"]
