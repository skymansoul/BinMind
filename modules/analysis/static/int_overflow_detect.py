from ._user_scope_mixin import UserScopeMixin
# 整数溢出检测器: 追踪 imul/shl/lea/add/cdqe 溢出源经寄存器/栈槽流入 malloc

import re
from typing import Dict, List, Optional, Tuple, Set


class IntOverflowDetector(UserScopeMixin):
    """二进制级整数溢出检测器 v3 - 6类溢出源 + 寄存器/栈槽双通道传播."""

    ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                    "g_malloc", "ExAllocatePoolWithTag"}
    _MULTI_ARG_ALLOC = {"calloc", "realloc"}
    _LARGE_IMM64 = 0x8000000000000000
    _LARGE_IMM32 = 0x80000000

    def __init__(self):
        self._findings: List[dict] = []
        self._reg_overflow: Dict[str, bool] = {}
        self._reg_constants: Dict[str, int] = {}
        self._stack_overflow: Dict[str, bool] = {}
        self._stack_constants: Dict[str, int] = {}
        self._user_func_ranges: List[Tuple[int, int]] = []
        self._caller_saved = {"rax","rcx","rdx","r8","r9","r10","r11"}

    def set_user_func_ranges(self, ranges: List[Tuple[int, int]]):
        self._user_func_ranges = sorted(ranges, key=lambda r: r[0])

    def _is_user_code(self, addr: int) -> bool:
        if not self._user_func_ranges:
            return True
        for lo, hi in self._user_func_ranges:
            if lo <= addr < hi:
                return True
        return False

    def analyze_instruction(self, ins: dict):
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        # 0. ret → 清除所有状态 (函数边界)
        if mnem == "ret":
            self._reg_overflow.clear()
            self._reg_constants.clear()
            self._stack_overflow.clear()
            self._stack_constants.clear()
            return

# 1. 溢出源识别

        # 1a. imul/mul → 乘法
        if mnem in ("imul", "mul") and len(ops) >= 2:
            self._reg_overflow[self._norm_reg(ops[0])] = True

        # 1b. shl/sal → 左移
        if mnem in ("shl", "sal") and len(ops) >= 2:
            self._reg_overflow[self._norm_reg(ops[0])] = True

        # 1c. cdqe/movsxd → 符号扩展 (signed→unsigned, negative→huge)
        if mnem in ("cdqe", "movsxd", "movsx"):
            if mnem == "cdqe":
                dst64, src32 = "rax", "eax"
            elif len(ops) >= 2:
                dst64, src32 = self._norm_reg(ops[0]), self._norm_reg(ops[1])
            else:
                dst64 = src32 = ""
            if dst64 and src32:
                sv = self._reg_constants.get(src32)
                if sv is None or sv < 0:
                    self._reg_overflow[dst64] = True

        # 1d. add/sub → 加性溢出 (add_underflow/loop_add)
        if mnem in ("add", "sub") and len(ops) >= 2:
            dst_raw, src_raw = ops[0], ops[1]
            stack_slot = self._extract_stack_slot(dst_raw)
            if stack_slot:
                iv = self._parse_imm(src_raw)
                if iv is not None and abs(iv) > 0:
                    self._stack_overflow[stack_slot] = True
            else:
                dst = self._norm_reg(dst_raw)
                si = self._parse_imm(src_raw)
                if si is not None:
                    if si >= self._LARGE_IMM64 or (si < 0 and abs(si) >= self._LARGE_IMM32):
                        self._reg_overflow[dst] = True
                elif self._reg_overflow.get(self._norm_reg(src_raw)):
                    self._reg_overflow[dst] = True
                elif not self._reg_overflow.get(dst):
                    # 检查源栈槽
                    ss = self._extract_stack_slot(src_raw)
                    if ss and self._stack_overflow.get(ss):
                        self._reg_overflow[dst] = True
                    elif ss and ss in self._stack_constants:
                        sc = self._stack_constants[ss]
                        if sc is not None and (sc >= self._LARGE_IMM64 or
                                                (sc < 0 and abs(sc) >= self._LARGE_IMM32)):
                            self._reg_overflow[dst] = True

# 2. mov 传播: reg↔reg, reg↔stack
        if mnem == "mov" and len(ops) >= 2:
            dst_raw, src_raw = ops[0], ops[1]
            dst, src = self._norm_reg(dst_raw), src_raw.strip().lower()
            val = self._parse_imm(src)
            if val is not None:
                self._reg_constants[dst] = val
                self._reg_overflow.pop(dst, None)
            else:
                sr = self._norm_reg(src)
                if self._reg_overflow.get(sr):
                    self._reg_overflow[dst] = True
                elif sr in self._reg_constants:
                    self._reg_constants[dst] = self._reg_constants[sr]
                # reg→stack
                ss_dst = self._extract_stack_slot(dst_raw)
                if ss_dst:
                    if self._reg_overflow.get(sr):
                        self._stack_overflow[ss_dst] = True
                    if sr in self._reg_constants:
                        self._stack_constants[ss_dst] = self._reg_constants[sr]
                # stack→reg
                ss_src = self._extract_stack_slot(src_raw)
                if ss_src:
                    if self._stack_overflow.get(ss_src):
                        self._reg_overflow[dst] = True
                    if ss_src in self._stack_constants:
                        self._reg_constants[dst] = self._stack_constants[ss_src]

        # 2b. movzx/movsx → 零/符号扩展传播
        if mnem in ("movzx", "movsx", "movsxd") and len(ops) >= 2:
            dst = self._norm_reg(ops[0])
            ss = self._extract_stack_slot(ops[1])
            if ss and self._stack_overflow.get(ss):
                self._reg_overflow[dst] = True
            sr = self._norm_reg(ops[1])
            if sr and self._reg_overflow.get(sr):
                self._reg_overflow[dst] = True

        # 3. lea: scaled index (*2/*4/*8) = 乘法 (O2优化)
        if mnem == "lea" and len(ops) >= 2:
            dst = self._norm_reg(ops[0])
            if self._has_scaled_index(ops[1]):
                self._reg_overflow[dst] = True
            br = self._extract_base_reg(ops[1])
            if br and self._reg_overflow.get(self._norm_reg(br)):
                self._reg_overflow[dst] = True
            ss = self._extract_stack_slot(ops[1])
            if ss and self._stack_overflow.get(ss):
                self._reg_overflow[dst] = True

# 4. call alloc: 检查溢出arg → 报告
        if mnem == "call" and ops:
            func = self._extract_func(ops[0])
            if func in self.ALLOC_FUNCS and self._is_user_code(addr):
                for arg_reg in (["rcx","rdx"] if func in self._MULTI_ARG_ALLOC else ["rcx"]):
                    if self._reg_overflow.get(arg_reg):
                        cv = self._reg_constants.get(arg_reg)
                        self._findings.append({
                            "type": "integer_overflow",
                            "subtype": "arith_before_alloc",
                            "address": addr,
                            "alloc_func": func,
                            "arg_reg": arg_reg,
                            "const_val": cv,
                            "severity": "critical" if cv is not None and cv < 16 else "high",
                            "description": "overflow source flows to alloc without check"
                        })
            for reg in self._caller_saved:
                self._reg_overflow.pop(reg, None)
                self._reg_constants.pop(reg, None)

    def finalize(self) -> List[dict]:
        return list(self._findings)

    @property
    def findings(self) -> List[dict]:
        return list(self._findings)

# 静态工具

    @staticmethod
    def _extract_func(target: str) -> str:
        t = target.strip().lower()
        for p in ("call ", "callq "):
            if t.startswith(p):
                t = t[len(p):]
        m = re.search(r"<([^>]+)>", t)
        if m:
            t = m.group(1)
        return t.split("@")[0].split("(")[0].split(".")[-1]

    @staticmethod
    def _norm_reg(reg: str) -> str:
        r = reg.strip().lower().lstrip("%")
        return {"eax":"rax","ebx":"rbx","ecx":"rcx","edx":"rdx",
                "esi":"rsi","edi":"rdi","r8d":"r8","r9d":"r9",
                "ax":"rax","bx":"rbx","cx":"rcx","dx":"rdx",
                "si":"rsi","di":"rdi"}.get(r, r)

    @staticmethod
    def _parse_imm(src: str) -> Optional[int]:
        s = src.strip().lower().split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.startswith("$"):
                v = s[1:]
                return int(v, 16) if v.startswith("0x") else int(v)
            if s.lstrip("-").isdigit():
                return int(s)
        except (ValueError, AttributeError):
            pass
        return None

    @staticmethod
    def _has_scaled_index(operand: str) -> bool:
        o = operand.strip().lower()
        if "[" not in o or "]" not in o:
            return False
        return bool(re.search(r'\*\s*[248]\b', o[o.index("[")+1:o.rindex("]")]))

    @staticmethod
    def _extract_base_reg(operand: str) -> Optional[str]:
        o = operand.strip().lower()
        if "[" not in o or "]" not in o:
            return None
        m = re.match(r'([a-z][a-z0-9]*)\b', o[o.index("[")+1:o.rindex("]")].strip())
        return m.group(1) if m else None

    @staticmethod
    def _extract_stack_slot(operand: str) -> Optional[str]:
        o = operand.strip().lower()
        if "[" in o and "]" in o:
            inner = o[o.index("[")+1:o.rindex("]")].replace("*", "").strip()
            parts = inner.replace("+", " ").replace("-", " -").split()
            parts = [p.strip() for p in parts if p.strip()]
            if len(parts) >= 2:
                base, off = parts[0], parts[-1].lstrip("+")
                if off.startswith("0x") or off.lstrip("-").replace("x","").isdigit():
                    sep = "-" if off.startswith("-") or off.startswith("0x") and "-" not in off else "+"
                    return f"{base}{off}" if off.startswith("-") else f"{base}-{off}" if off.startswith("0x") else f"{base}+{off}"
        return None


__all__ = ["IntOverflowDetector", "detect_int_overflow"]


def detect_int_overflow(instructions: List[dict], file_format: str = "",
                         user_func_ranges: List[Tuple[int, int]] = None) -> List[dict]:
    detector = IntOverflowDetector()
    if user_func_ranges:
        detector.set_user_func_ranges(user_func_ranges)
    for ins in instructions:
        detector.analyze_instruction(ins)
    return [{"type": "integer_overflow", "verdict": f.get("severity", "unknown"),
             "confidence": 0.75, "address": f.get("address", 0),
             "detail": str(f)[:200]} for f in detector.finalize()]
