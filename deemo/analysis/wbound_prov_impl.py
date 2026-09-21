# 来源约束写界推断 — Provenance-Constrained Write-Bound Inference (来源约束写界推断).
#
# 决策逻辑:
#   堆溢出误报的根源是"宽区间回退": 写入大小操作数无法解析为常量时,
#   现有检测器将其建模为[0, 2^31-1]最宽区间, 与分配区间必然重叠.
#   本模块把"来源"作为第一等公民参与判定, 五级来源格:
#     CONSTANT < GUARDED < ALLOC_LINKED < INPUT_TAINTED < UNKNOWN.
#   三级判定:
#     CONFIRMED — 可证明存在越过分配可用边界的路径
#     BENIGN    — 可证明所有路径写入均不越过分配可用边界
#     SUSPECTED — 信息不足, 保守保留但不计入确认告警
#   守卫别名传播: cmp/test 产生的 GUARDED 经 ProvValue 对象同一性
#   同步到全部别名寄存器/栈槽; 零值比较不设上界 (仅约束下界).
#
#   本文件实现来源约束写界推断核心管线: 来源格 → 来源传播器 → 写界推断器
#   → 跨函数摘要 → 符号表达式 → 分配器模型.


import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Set, Tuple


# 符号表达式

@dataclass
class SymExpr:
    """线性符号表达式: a*var + b, 或纯常量 b."""
    var: Optional[str] = None  # 符号变量名, None=纯常量
    coeff: int = 1             # 变量系数
    const: int = 0             # 常数项

    def is_const(self) -> bool:
        return self.var is None

    def is_identity(self) -> bool:
        """是否为 var*1 + 0, 即自身."""
        return self.var is not None and self.coeff == 1 and self.const == 0

    def add_const(self, c: int) -> "SymExpr":
        return SymExpr(self.var, self.coeff, self.const + c)

    def scale(self, k: int) -> "SymExpr":
        if k == 0:
            return SymExpr(None, 0, 0)
        return SymExpr(self.var, self.coeff * k, self.const * k)

    def __repr__(self) -> str:
        if self.var is None:
            return str(self.const)
        parts = []
        if self.coeff != 0:
            if self.coeff == 1:
                parts.append(self.var)
            else:
                parts.append(f"{self.coeff}*{self.var}")
        if self.const != 0:
            parts.append(str(self.const))
        return " + ".join(parts) if parts else "0"


def correlate_sizes(
    alloc_expr: Optional[SymExpr],
    write_expr: Optional[SymExpr],
) -> Tuple[str, int]:
    """判定分配尺寸与写入尺寸的符号关系.

    返回: (判定类别, 溢出字节数)
      ("safe_equal", 0)      — 两者完全等价, 安全
      ("safe_dominates", 0)  — 分配尺寸 ≥ 写入尺寸(符号证明), 安全
      ("overflow", n)        — 写入 > 分配, 溢出 n 字节
      ("unknown", 0)         — 无法判定, 需更高层分析
    """
    if alloc_expr is None or write_expr is None:
        return ("unknown", 0)

    if alloc_expr.is_const() and write_expr.is_const():
        a, w = alloc_expr.const, write_expr.const
        if w <= a:
            return ("safe_dominates", 0)
        return ("overflow", w - a)

    if (alloc_expr.var is not None and
            alloc_expr.var == write_expr.var):
        w_c, a_c = write_expr.coeff, alloc_expr.coeff
        w_k, a_k = write_expr.const, alloc_expr.const
        if w_c == a_c:
            diff = w_k - a_k
            if diff <= 0:
                return ("safe_equal", 0)
            return ("overflow", diff)
        elif w_c > a_c and w_k >= a_k:
            return ("overflow", 0)
        elif w_c < a_c and w_k <= a_k:
            return ("safe_dominates", 0)
        else:
            return ("unknown", 0)

    if alloc_expr.is_const() and not write_expr.is_const():
        return ("unknown", 0)

    if not alloc_expr.is_const() and write_expr.is_const():
        if write_expr.const <= 0:
            return ("safe_dominates", 0)
        return ("unknown", 0)

    return ("unknown", 0)


# 内联工具

_W32_TO_W64 = {"eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
               "esi": "rsi", "edi": "rdi", "r8d": "r8", "r9d": "r9",
               "ax": "rax", "bx": "rbx", "cx": "rcx", "dx": "rdx",
               "si": "rsi", "di": "rdi"}


def norm_reg(reg: str) -> str:
    """寄存器归一化: ecx→rcx, eax→rax (32→64bit)."""
    r = reg.strip().lower().lstrip("%").replace("$", "")
    if "#" in r:
        r = r.split("#")[0].strip()
    if "[" in r:
        return r
    return _W32_TO_W64.get(r, r)


def extract_stack_slot(operand: str) -> Optional[str]:
    """提取栈槽标识: [rbp-0x8]→'rbp-0x8', 或 None."""
    op = operand.strip().lower()
    op = re.sub(r'(qword|dword|word|byte)\s+ptr\s+', '', op)
    cleaned = op.replace(' ', '')
    m = re.search(r'\[(r[bs]p[-+]0x[0-9a-f]+)\]', cleaned)
    if m:
        return m.group(1)
    m = re.search(r'\[(r[bs]p)\]', cleaned)
    if m:
        return m.group(1)
    return None


_MINGW_NORMALIZE = {
    "__mingw_printf": "printf", "__mingw_sprintf": "sprintf",
    "__mingw_snprintf": "snprintf", "__mingw_fprintf": "fprintf",
    "__mingw_vfprintf": "vfprintf", "__mingw_vsprintf": "vsprintf",
    "__mingw_vsnprintf": "vsnprintf", "__mingw_scanf": "scanf",
    "__mingw_sscanf": "sscanf", "__mingw_fscanf": "fscanf",
    "__mingw_malloc": "malloc", "__mingw_free": "free",
    "__mingw_realloc": "realloc", "__mingw_calloc": "calloc",
    "__mingw_strcpy": "strcpy", "__mingw_strncpy": "strncpy",
    "__mingw_strcat": "strcat", "__mingw_strncat": "strncat",
    "__mingw_strlen": "strlen", "__mingw_strcmp": "strcmp",
    "__mingw_strncmp": "strncmp", "__mingw_memcpy": "memcpy",
    "__mingw_memmove": "memmove", "__mingw_memset": "memset",
    "__mingw_memcmp": "memcmp", "__mingw_fopen": "fopen",
    "__mingw_fclose": "fclose", "__mingw_fread": "fread",
    "__mingw_fwrite": "fwrite", "__mingw_fgets": "fgets",
    "__mingw_fputs": "fputs", "__mingw_puts": "puts",
    "__mingw_putchar": "putchar",
}


def extract_func_name(target: str) -> str:
    """从call操作数提取函数名, MinGW重命名自动归一化."""
    t = target.strip().lower()
    for p in ("call ", "callq "):
        if t.startswith(p):
            t = t[len(p):]
    m = re.search(r"<([^>]+)>", t)
    if m:
        t = m.group(1)
    name = t.split("@")[0].split("(")[0].split(".")[-1]
    return _MINGW_NORMALIZE.get(name, name)


# 来源格

class ProvClass(Enum):
    """写入大小操作数的来源类别."""

    CONSTANT = 0       # 编译时常量, 上界精确已知
    GUARDED = 1        # 经 cmp/jcc 与分配大小比较, 上界被守卫约束
    ALLOC_LINKED = 2   # 与分配大小同源 (共享符号变量或结构相关)
    INPUT_TAINTED = 3  # 来自 read/recv/argv 等外部输入, 无静态上界
    UNKNOWN = 4        # 无法追踪, 保守最不精确


_PROV_PRECISION = {
    ProvClass.CONSTANT: 0,
    ProvClass.GUARDED: 1,
    ProvClass.ALLOC_LINKED: 2,
    ProvClass.INPUT_TAINTED: 3,
    ProvClass.UNKNOWN: 4,
}


def join_class(a: ProvClass, b: ProvClass) -> ProvClass:
    """来源类别的最小上界 (取较不精确者)."""
    if _PROV_PRECISION[a] >= _PROV_PRECISION[b]:
        return a
    return b


class ProvValue:
    """携带边界信息的来源值.

    字段:
      cls: 来源类别.
      expr: 线性符号表达式 (可为None, 表示无符号表示).
      bound: 数值上界 (无静态上界时取None).
      guard_upper: 守卫约束给出的上界 (GUARDED时有效).
      note: 判定依据描述.
    """

    __slots__ = ("cls", "expr", "bound", "guard_upper", "note")

    def __init__(self, cls: ProvClass, expr: Optional[SymExpr] = None,
                 bound: Optional[int] = None,
                 guard_upper: Optional[int] = None,
                 note: str = ""):
        self.cls = cls
        self.expr = expr
        self.bound = bound
        self.guard_upper = guard_upper
        self.note = note

    def join(self, other: "ProvValue") -> "ProvValue":
        """合并两条路径上的来源值 (路径合并点)."""
        cls = join_class(self.cls, other.cls)
        expr = self.expr if self.expr is not None else other.expr
        if cls == ProvClass.CONSTANT and self.bound is not None \
                and other.bound is not None:
            bound = max(self.bound, other.bound)
        else:
            bound = None
        guard = self.guard_upper if self.guard_upper is not None \
            else other.guard_upper
        return ProvValue(cls=cls, expr=expr, bound=bound,
                         guard_upper=guard,
                         note=f"join({self.cls.name},{other.cls.name})")

    @staticmethod
    def constant(value: int) -> "ProvValue":
        return ProvValue(ProvClass.CONSTANT, SymExpr(None, 0, value),
                         bound=value, note=f"const {value}")

    @staticmethod
    def param(idx: int) -> "ProvValue":
        return ProvValue(ProvClass.INPUT_TAINTED, SymExpr(var=f"param_{idx}"),
                         note=f"param {idx}")

    @staticmethod
    def unknown() -> "ProvValue":
        return ProvValue(ProvClass.UNKNOWN, note="unknown")

    def describe(self) -> str:
        """生成人类可读的来源描述."""
        if self.expr is not None and not self.expr.is_const():
            expr_s = repr(self.expr)
        elif self.bound is not None:
            expr_s = str(self.bound)
        else:
            expr_s = "?"
        if self.guard_upper is not None:
            expr_s += f" (guarded ≤ {self.guard_upper})"
        return f"{self.cls.name}[{expr_s}]"


# 来源传播器

_TAINT_FUNCS = {"read", "recv", "recvfrom", "recvmsg", "fread", "fgets",
                "gets", "scanf", "__isoc99_scanf", "getenv", "getpwuid",
                "atoi", "atol", "atoll", "strtol", "strtoul",
                "strtoll", "strtoull", "strlen", "strnlen"}
_TAINT_PARAM_SRC = {"main", "winmain", "wmain"}


class ProvenancePropagator:
    """指令级来源传播器.

    通过 handle_instruction() 维护状态; 用 get_at(addr, reg)
    查询写入大小操作数的来源.
    """

    _ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                    "g_malloc", "g_try_malloc", "ExAllocatePoolWithTag"}

    def __init__(self, arg_regs=None, use_win64_abi: bool = False):
        self._arg_regs = arg_regs or (
            ("rcx", "rdx", "r8", "r9") if use_win64_abi
            else ("rdi", "rsi", "rdx", "rcx", "r8", "r9"))
        self._regs: Dict[str, ProvValue] = {}
        self._stack: Dict[str, ProvValue] = {}
        self._at: Dict[int, Dict[str, ProvValue]] = {}
        self._guarded: Dict[int, Dict[str, int]] = {}
        self._alloc_arg_sources: Dict[int, ProvValue] = {}
        self._instructions: List[dict] = []
        self._taint_counter: int = 0
        self._init_params()

    def _init_params(self):
        for i, reg in enumerate(self._arg_regs):
            self._regs[reg] = ProvValue.param(i)
        self._regs["rax"] = ProvValue.unknown()

    def set_instructions(self, instructions: List[dict]):
        self._instructions = instructions

    def reset(self):
        self._regs.clear()
        self._stack.clear()
        self._at.clear()
        self._guarded.clear()
        self._alloc_arg_sources.clear()
        self._init_params()

    def handle_instruction(self, ins: dict, in_main: bool = False):
        """处理单条指令, 更新来源状态."""
        addr = ins.get("address", 0)
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])

        self._at[addr] = dict(self._regs)

        if not ops:
            return

        if mnem == "call":
            self._handle_call(ops, addr, in_main)
        elif mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
            self._handle_mov(ops)
        elif mnem == "lea" and len(ops) >= 2:
            self._handle_lea(ops)
        elif mnem in ("add", "sub", "shl", "shr") and len(ops) >= 2:
            self._handle_arith(mnem, ops)
        elif mnem in ("imul", "mul") and len(ops) >= 2:
            self._handle_imul(ops)
        elif mnem.startswith("cmov") and len(ops) >= 2:
            src = self._regs.get(norm_reg(ops[1]))
            if src is not None:
                self._regs[norm_reg(ops[0])] = src
        elif mnem in ("cmp", "test") and len(ops) >= 2:
            self._record_compare(ops)

    def _handle_call(self, ops: List[str], addr: int, in_main: bool):
        func = extract_func_name(ops[0])

        if func in self._ALLOC_FUNCS:
            arg_src = self._alloc_arg_source(func)
            self._alloc_arg_sources[addr] = arg_src
            self._regs["rax"] = ProvValue(
                ProvClass.ALLOC_LINKED,
                note=f"alloc@{addr:x}")
            return

        if func in _TAINT_FUNCS or (in_main and func in _TAINT_PARAM_SRC):
            self._taint_counter += 1
            self._regs["rax"] = ProvValue(
                ProvClass.INPUT_TAINTED,
                expr=SymExpr(var=f"taint_{self._taint_counter}"),
                note=f"input:{func}")
            return

        # 未知调用: 返回值来源无法追踪
        self._regs["rax"] = ProvValue.unknown()

    def _alloc_arg_source(self, func: str) -> ProvValue:
        """提取分配 size 参数寄存器当前的来源值."""
        if func == "realloc":
            idx = 1
        else:
            idx = 0
        reg = self._arg_regs[idx] if idx < len(self._arg_regs) else "rdi"
        return self._regs.get(reg, ProvValue.unknown())

    def mark_call_guard(self, reg: str, upper: Optional[int]):
        """call 边界前由检测器显式注入的守卫信息."""
        cur = self._regs.get(norm_reg(reg))
        if cur is None:
            return
        self._regs[norm_reg(reg)] = ProvValue(
            ProvClass.GUARDED, expr=cur.expr, bound=upper,
            guard_upper=upper, note="guard-injected")

    def get_at(self, addr: int, reg: str) -> Optional[ProvValue]:
        """查询某地址处寄存器的来源值."""
        return self._at.get(addr, {}).get(norm_reg(reg))

    def get_alloc_arg_source(self, alloc_addr: int) -> Optional[ProvValue]:
        """查询分配点 size 参数的来源值."""
        return self._alloc_arg_sources.get(alloc_addr)

    def _handle_mov(self, ops: List[str]):
        dst_raw = ops[0].strip()
        src_raw = ops[1].strip().lstrip("$").split("#")[0].strip()
        dst_reg = norm_reg(dst_raw)

        val = self._parse_imm(src_raw)
        if val is not None:
            pv = ProvValue.constant(val)
        elif "[" in src_raw.lower():
            slot = extract_stack_slot(src_raw)
            pv = self._stack.get(slot, ProvValue.unknown()) if slot \
                else ProvValue.unknown()
        else:
            pv = self._regs.get(norm_reg(src_raw), ProvValue.unknown())

        if "[" in dst_raw.lower():
            slot = extract_stack_slot(dst_raw)
            if slot:
                self._stack[slot] = pv
            return
        self._regs[dst_reg] = pv

    def _handle_lea(self, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        src = ops[1].strip()
        coeffs, offset = self._parse_lea_terms(src)
        pv = None
        if len(coeffs) == 1:
            reg, c = next(iter(coeffs.items()))
            if reg in self._regs:
                cur = self._regs[reg]
                if cur.expr is not None:
                    expr = cur.expr.scale(c)
                    if offset:
                        expr = expr.add_const(offset)
                    pv = ProvValue(cur.cls, expr=expr, bound=cur.bound,
                                   guard_upper=cur.guard_upper,
                                   note=f"lea {c}*{reg}"
                                   + (f"+{offset}" if offset else ""))
                else:
                    pv = cur
        self._regs[dst_reg] = pv if pv is not None else ProvValue.unknown()

    def _handle_arith(self, mnem: str, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        src_raw = ops[1].strip().lstrip("$").split("#")[0].strip()
        cur = self._regs.get(dst_reg, ProvValue.unknown())
        imm = self._parse_imm(src_raw)

        if imm is not None:
            if cur.cls == ProvClass.CONSTANT and cur.bound is not None:
                new_bound = cur.bound + imm if mnem == "add" \
                    else cur.bound - imm if mnem == "sub" \
                    else (cur.bound << imm) if mnem == "shl" \
                    else (cur.bound >> imm)
                self._regs[dst_reg] = ProvValue.constant(new_bound)
            else:
                expr = self._shift_expr(cur, mnem, imm)
                self._regs[dst_reg] = ProvValue(cur.cls, expr=expr,
                                                note=f"{mnem} {imm}")
            return

        src = self._regs.get(norm_reg(src_raw), ProvValue.unknown())
        if mnem == "add":
            self._regs[dst_reg] = self._binop_add(cur, src)
        else:
            self._regs[dst_reg] = ProvValue(
                join_class(cur.cls, ProvClass.UNKNOWN), note=f"{mnem} reg")

    def _binop_add(self, a: ProvValue, b: ProvValue) -> ProvValue:
        """add dst, src — 常量平移或同源翻倍 (reg+reg 同源)."""
        if b.cls == ProvClass.CONSTANT and b.bound is not None:
            expr = a.expr.add_const(b.bound) if a.expr is not None else None
            return ProvValue(a.cls, expr=expr, note="add const")
        if (a.expr is not None and b.expr is not None
                and a.expr.var is not None and a.expr.var == b.expr.var):
            expr = SymExpr(a.expr.var, a.expr.coeff + b.expr.coeff,
                           a.expr.const + b.expr.const)
            return ProvValue(a.cls, expr=expr, note="add same-src")
        return ProvValue(join_class(a.cls, b.cls), note="add reg")

    def _shift_expr(self, pv: ProvValue, mnem: str,
                    imm: int) -> Optional[SymExpr]:
        """对来源值应用移位/平移, 生成新的符号表达式."""
        if pv.expr is None:
            return None
        if mnem == "shl":
            return pv.expr.scale(1 << imm)
        if mnem == "shr":
            return None
        if mnem == "add":
            return pv.expr.add_const(imm)
        return pv.expr.add_const(-imm)

    def _handle_imul(self, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        src_raw = ops[1].strip().lstrip("$").split("#")[0].strip()
        cur = self._regs.get(dst_reg, ProvValue.unknown())
        imm = self._parse_imm(src_raw)
        if imm is not None and cur.expr is not None:
            self._regs[dst_reg] = ProvValue(cur.cls,
                                            expr=cur.expr.scale(imm),
                                            note=f"imul {imm}")
        else:
            self._regs[dst_reg] = ProvValue(
                join_class(cur.cls, ProvClass.UNKNOWN), note="imul reg")

    def _record_compare(self, ops: List[str]):
        """记录 cmp/test — 被比较对象在当前路径之后被守卫.

        支持寄存器与栈槽两种操作数 (O0 编译常将局部变量驻留栈槽).
        """
        target_raw = ops[0].strip().lower()
        cur = None
        if "[" in target_raw:
            slot = extract_stack_slot(target_raw)
            if slot:
                cur = self._stack.get(slot)
        else:
            reg = norm_reg(target_raw)
            cur = self._regs.get(reg)
        if cur is None:
            return

        other_raw = ops[1].strip().lstrip("$")
        other_val = self._parse_imm(other_raw)
        guard_upper = other_val
        if guard_upper is None:
            other_reg = norm_reg(other_raw)
            other_pv = self._regs.get(other_reg)
            if other_pv is not None and other_pv.bound is not None:
                guard_upper = other_pv.bound
        # 零值比较 (cmp reg, 0; jle/jg) 是正性检查而非上界守卫:
        # 写入路径要求 reg>0, 并不约束上界. 0 作为 guard_upper 会让
        # 写界推断把任意正写入误判为 benign. 此情形不设上界.
        if guard_upper == 0:
            guard_upper = None
        if guard_upper is None:
            guard_upper = cur.guard_upper

        guarded = ProvValue(ProvClass.GUARDED, expr=cur.expr,
                            bound=guard_upper,
                            guard_upper=guard_upper,
                            note="bounds-checked")
        # 副本经 mov/movsxd 共享同一 ProvValue 对象 (对象同一性),
        # 将守卫同步到当前仍指向该对象的所有寄存器/栈槽别名.
        for r in list(self._regs.keys()):
            if self._regs[r] is cur:
                self._regs[r] = guarded
        for s in list(self._stack.keys()):
            if self._stack[s] is cur:
                self._stack[s] = guarded
        if "[" in target_raw:
            slot = extract_stack_slot(target_raw)
            if slot:
                self._stack[slot] = guarded
        else:
            self._regs[norm_reg(target_raw)] = guarded

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
    def _parse_lea_terms(operand: str) -> Tuple[Dict[str, int], int]:
        """解析 lea 操作数为 (寄存器系数表, 常量偏移).

        [rax+rax*1] → ({rax:2}, 0); [rax+0x1] → ({rax:1}, 1);
        [rax+rcx*4] → ({rax:1, rcx:4}, 0); [rip+...] → ({}, 0).
        """
        op = operand.strip().lower()
        if "[" not in op or "]" not in op:
            return {}, 0
        inner = op.split("[", 1)[1].split("]", 1)[0]
        coeffs: Dict[str, int] = {}
        offset = 0
        for term in inner.split("+"):
            term = term.strip()
            if not term or term.startswith("rip"):
                continue
            if "*" in term:
                reg, mul = term.split("*", 1)
                reg = reg.strip()
                if reg.startswith("rip"):
                    continue
                try:
                    coeffs[norm_reg(reg)] = coeffs.get(norm_reg(reg), 0) \
                        + int(mul.strip(), 0)
                except ValueError:
                    continue
            else:
                try:
                    offset += int(term, 0)
                except ValueError:
                    reg = norm_reg(term)
                    if reg:
                        coeffs[reg] = coeffs.get(reg, 0) + 1
        return coeffs, offset


# 分配器模型

class AllocatorFamily(Enum):
    GLIBC = "glibc"
    JEMALLOC = "jemalloc"
    TCMALLOC = "tcmalloc"
    WINDOWS = "windows"
    GENERIC = "generic"


def glibc_chunk_size(request: int) -> int:
    """glibc ptmalloc2 的实际 chunk 大小 (x86-64).

    glibc request2size公式:
      (request + SIZE_SZ + MALLOC_ALIGN_MASK) & ~MALLOC_ALIGN_MASK
      SIZE_SZ=8, MALLOC_ALIGN_MASK=15, MINSIZE=32
    """
    if request < 0:
        return 32
    size = (request + 8 + 15) & ~15
    return max(size, 32)


_JEMALLOC_SIZE_CLASSES = [
    8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128,
    160, 192, 224, 256, 320, 384, 448, 512, 640, 768, 896, 1024,
    1280, 1536, 1792, 2048, 2560, 3072, 3584, 4096, 5120, 6144,
    7168, 8192, 10240, 12288, 14336, 16384,
]


def jemalloc_chunk_size(request: int) -> int:
    """jemalloc 分配器: 返回所属 size class 的大小."""
    for sc in _JEMALLOC_SIZE_CLASSES:
        if request <= sc:
            return sc
    return (request + 4095) & ~4095


_TCMALLOC_CLASSES = [8, 16, 32, 64, 128, 256, 512, 1024, 2048, 4096, 8192]


def tcmalloc_chunk_size(request: int) -> int:
    """tcmalloc: 向上取到最近的 size class."""
    for sc in _TCMALLOC_CLASSES:
        if request <= sc:
            return sc
    return (request + 4095) & ~4095


def windows_chunk_size(request: int) -> int:
    """Windows RtlHeap / HeapAlloc."""
    return max(16, (request + 7) & ~7)


_ALLOCATOR_MODELS = {
    AllocatorFamily.GLIBC: glibc_chunk_size,
    AllocatorFamily.JEMALLOC: jemalloc_chunk_size,
    AllocatorFamily.TCMALLOC: tcmalloc_chunk_size,
    AllocatorFamily.WINDOWS: windows_chunk_size,
    AllocatorFamily.GENERIC: lambda r: max(16, (r + 15) & ~15),
}


class HeapAllocModel:
    """堆分配器行为模型: request_size → actual_chunk_size 映射."""

    def __init__(self, family: AllocatorFamily = AllocatorFamily.GLIBC):
        self._family = family
        self._model = _ALLOCATOR_MODELS.get(
            family, _ALLOCATOR_MODELS[AllocatorFamily.GENERIC])

    def actual_chunk_size(self, request: int) -> int:
        """用户请求N字节 → 分配器实际分配的chunk总大小."""
        return self._model(request)

    def usable_size(self, request: int) -> int:
        """用户请求N字节 → 实际可安全写入的字节数.

        glibc: usable = chunk - SIZE_SZ(8), 因下一个chunk的prev_size在
        当前chunk in-use时可被复用, 实际可写8字节额外空间.
        """
        chunk = self.actual_chunk_size(request)
        if self._family == AllocatorFamily.GLIBC:
            return chunk - 8
        elif self._family == AllocatorFamily.JEMALLOC:
            return chunk
        elif self._family == AllocatorFamily.TCMALLOC:
            return chunk - 8
        elif self._family == AllocatorFamily.WINDOWS:
            return chunk - 8
        return chunk

    def is_overflow(self, request: int, write_size: int) -> Tuple[bool, str]:
        """判断给定请求大小和写入大小是否构成溢出."""
        usable = self.usable_size(request)
        if write_size <= usable:
            return False, (
                f"safe: write({write_size}) <= usable({usable}) "
                f"[request={request}, chunk={self.actual_chunk_size(request)}, "
                f"allocator={self._family.value}]"
            )
        return True, (
            f"overflow: write({write_size}) > usable({usable}) "
            f"[request={request}, chunk={self.actual_chunk_size(request)}, "
            f"allocator={self._family.value}]"
        )

    def min_overflow_write(self, request: int) -> int:
        """给定分配请求, 触发溢出的最小写入量."""
        return self.usable_size(request) + 1

    @property
    def family(self) -> AllocatorFamily:
        return self._family

    def set_family(self, family: AllocatorFamily):
        self._family = family
        self._model = _ALLOCATOR_MODELS.get(
            family, _ALLOCATOR_MODELS[AllocatorFamily.GENERIC])


# 写界推断器

class WbVerdict:
    CONFIRMED = "confirmed"
    BENIGN = "benign"
    SUSPECTED = "suspected"


@dataclass
class WriteBoundResult:
    """单条告警的写界判定结果."""
    finding: dict
    verdict: str
    reason: str
    provenance: str = ""

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "provenance": self.provenance,
            **{k: v for k, v in self.finding.items()},
        }


class WriteBoundInferer:
    """写界推断器 — 将原始告警映射到三级判定."""

    def __init__(self, alloc_model: Optional[HeapAllocModel] = None):
        self._alloc_model = alloc_model or HeapAllocModel()
        self._stats = {"confirmed": 0, "benign": 0, "suspected": 0}

    def infer(self, findings: List[dict],
              get_write_prov, get_alloc_prov) -> List[WriteBoundResult]:
        """对告警集合执行写界推断.

        get_write_prov(write_addr, size_reg) -> ProvValue|None
        get_alloc_prov(alloc_addr) -> ProvValue|None (分配size参数来源)
        """
        results = []
        for f in findings:
            alloc_sz = f.get("alloc_size", 0) or 0
            write_sz = f.get("write_size")
            size_op = f.get("size_operand", "")
            write_addr = f.get("write_addr", 0)
            alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))

            wprov = None
            if size_op:
                wprov = get_write_prov(write_addr, size_op)

            alloc_prov = get_alloc_prov(alloc_addr)

            res = self._decide(f, alloc_sz, write_sz, wprov, alloc_prov)
            self._stats[res.verdict] += 1
            results.append(res)
        return results

    def _decide(self, f: dict, alloc_sz: int, write_sz,
                wprov: Optional[ProvValue],
                alloc_prov: Optional[ProvValue]) -> WriteBoundResult:
        """单条告警的三级判定."""

        # 0. 符号相关性优先: 分配与写入共享符号变量且线性可比时,
        #    符号证据强于数值区间, 先于一切数值分支判定.
        sym = self._symbolic_compare(f, wprov, alloc_prov)
        if sym is not None:
            return sym

        # 0.5 静态写终点优先: 内联存储的写终点是编译时确定的数值,
        #    直接与分配(对齐后)比较, 不依赖寄存器来源传播.
        wb_num = f.get("wb_numeric")
        if wb_num is not None and isinstance(wb_num, int) \
                and alloc_sz is not None and 0 < alloc_sz < 2**31 - 1:
            request = f.get("alloc_request")
            bound = request if request and 0 < request < 2**31 - 1 \
                else alloc_sz
            usable = self._alloc_model.usable_size(bound)
            if wb_num > usable:
                return WriteBoundResult(
                    f, WbVerdict.CONFIRMED,
                    f"static write_end {wb_num} > usable {usable}",
                    "inline-store")
            return WriteBoundResult(
                f, WbVerdict.BENIGN,
                f"static write_end {wb_num} ≤ usable {usable} "
                f"(alignment padding)", "inline-store")

        # 分配大小缺失或无界: 无法证明安全, 保守确认.
        if alloc_sz is None or alloc_sz <= 0 or alloc_sz >= 2**31 - 1:
            if wprov is None or wprov.cls in (
                    ProvClass.CONSTANT, ProvClass.GUARDED,
                    ProvClass.ALLOC_LINKED):
                return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                        "alloc size unbounded",
                                        wprov.describe() if wprov else "?")
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    "unbounded alloc + tainted write",
                                    wprov.describe())

        # alloc_sz 是对齐后的分配上界; usable 优先基于原始请求
        # alloc_request 计算, 避免对齐值导致可用量偏高而漏报.
        request = f.get("alloc_request")
        if not request or request <= 0 or request >= 2**31 - 1:
            request = max(0, alloc_sz - 15)
        usable = self._alloc_model.usable_size(request)

        if wprov is None:
            # 无来源信息: 数值写大小已知则直接比较, 否则保守.
            if isinstance(write_sz, int) and write_sz > usable:
                return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                        f"write {write_sz} > usable {usable}",
                                        "numeric")
            return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                    "no provenance info", "?")

        cls = wprov.cls

        if cls == ProvClass.CONSTANT:
            w = write_sz if (isinstance(write_sz, int)
                             and 0 < write_sz < 2**31 - 1) \
                else wprov.bound
            if w is None:
                return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                        "constant without value", "const")
            if w <= usable:
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"const write {w} ≤ usable {usable} "
                    f"(allocator padding)", wprov.describe())
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    f"const write {w} > usable {usable}",
                                    wprov.describe())

        if cls == ProvClass.GUARDED:
            g = wprov.guard_upper if wprov.guard_upper is not None \
                else wprov.bound
            # 守卫上界必须为正数才是真正的上界; 0/None 表示无有效上界
            # (零值比较仅约束下界), 此时不能证明写量有界 → 保守保留.
            if g is not None and g > 0 and g <= usable:
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"bounds-checked write ≤ {g} ≤ usable {usable}",
                    wprov.describe())
            return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                    "guard upper exceeds usable or unknown",
                                    wprov.describe())

        if cls == ProvClass.ALLOC_LINKED:
            return self._decide_alloc_linked(f, alloc_sz, usable, wprov,
                                             alloc_prov)

        if cls == ProvClass.INPUT_TAINTED:
            # 分配参数自身的整数回绕未建模 (count*16 收缩为小分配
            # 后写入 count 仍超限), 该模式依赖整数溢出检测器补充.
            if isinstance(write_sz, int) and write_sz <= usable:
                return WriteBoundResult(f, WbVerdict.BENIGN,
                                        f"bounded write {write_sz}",
                                        wprov.describe())
            alloc_const = self._alloc_is_constant(alloc_prov)
            if alloc_const is not None and alloc_const < usable + 1:
                return WriteBoundResult(
                    f, WbVerdict.CONFIRMED,
                    f"fixed alloc {alloc_const} + tainted write",
                    wprov.describe())
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    "tainted write, unbounded upper",
                                    wprov.describe())

        return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                "unknown provenance", wprov.describe())

    def _symbolic_compare(self, f: dict, wprov: Optional[ProvValue],
                          alloc_prov: Optional[ProvValue]) -> Optional[WriteBoundResult]:
        """基于线性符号表达式比较分配与写入.

        两者均有可比较表达式且共享符号变量时返回判定, 否则None.
        """
        if wprov is None or alloc_prov is None:
            return None
        w_expr = wprov.expr
        a_expr = alloc_prov.expr
        if w_expr is None or a_expr is None:
            return None
        # 纯常量对: 数值路径用 usable_size 判定 (含分配器padding),
        # 符号比较只负责共享符号变量的线性关系.
        if a_expr.is_const() and w_expr.is_const():
            return None
        verdict, overflow = correlate_sizes(a_expr, w_expr)
        # 分配-写关联 已确认溢出 (含目标偏移) 时, 符号等价不可覆盖该结论.
        if f.get("awsc_confirmed"):
            return None
        if verdict == "safe_equal":
            return WriteBoundResult(f, WbVerdict.BENIGN,
                                    "write ≡ alloc (shared symbol)",
                                    wprov.describe())
        if verdict == "safe_dominates":
            return WriteBoundResult(f, WbVerdict.BENIGN,
                                    "alloc dominates write (symbolic)",
                                    wprov.describe())
        if verdict == "overflow":
            return WriteBoundResult(f, WbVerdict.CONFIRMED,
                                    f"write grows beyond alloc (+{overflow}B)",
                                    wprov.describe())
        return None

    def _decide_alloc_linked(self, f: dict, alloc_sz: int, usable: int,
                             wprov: ProvValue,
                             alloc_prov: Optional[ProvValue]) -> WriteBoundResult:
        """分配同源写入的符号判定."""
        w_expr = wprov.expr
        a_expr = alloc_prov.expr if alloc_prov is not None else None

        if w_expr is not None and a_expr is not None:
            verdict, overflow = correlate_sizes(a_expr, w_expr)
            if verdict == "safe_equal":
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"write ≡ alloc (shared symbol)", wprov.describe())
            if verdict == "safe_dominates":
                return WriteBoundResult(
                    f, WbVerdict.BENIGN,
                    f"alloc dominates write (symbolic)", wprov.describe())
            if verdict == "overflow":
                return WriteBoundResult(
                    f, WbVerdict.CONFIRMED,
                    f"write grows beyond alloc (+{overflow}B)", wprov.describe())

        # 符号不可比时回退到数值: 写入上界已知且≤usable → 安全.
        if wprov.bound is not None and wprov.bound <= usable:
            return WriteBoundResult(f, WbVerdict.BENIGN,
                                    f"linked write bound {wprov.bound} ≤ usable",
                                    wprov.describe())
        return WriteBoundResult(f, WbVerdict.SUSPECTED,
                                "alloc-linked but incomparable",
                                wprov.describe())

    @staticmethod
    def _alloc_is_constant(alloc_prov: Optional[ProvValue]) -> Optional[int]:
        """提取分配 size 参数的常量值 (非常量返回None)."""
        if alloc_prov is None:
            return None
        if alloc_prov.cls == ProvClass.CONSTANT:
            return alloc_prov.bound
        if alloc_prov.expr is not None and alloc_prov.expr.is_const():
            return alloc_prov.expr.const
        return None

    @property
    def stats(self) -> dict:
        return dict(self._stats)


# 跨函数摘要

class FunctionProvenanceSummary:
    """单个函数的来源摘要."""

    __slots__ = ("name", "copy_chains", "alloc_return")

    def __init__(self, name: str):
        self.name = name
        self.copy_chains: Dict[str, Tuple[int, int]] = {}
        self.alloc_return: Optional[int] = None

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "copy_chains": {k: list(v) for k, v in self.copy_chains.items()},
            "alloc_return": self.alloc_return,
        }


class InterprocSummaryBuilder:
    """从指令序列构建函数来源摘要."""

    _ALLOC_FUNCS = {"malloc", "calloc", "_Znwm", "_Znam", "g_malloc"}

    def __init__(self, arg_regs=None):
        self._arg_regs = arg_regs or ("rdi", "rsi", "rdx", "rcx", "r8", "r9")
        self._summaries: Dict[str, FunctionProvenanceSummary] = {}

    def build(self, func_name: str, instructions: List[dict],
              is_win64: bool = False) -> FunctionProvenanceSummary:
        """扫描单个函数, 构建摘要."""
        args = ("rcx", "rdx", "r8", "r9") if is_win64 else self._arg_regs
        arg_idx = {r: i for i, r in enumerate(args)}
        summary = FunctionProvenanceSummary(func_name)

        for ins in instructions:
            mnem = ins.get("mnemonic", "").lower()
            ops = ins.get("operands", [])
            if not ops:
                continue

            if mnem in ("mov", "movzx", "movsx", "movsxd") and len(ops) >= 2:
                dst = self._norm_reg(ops[0])
                src = self._norm_reg(ops[1])
                if src in arg_idx and dst not in arg_idx:
                    summary.copy_chains[dst] = (arg_idx[src], 0)
                continue

            if mnem in ("add", "sub") and len(ops) >= 2:
                dst = self._norm_reg(ops[0])
                if dst in summary.copy_chains:
                    delta = self._parse_imm(ops[1])
                    if delta is not None:
                        idx, base = summary.copy_chains[dst]
                        summary.copy_chains[dst] = (idx, base + delta)
                continue

            if mnem == "call" and ops:
                func = extract_func_name(ops[0])
                if func in self._ALLOC_FUNCS:
                    size_reg = args[0]
                    if size_reg in summary.copy_chains:
                        summary.alloc_return = summary.copy_chains[size_reg][0]

        self._summaries[func_name] = summary
        return summary

    def get(self, func_name: str) -> Optional[FunctionProvenanceSummary]:
        return self._summaries.get(func_name)

    def rewrite_reg(self, func_name: str, reg: str) -> Optional[int]:
        """查询函数摘要: 输出寄存器对应哪个输入参数索引.

        返回 None 表示无摘要信息.
        """
        summary = self._summaries.get(func_name)
        if summary is None:
            return None
        return summary.copy_chains.get(reg)

    @staticmethod
    def _norm_reg(op: str) -> str:
        op = op.strip().lower().lstrip("%").lstrip("$")
        if "[" in op or op.startswith("0x") or op.isdigit():
            return ""
        return op

    @staticmethod
    def _parse_imm(s: str) -> Optional[int]:
        s = s.strip().lstrip("$").split("#")[0].strip()
        try:
            if s.startswith("0x"):
                return int(s, 16)
            if s.isdigit() or (s.startswith("-") and s[1:].isdigit()):
                return int(s)
        except ValueError:
            pass
        return None


__all__ = [
    "SymExpr", "correlate_sizes",
    "ProvClass", "ProvValue", "join_class",
    "ProvenancePropagator",
    "WbVerdict", "WriteBoundResult", "WriteBoundInferer",
    "HeapAllocModel", "AllocatorFamily",
    "glibc_chunk_size", "jemalloc_chunk_size",
    "tcmalloc_chunk_size", "windows_chunk_size",
    "FunctionProvenanceSummary", "InterprocSummaryBuilder",
]
