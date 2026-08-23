# 符号化大小表达式追踪器 (Symbolic Size Expression Tracker)
#
# 核心决策:
#   现有方法的误报根源在于用区间[lo,hi]近似变量值.
#   但堆溢出判定的关键不是"值有多大",而是"分配大小与写入大小是否来自同一变量".
#   例如: x = user_input; malloc(x); memcpy(p, src, x) 不可能溢出,
#   但区间分析看到的是 malloc([0,2^31-1]) + memcpy([0,2^31-1]) → 可能溢出.
#
#   本模块为每个寄存器维护其来源的符号化表达式 (Symbolic Expression),
#   而非数值区间. 表达式结构:
# Const(v): 编译时常量
# Param(idx): 函数参数
# CallRet(func): 函数返回值
#     - BinOp(op, lhs, rhs): 二元运算 (add/sub/mul/shl)
# Unknown: 无法追踪
#
#   在分配点和写入点, 比较两个表达式是否结构等价 (α-equivalent).
#   若等价 → 分配大小 == 写入大小 → 安全 (不可能溢出).
#
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Set
from .disasm_util import norm_reg, extract_func_name, extract_stack_slot, \
    is_32bit_reg


@dataclass(frozen=True)
class SymExpr:
    """不可变符号化表达式. 支持结构等价比较."""
    kind: str          # const|param|callret|binop|unknown|extern
    val: int = 0       # const: 数值
    idx: int = 0       # param: 参数索引
    func: str = ""     # callret/extern: 函数名
    op: str = ""       # binop: 运算符
    children: tuple = field(default_factory=tuple)  # binop: 子表达式

    def __eq__(self, other):
        if not isinstance(other, SymExpr):
            return False
        return (self.kind == other.kind and self.val == other.val and
                self.idx == other.idx and self.func == other.func and
                self.op == other.op and self.children == other.children)

    def __hash__(self):
        return hash((self.kind, self.val, self.idx, self.func,
                     self.op, self.children))

    @staticmethod
    def const(v: int) -> "SymExpr":
        return SymExpr(kind="const", val=v)

    @staticmethod
    def param(i: int) -> "SymExpr":
        return SymExpr(kind="param", idx=i)

    @staticmethod
    def callret(fn: str) -> "SymExpr":
        return SymExpr(kind="callret", func=fn)

    @staticmethod
    def extern(fn: str) -> "SymExpr":
        return SymExpr(kind="extern", func=fn)

    @staticmethod
    def binop(op: str, lhs: "SymExpr", rhs: "SymExpr") -> "SymExpr":
        return SymExpr(kind="binop", op=op, children=(lhs, rhs))

    @staticmethod
    def unknown() -> "SymExpr":
        return SymExpr(kind="unknown")

    def is_const(self) -> bool:
        return self.kind == "const"

    def is_unknown(self) -> bool:
        return self.kind == "unknown"

    def const_val(self) -> Optional[int]:
        return self.val if self.kind == "const" else None

    def contains(self, other: "SymExpr") -> bool:
        """递归检查other是否是self的子表达式."""
        if self == other:
            return True
        for child in self.children:
            if child.contains(other):
                return True
        return False

    def substitute(self, old: "SymExpr", new: "SymExpr") -> "SymExpr":
        """将子表达式old替换为new, 返回新表达式."""
        if self == old:
            return new
        if self.kind != "binop":
            return self
        new_children = tuple(
            c.substitute(old, new) for c in self.children)
        return SymExpr(kind=self.kind, op=self.op, children=new_children,
                       val=self.val, idx=self.idx, func=self.func)

    def to_str(self) -> str:
        if self.kind == "const":
            return str(self.val)
        if self.kind == "param":
            return f"arg{self.idx}"
        if self.kind == "callret":
            return f"ret({self.func})"
        if self.kind == "extern":
            return f"ext({self.func})"
        if self.kind == "binop":
            if len(self.children) == 2:
                return f"({self.children[0].to_str()}" \
                       f"{self.op}{self.children[1].to_str()})"
            return f"({self.op}...)".format()
        return "?"

    def __repr__(self):
        return self.to_str()


# x86-64 参数寄存器 (SysV)
_ARG_REGS = ("rdi", "rsi", "rdx", "rcx", "r8", "r9")

# 分配函数 → size参数索引
_ALLOC_SIZE_ARG = {
    "malloc": 0, "_Znwm": 0, "_Znam": 0,
    "g_malloc": 0, "calloc": (0, 1),
    "realloc": 1, "ExAllocatePoolWithTag": 1,
}

# 写入函数 → size参数索引
_WRITE_SIZE_ARG = {
    "memcpy": 2, "memmove": 2, "memset": 2,
    "strncpy": 2, "snprintf": 1,
    "read": 2, "fread": (1, 2), "recv": 2,
    "recvfrom": 2, "send": 2, "sendto": 2,
    "bcopy": 2, "bzero": 1, "explicit_bzero": 1,
}

# 常量返回函数 (strlen等)
_CONST_RET_FUNCS = {"strlen", "strnlen"}


class SymbolicSizeTracker:
    """符号化大小表达式追踪器.

    在指令序列上逐条前向传播每个寄存器的符号化表达式.
    在分配点和写入点捕获表达式, 供后续等价比较.
    """

    def __init__(self, arg_regs: Tuple[str, ...] = _ARG_REGS):
        self._regs: Dict[str, SymExpr] = {}
        self._stack: Dict[str, SymExpr] = {}
        self._arg_regs = arg_regs
        # 初始化参数表达式
        for i, reg in enumerate(arg_regs):
            self._regs[reg] = SymExpr.param(i)
        self._regs["rax"] = SymExpr.unknown()
        self._alloc_exprs: List[Tuple[int, str, SymExpr]] = []
        self._write_exprs: List[Tuple[int, str, SymExpr]] = []
        self._instructions: List[dict] = []

    def set_instructions(self, instructions: List[dict]):
        self._instructions = instructions

    def process(self, ins: dict):
        """处理单条指令, 更新符号化表达式状态."""
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        addr = ins.get("address", 0)

        if mnem == "call" and ops:
            self._handle_call(ins, ops, addr)
        elif mnem in ("mov", "movzx", "movsx", "movsxd", "cmovne",
                       "cmove", "cmovz", "cmov") and len(ops) >= 2:
            self._handle_mov(ops, addr)
        elif mnem in ("lea",) and len(ops) >= 2:
            self._handle_lea(ops)
        elif mnem in ("add", "sub", "imul", "mul", "shl", "shr",
                       "and", "or", "xor") and len(ops) >= 2:
            self._handle_arith(mnem, ops)
        elif mnem == "rep" and ops and ops[0].lower().startswith("movs"):
            self._handle_rep_movs(addr, ops)

    def _handle_call(self, ins: dict, ops: List[str], addr: int):
        func = extract_func_name(ops[0])
        # 分配函数: 捕获size表达式
        if func in _ALLOC_SIZE_ARG:
            size_idx = _ALLOC_SIZE_ARG[func]
            size_expr = self._get_arg_expr(ops, size_idx)
            self._alloc_exprs.append((addr, func, size_expr))
            # rax = callret(malloc)
            self._regs["rax"] = SymExpr.callret(func)
            return
        # 写入函数: 捕获size表达式
        if func in _WRITE_SIZE_ARG:
            size_idx = _WRITE_SIZE_ARG[func]
            size_expr = self._get_arg_expr(ops, size_idx)
            ptr_expr = self._get_arg_expr(ops, 0)
            self._write_exprs.append((addr, func, size_expr))
        elif func in _CONST_RET_FUNCS:
            self._regs["rax"] = SymExpr.callret(func)
        else:
            # 未知函数: 清除返回值寄存器
            self._regs["rax"] = SymExpr.unknown()

    def _get_arg_expr(self, ops: List[str], idx) -> SymExpr:
        """获取指定参数索引的符号表达式.

        call指令在objdump解析后只有1个operand(函数名),
        无法从ops中提取参数寄存器. 改为直接查询参数寄存器
        在Regs表中的当前符号表达式.
        """
        if isinstance(idx, tuple):
            # calloc(nmemb, size) -> nmemb * size
            exprs = [self._get_arg_expr(ops, i) for i in idx]
            result = exprs[0]
            for e in exprs[1:]:
                if result.is_unknown() or e.is_unknown():
                    return SymExpr.unknown()
                result = SymExpr.binop("*", result, e)
            return result
        # call指令只有1个operand → 从参数寄存器表查询
        if len(ops) <= 1:
            arg_reg = self._arg_regs[idx] if idx < len(self._arg_regs) else ""
            return self._regs.get(arg_reg, SymExpr.param(idx))
        # objdump格式: ops[0]=函数名, ops[1]=第一参数寄存器
        # 但实际objdump解析后call只有1个operand, 此分支很少触发
        reg = norm_reg(ops[idx + 1])
        return self._regs.get(reg, SymExpr.unknown())

    def _handle_mov(self, ops: List[str], addr: int):
        src = ops[1].strip().lstrip("$").split("#")[0].strip()
        dst_raw = ops[0].strip()
        dst_reg = norm_reg(dst_raw)

        # 立即数 (按目标寄存器宽度符号扩展, 避免 32 位负数误解析)
        if src.startswith("0x") or src.isdigit() or \
           (src.startswith("-") and src[1:].isdigit()):
            val = int(src, 16) if src.startswith("0x") else int(src)
            if is_32bit_reg(dst_raw) and val >= 0x80000000:
                val -= 0x100000000
            expr = SymExpr.const(val)
        else:
            src_reg = norm_reg(src)
            if "[" in src.lower() and "rbp" in src.lower():
                slot = extract_stack_slot(src)
                expr = self._stack.get(slot, SymExpr.unknown()) if slot \
                    else SymExpr.unknown()
            elif "[" in src.lower():
                expr = SymExpr.unknown()
            else:
                expr = self._regs.get(src_reg, SymExpr.unknown())

        # 栈写入
        if "[" in dst_raw.lower() and "rbp" in dst_raw.lower():
            slot = extract_stack_slot(dst_raw)
            if slot:
                self._stack[slot] = expr
        else:
            self._regs[dst_reg] = expr

    def _handle_lea(self, ops: List[str]):
        dst_reg = norm_reg(ops[0])
        # lea 通常用于地址计算, 不是数据的符号化来源
        self._regs[dst_reg] = SymExpr.unknown()

    def _handle_arith(self, mnem: str, ops: List[str]):
        dst = norm_reg(ops[0])
        src1 = self._regs.get(dst, SymExpr.unknown())
        src2_str = ops[1].strip().lstrip("$").split("#")[0].strip()
        if src2_str.startswith("0x") or src2_str.isdigit() or \
           (src2_str.startswith("-") and src2_str[1:].isdigit()):
            val = int(src2_str, 16) if src2_str.startswith("0x") \
                else int(src2_str)
            if is_32bit_reg(ops[0]) and val >= 0x80000000:
                val -= 0x100000000  # 32位负数编码符号扩展
            src2 = SymExpr.const(val)
        else:
            src2 = self._regs.get(norm_reg(src2_str), SymExpr.unknown())

        op_map = {"add": "+", "sub": "-", "imul": "*", "mul": "*",
                  "shl": "<<", "shr": ">>", "and": "&",
                  "or": "|", "xor": "^"}
        op = op_map.get(mnem, "?")
        if src1.is_unknown() or src2.is_unknown():
            self._regs[dst] = SymExpr.unknown()
        else:
            self._regs[dst] = SymExpr.binop(op, src1, src2)

    def _handle_rep_movs(self, addr: int, ops: List[str]):
        """rep movs 内联 memcpy: 写入字节数 = ecx * 元素大小.

        元素大小由 movs 的操作数类型推断 (movsb=1, movsw=2,
        movsd=4, movsq=8). 只记 ecx 会把字节数低估为元素计数,
        导致 SAWCE 将真实溢出误判为安全 (alloc>=write).
        """
        elem_size = 1
        first = ops[0].lower() if ops else ""
        # 先匹配长前缀: "dword"/"qword" 含 "word" 子串, 需先判定
        if "qword" in first or first == "movsq":
            elem_size = 8
        elif "dword" in first or first == "movsd":
            elem_size = 4
        elif "word" in first or first == "movsw":
            elem_size = 2
        elif "byte" in first or first == "movsb":
            elem_size = 1
        ecx_expr = self._regs.get("rcx", SymExpr.unknown())
        if ecx_expr.is_unknown():
            self._write_exprs.append((addr, "inline_memcpy",
                                      SymExpr.unknown()))
            return
        if ecx_expr.is_const():
            self._write_exprs.append(
                (addr, "inline_memcpy",
                 SymExpr.const(ecx_expr.const_val() * elem_size)))
            return
        self._write_exprs.append(
            (addr, "inline_memcpy",
             SymExpr.binop("*", ecx_expr, SymExpr.const(elem_size))))

    @property
    def alloc_exprs(self) -> List[Tuple[int, str, SymExpr]]:
        return list(self._alloc_exprs)

    @property
    def write_exprs(self) -> List[Tuple[int, str, SymExpr]]:
        return list(self._write_exprs)

    def get_reg_expr(self, reg: str) -> SymExpr:
        return self._regs.get(norm_reg(reg), SymExpr.unknown())

    def get_stack_expr(self, slot: str) -> SymExpr:
        return self._stack.get(slot, SymExpr.unknown())

    def reset(self):
        self._regs.clear()
        self._stack.clear()
        self._alloc_exprs.clear()
        self._write_exprs.clear()
        for i, reg in enumerate(self._arg_regs):
            self._regs[reg] = SymExpr.param(i)
        self._regs["rax"] = SymExpr.unknown()


__all__ = ["SymExpr", "SymbolicSizeTracker"]
