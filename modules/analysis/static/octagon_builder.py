# Octagon 约束构建器 (Octagon Constraint Builder)
#
# 从指令序列中提取变量间关系约束, 填充到 OctagonDomain.
# 仅追踪堆分析相关变量 (分配/写入大小参数), 保持稀疏性.
#
# 约束来源:
#   1. mov reg, imm → reg = const
#   2. mov reg1, reg2 → reg1 = reg2
#   3. lea reg, [base+offset] → reg = base + offset
#   4. cmp reg, imm; jcc → reg ≤ imm 或 reg > imm
#   5. call malloc(arg_reg) → arg_reg 标记为 alloc_size
#   6. call memcpy(,,size_reg) → size_reg 标记为 write_size
#

from typing import Dict, List, Optional, Tuple

from .octagon_domain import OctagonDomain
from .disasm_util import norm_reg, extract_func_name


_ALLOC_FUNCS = {"malloc", "calloc", "realloc", "_Znwm", "_Znam",
                "g_malloc", "HeapAlloc", "ExAllocatePoolWithTag"}
_WRITE_FUNCS = {"memcpy", "memmove", "memset", "strcpy", "strncpy",
                "strcat", "strncat", "read", "recv", "fread"}
_ARG_REGS = ["rdi", "rsi", "rdx", "rcx", "r8", "r9"]


# 各危险函数的大小参数在调用约定中的位置
_SIZE_ARG_POS = {
    "memcpy": 2, "memmove": 2, "memset": 2,
    "strncpy": 2, "strncat": 2, "read": 2,
    "recv": 2, "fread": 1,
}
_ALLOC_ARG_POS = {
    "malloc": 0, "calloc": 0, "realloc": 1,
    "_Znwm": 0, "_Znam": 0, "g_malloc": 0,
}


class OctagonConstraintBuilder:
    """从指令序列构建 Octagon 域约束.

    前向扫描指令, 在以下位置生成约束:
    - 常量赋值: mov reg, imm
    - 变量传播: mov reg1, reg2
    - 地址计算: lea reg, [base+off] → reg = base + off
    - 分支约束: cmp reg, imm; jcc → reg ≤ imm (taken path)
    - 分配/写入点: 标记相关寄存器

    最终输出: 已填充约束的 OctagonDomain + 变量角色映射
    (alloc_size_reg, write_size_reg per call site).
    """

    def __init__(self):
        self._domain = OctagonDomain()
        self._reg_to_const: Dict[str, int] = {}
        self._reg_aliases: Dict[str, str] = {}
        self._alloc_sites: Dict[int, str] = {}
        self._write_sites: Dict[int, str] = {}
        self._pending_cmp: Optional[Tuple[str, str]] = None

    @property
    def domain(self) -> OctagonDomain:
        return self._domain

    @property
    def alloc_sites(self) -> Dict[int, str]:
        """分配调用地址 → 大小参数寄存器名."""
        return self._alloc_sites

    @property
    def write_sites(self) -> Dict[int, str]:
        """写入调用地址 → 大小参数寄存器名."""
        return self._write_sites

    def build(self, instructions: List[dict]):
        """前向扫描指令序列, 构建约束."""
        for ins in instructions:
            self._process(ins)
        self._domain.finalize_constraints()

    def _process(self, ins: dict):
        mnem = ins.get("mnemonic", "").lower()
        ops = ins.get("operands", [])
        if not ops:
            self._pending_cmp = None
            return

        dst = norm_reg(ops[0]) if ops else ""

        if mnem == "cmp" and len(ops) >= 2:
            self._handle_cmp(ops)
            return

        if mnem.startswith("j") and mnem != "jmp":
            self._pending_cmp = None
            return

        if mnem == "mov" and len(ops) >= 2:
            self._handle_mov(dst, ops[1], ins)
        elif mnem == "lea" and len(ops) >= 2:
            self._handle_lea(dst, ops[1])
        elif mnem == "call" and ops:
            self._handle_call(ops[0], ins)
        elif mnem in ("add", "sub") and len(ops) >= 2:
            self._handle_add_sub(dst, ops[1], mnem)

        if mnem not in ("cmp", "test"):
            self._pending_cmp = None

    def _handle_mov(self, dst: str, src_op: str, ins: dict):
        src = src_op.strip().lstrip("$")
        if src.startswith("0x") or src.lstrip("-").isdigit():
            try:
                val = int(src, 16) if src.startswith("0x") else int(src)
            except ValueError:
                return
            self._reg_to_const[dst] = val
            self._domain.set_constant(dst, val)
            self._domain.track(dst)
        else:
            src_reg = norm_reg(src)
            if src_reg in self._reg_to_const:
                self._reg_to_const[dst] = self._reg_to_const[src_reg]
                self._domain.set_constant(
                    dst, self._reg_to_const[src_reg])
            elif src_reg in self._domain._tracked:
                self._domain.set_equality(dst, src_reg)
            self._reg_aliases[dst] = src_reg

    def _handle_lea(self, dst: str, src_op: str):
        base, offset = self._parse_mem_operand(src_op)
        if base is None:
            return
        base_reg = norm_reg(base)
        if base_reg in self._reg_to_const and offset != 0:
            self._reg_to_const[dst] = self._reg_to_const[base_reg] + offset
            self._domain.set_constant(
                dst, self._reg_to_const[dst])
        elif base_reg in self._domain._tracked:
            self._domain.set_diff(dst, base_reg, offset)

    def _handle_add_sub(self, dst: str, src_op: str, mnem: str):
        src = src_op.strip().lstrip("$")
        if src.startswith("0x") or src.lstrip("-").isdigit():
            try:
                val = int(src, 16) if src.startswith("0x") else int(src)
            except ValueError:
                return
            if mnem == "sub":
                val = -val
            if dst in self._reg_to_const:
                self._reg_to_const[dst] += val
                self._domain.set_constant(
                    dst, self._reg_to_const[dst])

    def _handle_call(self, target_op: str, ins: dict):
        func = extract_func_name(target_op)
        addr = ins.get("address", 0)

        if func in _ALLOC_ARG_POS:
            arg_pos = _ALLOC_ARG_POS[func]
            if arg_pos < len(_ARG_REGS):
                size_reg = _ARG_REGS[arg_pos]
                self._alloc_sites[addr] = size_reg
                self._domain.track(size_reg)

        if func in _SIZE_ARG_POS:
            arg_pos = _SIZE_ARG_POS[func]
            if arg_pos < len(_ARG_REGS):
                size_reg = _ARG_REGS[arg_pos]
                self._write_sites[addr] = size_reg
                self._domain.track(size_reg)

    def _handle_cmp(self, ops: List[str]):
        r1 = norm_reg(ops[0])
        r2 = ops[1].strip().lstrip("$")
        if r2.startswith("0x") or r2.lstrip("-").isdigit():
            try:
                val = int(r2, 16) if r2.startswith("0x") else int(r2)
                self._pending_cmp = (r1, val)
            except ValueError:
                self._pending_cmp = None
        else:
            self._pending_cmp = None

    def apply_branch_constraint(self, taken: bool):
        """在条件跳转后, 对 taken 路径应用 cmp 约束.

        cmp reg, imm; jcc target → taken 路径上 reg ≤ imm (或 reg > imm).
        """
        if self._pending_cmp is None:
            return
        reg, val = self._pending_cmp
        if taken:
            self._domain.set(reg, "zero", float(val))
        else:
            self._domain.set("zero", reg, -float(val - 1))

    @staticmethod
    def _parse_mem_operand(op: str) -> Tuple[Optional[str], int]:
        op_clean = op.strip().lower().replace("[", "").replace("]", "")
        base = None
        offset = 0
        if "+" in op_clean:
            parts = op_clean.split("+")
            base = parts[0].strip()
            try:
                offset = int(parts[1].strip(), 0)
            except ValueError:
                pass
        elif "-" in op_clean:
            parts = op_clean.split("-", 1)
            base = parts[0].strip()
            try:
                offset = -int(parts[1].strip(), 0)
            except ValueError:
                pass
        else:
            base = op_clean.strip()
        return base, offset


__all__ = ["OctagonConstraintBuilder"]
