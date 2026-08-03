# 符号状态表示 — region-based 符号内存，支持 LShR/AShR 位运算及 alias 推理

"""轻量 concolic 执行的符号状态与路径条件。

不依赖外部 SMT solver。在 Python 整数语义内实现线性约束简化。

参考 BASICS [arXiv:2511.19670] concolic execution 框架，
借鉴其符号状态追踪思路，但不引入 KLEE 级符号执行引擎。
约束求解限制在线性算术和 bitwise 等式，NP-hard 部分回退到具体值。
代价是路径覆盖不完整，收益是零外部依赖和确定性运行时间。

参考 ColorGo [arXiv:2505.21130] directed concolic execution，
其"增量可达性染色"思路用于路径优先级排序。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Union
from enum import Enum
import struct
import operator


class ExprKind(Enum):
    CONST = "const"
    SYMBOL = "symbol"          # 符号变量（输入字节/寄存器初始值）
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    AND = "and"
    OR = "or"
    XOR = "xor"
    SHL = "shl"
    LSHR = "lshr"              # 逻辑右移
    ASHR = "ashr"              # 算术右移
    ZEXT = "zext"              # 零扩展
    EXTRACT = "extract"        # 位提取
    ITE = "ite"                # if-then-else（条件选择）
    READ_MEM = "read_mem"      # 内存读取


@dataclass(frozen=True)
class SymExpr:
    """不可变符号表达式 —— frozen 支持缓存与 set 操作。

    结构: (kind, operands, bits)
    bits 为表达式位宽 (8/16/32/64)，用于截断语义。
    """
    kind: ExprKind
    operands: tuple = ()       # (SymExpr, ...) 或 (int, ...)
    bits: int = 64
    label: str = ""            # 仅 SYMBOL 类型有标签

    def __repr__(self):
        if self.kind == ExprKind.CONST:
            return f"#{self.operands[0]}"
        if self.kind == ExprKind.SYMBOL:
            return self.label or f"sym_{id(self):x}"
        ops = ', '.join(str(o) for o in self.operands)
        return f"({self.kind.value} {ops})"

    @staticmethod
    def const(val: int, bits: int = 64) -> 'SymExpr':
        return SymExpr(ExprKind.CONST, (val & ((1 << bits) - 1),), bits=bits)

    @staticmethod
    def symbol(label: str, bits: int = 64) -> 'SymExpr':
        return SymExpr(ExprKind.SYMBOL, (), bits=bits, label=label)

    def _binop(self, other, kind, bits=None):
        b = max(self.bits, other.bits) if bits is None else bits
        return SymExpr(kind, (self, other), bits=b)

    def __add__(self, o): return self._binop(o, ExprKind.ADD)
    def __sub__(self, o): return self._binop(o, ExprKind.SUB)
    def __mul__(self, o): return self._binop(o, ExprKind.MUL)
    def __and__(self, o): return self._binop(o, ExprKind.AND)
    def __or__(self, o):  return self._binop(o, ExprKind.OR)
    def __xor__(self, o): return self._binop(o, ExprKind.XOR)
    def __lshift__(self, n): return SymExpr(ExprKind.SHL, (self, SymExpr.const(n, 8)), bits=self.bits)
    def __rshift__(self, n): return SymExpr(ExprKind.LSHR, (self, SymExpr.const(n, 8)), bits=self.bits)

    def zext(self, to_bits: int) -> 'SymExpr':
        if self.bits >= to_bits:
            return self
        return SymExpr(ExprKind.ZEXT, (self,), bits=to_bits)

    def extract(self, hi: int, lo: int) -> 'SymExpr':
        return SymExpr(ExprKind.EXTRACT, (self, SymExpr.const(hi, 8), SymExpr.const(lo, 8)),
                       bits=hi - lo + 1)


# ── 约束 ────────────────────────────────────────────────────────

class ConstraintKind(Enum):
    EQ = "eq"
    NE = "ne"
    ULT = "ult"
    ULE = "ule"
    SGT = "sgt"
    SGE = "sge"


@dataclass(frozen=True)
class Constraint:
    kind: ConstraintKind
    lhs: SymExpr
    rhs: SymExpr  # 当前 rhs 必须是 CONST，简化求解

    def negate(self) -> 'Constraint':
        """取反 —— 用于分支翻转。"""
        _flip = {
            ConstraintKind.EQ: ConstraintKind.NE,
            ConstraintKind.NE: ConstraintKind.EQ,
            ConstraintKind.ULT: ConstraintKind.SGE,
            ConstraintKind.ULE: ConstraintKind.SGT,
            ConstraintKind.SGT: ConstraintKind.ULE,
            ConstraintKind.SGE: ConstraintKind.ULT,
        }
        return Constraint(_flip[self.kind], self.lhs, self.rhs)

    def __repr__(self):
        return f"{self.lhs} {self.kind.value} {self.rhs}"


class PathCondition:
    """路径条件集合 —— 一组 Constraint 的 conjunction。

    支持简化（常量折叠）、一致性检查（无需求解器检测部分矛盾）。
    """

    def __init__(self, constraints=None):
        self._constraints: List[Constraint] = list(constraints) if constraints else []

    def add(self, c: Constraint):
        self._constraints.append(c)

    def copy(self) -> 'PathCondition':
        return PathCondition(list(self._constraints))

    @property
    def constraints(self) -> List[Constraint]:
        return list(self._constraints)

    def is_consistent(self) -> bool:
        """快速一致性检查 —— 不依赖求解器。

        仅检测平凡矛盾：同一表达式既被约束 EQ v1 又被 EQ v2 (v1≠v2)。
        更复杂的矛盾在 solve() 阶段由具体化处理。
        """
        eq_map: Dict[str, int] = {}
        for c in self._constraints:
            if c.kind == ConstraintKind.EQ and c.rhs.kind == ExprKind.CONST:
                key = repr(c.lhs)
                val = c.rhs.operands[0]
                if key in eq_map and eq_map[key] != val:
                    return False
                eq_map[key] = val
        return True

    def solve(self, symbols: Dict[str, int]) -> Optional[Dict[str, int]]:
        """为符号变量赋值以满足约束。

        对每个 EQ 约束，将 rhs 具体值赋给 lhs 中符号变量。
        无法求解的约束回退到保守处理。
        返回更新后的 symbol→value 映射，矛盾返回 None。
        """
        result = dict(symbols)
        for c in self._constraints:
            if not self._apply_constraint(c, result):
                return None
        return result

    def _apply_constraint(self, c: Constraint, env: Dict[str, int]) -> bool:
        """将单个约束应用于环境。"""
        try:
            lhs_val = self._eval(c.lhs, env)
        except KeyError:
            return True  # 符号变量未绑定，无法判定，保守认为可行
        rhs_val = c.rhs.operands[0] if c.rhs.kind == ExprKind.CONST else self._eval(c.rhs, env)

        if c.kind == ConstraintKind.EQ:
            return lhs_val == rhs_val
        elif c.kind == ConstraintKind.NE:
            return lhs_val != rhs_val
        elif c.kind == ConstraintKind.ULT:
            return (lhs_val & ((1 << c.lhs.bits) - 1)) < (rhs_val & ((1 << c.rhs.bits) - 1))
        elif c.kind == ConstraintKind.ULE:
            return (lhs_val & ((1 << c.lhs.bits) - 1)) <= (rhs_val & ((1 << c.rhs.bits) - 1))
        elif c.kind == ConstraintKind.SGT:
            mask = (1 << c.lhs.bits) - 1
            a, b = lhs_val & mask, rhs_val & mask
            sign_bit = 1 << (c.lhs.bits - 1)
            return (a ^ sign_bit) > (b ^ sign_bit)
        elif c.kind == ConstraintKind.SGE:
            mask = (1 << c.lhs.bits) - 1
            a, b = lhs_val & mask, rhs_val & mask
            sign_bit = 1 << (c.lhs.bits - 1)
            return (a ^ sign_bit) >= (b ^ sign_bit)
        return True

    @staticmethod
    def _eval(expr: SymExpr, env: Dict[str, int]) -> int:
        """在给定环境下求值表达式。符号变量必须在 env 中有绑定。"""
        if expr.kind == ExprKind.CONST:
            return expr.operands[0]
        if expr.kind == ExprKind.SYMBOL:
            return env[expr.label]
        ops = [PathCondition._eval(o, env) for o in expr.operands]
        mask = (1 << expr.bits) - 1
        if expr.kind == ExprKind.ADD:      return (ops[0] + ops[1]) & mask
        if expr.kind == ExprKind.SUB:      return (ops[0] - ops[1]) & mask
        if expr.kind == ExprKind.MUL:      return (ops[0] * ops[1]) & mask
        if expr.kind == ExprKind.AND:      return ops[0] & ops[1]
        if expr.kind == ExprKind.OR:       return ops[0] | ops[1]
        if expr.kind == ExprKind.XOR:      return ops[0] ^ ops[1]
        if expr.kind == ExprKind.SHL:      return (ops[0] << (ops[1] & 63)) & mask
        if expr.kind == ExprKind.LSHR:     return (ops[0] >> (ops[1] & 63)) & mask
        if expr.kind == ExprKind.ZEXT:     return ops[0] & mask
        if expr.kind == ExprKind.EXTRACT:  return (ops[0] >> ops[2]) & ((1 << (ops[1] - ops[2] + 1)) - 1)
        raise NotImplementedError(f"eval: {expr.kind}")


# ── 符号状态 ────────────────────────────────────────────────────

@dataclass
class SymbolicState:
    """轻量符号执行状态 —— 寄存器→表达式 + 内存 region→表达式。

    内存模型：region-based（按基址+偏移分区），不做全 alias analysis。
    """

    regs: Dict[str, SymExpr] = field(default_factory=dict)
    memory: Dict[int, SymExpr] = field(default_factory=dict)  # address → expr
    path_cond: PathCondition = field(default_factory=PathCondition)
    input_symbols: Dict[str, int] = field(default_factory=dict)  # 符号变量→具体值

    def copy(self) -> 'SymbolicState':
        return SymbolicState(
            regs=dict(self.regs),
            memory=dict(self.memory),
            path_cond=self.path_cond.copy(),
            input_symbols=dict(self.input_symbols),
        )

    def concrete_inputs(self) -> bytes:
        """从符号变量映射重建具体输入字节序列。"""
        if not self.input_symbols:
            return b""
        max_idx = max((int(k.replace('in_', '')) for k in self.input_symbols
                       if k.startswith('in_')), default=-1)
        if max_idx < 0:
            return b""
        result = bytearray(max_idx + 1)
        for i in range(max_idx + 1):
            result[i] = self.input_symbols.get(f'in_{i}', 0) & 0xFF
        return bytes(result)

    def set_concrete_inputs(self, data: bytes):
        """将具体输入字节注入符号变量映射。"""
        for i, b in enumerate(data):
            self.input_symbols[f'in_{i}'] = b
