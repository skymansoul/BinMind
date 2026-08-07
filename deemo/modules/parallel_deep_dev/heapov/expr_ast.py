"""表达式抽象语法树 — CACBV 容量分析的基础对象。

表达式树仅承载结构，不持有语义；区间求值与符号比较由
interval 与 coupling_check 在各自域上完成，避免域耦合。
"""


from dataclasses import dataclass, field
from typing import List, Optional, Tuple


class Expr:
    """表达式基类。"""

    def vars(self) -> set:
        raise NotImplementedError

    def is_const(self) -> bool:
        return False

    def const_value(self) -> Optional[int]:
        return None


@dataclass
class Const(Expr):
    value: int

    def vars(self) -> set:
        return set()

    def is_const(self) -> bool:
        return True

    def const_value(self) -> Optional[int]:
        return self.value


@dataclass
class Var(Expr):
    name: str

    def vars(self) -> set:
        return {self.name}


@dataclass
class Neg(Expr):
    operand: Expr

    def vars(self) -> set:
        return self.operand.vars()


@dataclass
class Binary(Expr):
    op: str  # + - * / % << >> & | ^ == != < <= > >= && ||
    left: Expr
    right: Expr

    def vars(self) -> set:
        return self.left.vars() | self.right.vars()


@dataclass
class Call(Expr):
    name: str
    args: List[Expr] = field(default_factory=list)

    def vars(self) -> set:
        s: set = set()
        for a in self.args:
            s |= a.vars()
        return s


@dataclass
class Index(Expr):
    base: Expr
    index: Expr

    def vars(self) -> set:
        return self.base.vars() | self.index.vars()


@dataclass
class Field(Expr):
    base: Expr
    name: str

    def vars(self) -> set:
        return self.base.vars()


@dataclass
class Deref(Expr):
    operand: Expr

    def vars(self) -> set:
        return self.operand.vars()


@dataclass
class Addr(Expr):
    operand: Expr

    def vars(self) -> set:
        return self.operand.vars()


@dataclass
class Sizeof(Expr):
    """sizeof(type) — 编译期常量。"""
    type_name: str
    value: int = 0

    def vars(self) -> set:
        return set()

    def is_const(self) -> bool:
        return self.value > 0

    def const_value(self) -> Optional[int]:
        return self.value if self.value > 0 else None


_ARITH_BINOPS = frozenset(['+', '-', '*', '/', '%', '<<', '>>', '&', '|', '^'])
_CMP_BINOPS = frozenset(['==', '!=', '<', '<=', '>', '>='])
_LOGIC_BINOPS = frozenset(['&&', '||'])


def is_arith_op(op: str) -> bool:
    return op in _ARITH_BINOPS


def is_cmp_op(op: str) -> bool:
    return op in _CMP_BINOPS


def is_logic_op(op: str) -> bool:
    return op in _LOGIC_BINOPS


def substitute(e: Expr, var: str, repl: Expr) -> Expr:
    """把表达式中的变量替换为 repl。用于守卫上界代换。"""
    if isinstance(e, Var):
        return repl if e.name == var else e
    if isinstance(e, Neg):
        return Neg(substitute(e.operand, var, repl))
    if isinstance(e, Binary):
        return Binary(e.op, substitute(e.left, var, repl),
                      substitute(e.right, var, repl))
    if isinstance(e, Index):
        return Index(substitute(e.base, var, repl),
                     substitute(e.index, var, repl))
    if isinstance(e, Field):
        return Field(substitute(e.base, var, repl), e.name)
    if isinstance(e, Deref):
        return Deref(substitute(e.operand, var, repl))
    if isinstance(e, Addr):
        return Addr(substitute(e.operand, var, repl))
    if isinstance(e, Call):
        return Call(e.name, [substitute(a, var, repl) for a in e.args])
    return e


def substitute_sizeof(e: Expr, sizes: dict) -> Expr:
    """把未知尺寸的 sizeof(变量) 代换为数组尺寸表给出的常量。"""
    if isinstance(e, Sizeof) and e.value == 0:
        v = sizes.get(e.type_name)
        if v is not None:
            return Const(v)
        return e
    if isinstance(e, Neg):
        return Neg(substitute_sizeof(e.operand, sizes))
    if isinstance(e, Binary):
        return Binary(e.op, substitute_sizeof(e.left, sizes),
                      substitute_sizeof(e.right, sizes))
    if isinstance(e, Index):
        return Index(substitute_sizeof(e.base, sizes),
                     substitute_sizeof(e.index, sizes))
    if isinstance(e, Field):
        return Field(substitute_sizeof(e.base, sizes), e.name)
    if isinstance(e, Deref):
        return Deref(substitute_sizeof(e.operand, sizes))
    if isinstance(e, Addr):
        return Addr(substitute_sizeof(e.operand, sizes))
    if isinstance(e, Call):
        return Call(e.name, [substitute_sizeof(a, sizes) for a in e.args])
    return e


def expr_str(e: Expr) -> str:
    """调试用字符串表示。"""
    if isinstance(e, Const):
        return str(e.value)
    if isinstance(e, Var):
        return e.name
    if isinstance(e, Neg):
        return f'-({expr_str(e.operand)})'
    if isinstance(e, Binary):
        return f'({expr_str(e.left)} {e.op} {expr_str(e.right)})'
    if isinstance(e, Call):
        return f'{e.name}({",".join(expr_str(a) for a in e.args)})'
    if isinstance(e, Index):
        return f'{expr_str(e.base)}[{expr_str(e.index)}]'
    if isinstance(e, Field):
        return f'{expr_str(e.base)}.{e.name}'
    if isinstance(e, Deref):
        return f'*({expr_str(e.operand)})'
    if isinstance(e, Addr):
        return f'&({expr_str(e.operand)})'
    if isinstance(e, Sizeof):
        return f'sizeof({e.type_name})'
    return '?'


def _merge(l1: Tuple[dict, int], l2: Tuple[dict, int], sign: int) -> Tuple[dict, int]:
    """合并两条线性形式: l1 + sign*l2。"""
    c1, k1 = l1
    c2, k2 = l2
    out = dict(c1)
    for v, x in c2.items():
        out[v] = out.get(v, 0) + sign * x
    return out, k1 + sign * k2


def linearize(e: Expr) -> Tuple[dict, int]:
    """将 + / - / 常量乘 表达式规约为 c*var 求和形式。

    规约失败的项整体视为未知(返回空系数+0常数) — 调用方
    据此退化为区间比较，保证符号域失败时仍可判定。
    返回 (coefs, const)。
    """
    if isinstance(e, Const):
        return {}, e.value
    if isinstance(e, Var):
        return {e.name: 1}, 0
    if isinstance(e, Neg):
        c, k = linearize(e.operand)
        return {v: -x for v, x in c.items()}, -k
    if isinstance(e, Binary) and e.op == '+':
        return _merge(linearize(e.left), linearize(e.right), 1)
    if isinstance(e, Binary) and e.op == '-':
        return _merge(linearize(e.left), linearize(e.right), -1)
    if isinstance(e, Binary) and e.op == '*' and isinstance(e.right, Const):
        c, k = linearize(e.left)
        return {v: x * e.right.value for v, x in c.items()}, k * e.right.value
    if isinstance(e, Binary) and e.op == '*' and isinstance(e.left, Const):
        c, k = linearize(e.right)
        return {v: x * e.left.value for v, x in c.items()}, k * e.left.value
    # 非线性项(乘变量、除法、调用等)无法线性化
    return {}, 0
