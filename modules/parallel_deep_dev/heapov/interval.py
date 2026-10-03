"""区间域 — 容量感知耦合边界验证 的数值抽象。

区间以 None 表示无界，避免哨兵值与真实值冲突。
align_up 计算 glibc 16 字节对齐后的 chunk 载荷容量，
是误报过滤中"对齐冗余"判定的依据。
"""


import operator
from dataclasses import dataclass
from typing import Dict, Optional

from .expr_ast import (
    Expr, Const, Var, Neg, Binary, Call, Sizeof,
    is_arith_op, is_cmp_op, is_logic_op,
)


@dataclass(frozen=True)
class Interval:
    lo: Optional[int] = None  # None = 下界未知
    hi: Optional[int] = None  # None = 上界未知

    @staticmethod
    def top() -> 'Interval':
        return Interval(None, None)

    @staticmethod
    def exact(v: int) -> 'Interval':
        return Interval(v, v)

    def is_top(self) -> bool:
        return self.lo is None and self.hi is None

    def join(self, other: 'Interval') -> 'Interval':
        lo = self.lo if other.lo is None else (other.lo if self.lo is None
                                               else min(self.lo, other.lo))
        hi = self.hi if other.hi is None else (other.hi if self.hi is None
                                               else max(self.hi, other.hi))
        return Interval(lo, hi)

    def meet(self, other: 'Interval') -> 'Interval':
        if self.lo is None:
            lo = other.lo
        elif other.lo is None:
            lo = self.lo
        else:
            lo = max(self.lo, other.lo)
        if self.hi is None:
            hi = other.hi
        elif other.hi is None:
            hi = self.hi
        else:
            hi = min(self.hi, other.hi)
        return Interval(lo, hi)

    def __repr__(self) -> str:
        def f(v):
            return '?' if v is None else str(v)
        return f'[{f(self.lo)}, {f(self.hi)}]'


def align_up(size: int, alignment: int = 16) -> int:
    """对齐到 alignment 整数倍。"""
    return ((size + alignment - 1) // alignment) * alignment


def _arith(op: str, a: Interval, b: Interval) -> Interval:
    """二元算术区间运算。任一操作数无界时保守返回 top。"""
    if a.lo is None or a.hi is None or b.lo is None or b.hi is None:
        return Interval.top()
    if op == '+':
        return Interval(a.lo + b.lo, a.hi + b.hi)
    if op == '-':
        return Interval(a.lo - b.hi, a.hi - b.lo)
    if op == '*':
        cands = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]
        return Interval(min(cands), max(cands))
    if op == '/':
        if b.lo <= 0 <= b.hi:
            return Interval.top()
        cands = [a.lo // b.lo, a.lo // b.hi, a.hi // b.lo, a.hi // b.hi]
        return Interval(min(cands), max(cands))
    if op == '%':
        if b.lo is None or b.lo <= 0:
            return Interval.top()
        return Interval(0, b.hi - 1 if b.hi is not None else None)
    if op == '<<':
        if b.lo < 0:
            return Interval.top()
        return Interval(a.lo << b.lo, a.hi << b.hi)
    if op == '>>':
        if b.lo < 0:
            return Interval.top()
        return Interval(a.lo >> b.hi, a.hi >> b.lo)
    return Interval.top()


def _cmp(op: str, a: Interval, b: Interval) -> Interval:
    """比较表达式结果区间 — 比较返回布尔(0/1)。"""
    if op == '==' or op == '!=':
        return Interval(0, 1)
    if op == '<':
        if a.hi is not None and b.lo is not None and a.hi < b.lo:
            return Interval.exact(1)
        if a.lo is not None and b.hi is not None and a.lo >= b.hi:
            return Interval.exact(0)
    if op == '<=':
        if a.hi is not None and b.lo is not None and a.hi <= b.lo:
            return Interval.exact(1)
        if a.lo is not None and b.hi is not None and a.lo > b.hi:
            return Interval.exact(0)
    if op == '>':
        if a.lo is not None and b.hi is not None and a.lo > b.hi:
            return Interval.exact(1)
        if a.hi is not None and b.lo is not None and a.hi <= b.lo:
            return Interval.exact(0)
    if op == '>=':
        if a.lo is not None and b.hi is not None and a.lo >= b.hi:
            return Interval.exact(1)
        if a.hi is not None and b.lo is not None and a.hi < b.lo:
            return Interval.exact(0)
    return Interval(0, 1)


def eval_expr(e: Expr, env: Dict[str, Interval],
              tainted: Optional[set] = None) -> Interval:
    """在 env 上求值表达式区间。未知变量→top，调用→top。

    tainted 仅用于识别 strlen 类来源，扩大上界由调用方控制。
    """
    if isinstance(e, Const):
        return Interval.exact(e.value)
    if isinstance(e, Sizeof):
        if e.value > 0:
            return Interval.exact(e.value)
        return Interval.top()
    if isinstance(e, Var):
        return env.get(e.name, Interval.top())
    if isinstance(e, Neg):
        iv = eval_expr(e.operand, env, tainted)
        if iv.lo is None or iv.hi is None:
            return Interval.top()
        return Interval(-iv.hi, -iv.lo)
    if isinstance(e, Binary):
        op = e.op
        if is_logic_op(op):
            left = eval_expr(e.left, env, tainted)
            right = eval_expr(e.right, env, tainted)
            if op == '&&':
                if left == Interval.exact(0) or right == Interval.exact(0):
                    return Interval.exact(0)
                if (left == Interval.exact(1) and right == Interval.exact(1)):
                    return Interval.exact(1)
                return Interval(0, 1)
            return Interval(0, 1)
        if is_cmp_op(op):
            return _cmp(op, eval_expr(e.left, env, tainted),
                        eval_expr(e.right, env, tainted))
        if is_arith_op(op):
            return _arith(op, eval_expr(e.left, env, tainted),
                          eval_expr(e.right, env, tainted))
        return Interval.top()
    if isinstance(e, Call):
        # strlen(src) 的上界未知; 返回 top 交由 taint 判定
        return Interval.top()
    return Interval.top()


def le_provable(a: Interval, b: Interval) -> bool:
    """a <= b 可证明成立。"""
    return a.hi is not None and b.lo is not None and a.hi <= b.lo


def gt_provable(a: Interval, b: Interval) -> bool:
    """a > b 可证明成立。"""
    return a.lo is not None and b.hi is not None and a.lo > b.hi


def scalar_ge(e: Expr, bound: int, env: Dict[str, Interval],
              tainted: Optional[set] = None) -> bool:
    """e 的下界可证明 >= bound。"""
    iv = eval_expr(e, env, tainted)
    return iv.lo is not None and iv.lo >= bound
