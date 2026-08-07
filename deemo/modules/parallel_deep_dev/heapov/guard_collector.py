"""守卫约束收集 — 把 if/for/while 条件转为可精化区间的约束。

关键处理: 无 else 且 then 分支为 return/break 的 if, 其否定
约束作用于后续语句 — 这是 "if (len > size) return;" 后
memcpy 安全的通用模式, 也是误报过滤的核心守卫信号。
"""


from typing import Dict, List

from heapov.expr_ast import (
    Expr, Const, Var, Binary, Neg, Call,
)
from heapov import cparser as cp
from heapov.model import GuardConstraint

_CMP = frozenset(['<', '<=', '>', '>=', '==', '!='])


def _decompose(cond: Expr, negate: bool = False) -> List[GuardConstraint]:
    """条件分解为约束列表。|| 无法安全分解, 忽略。"""
    if isinstance(cond, Binary) and cond.op == '&&':
        return (_decompose(cond.left, negate)
                + _decompose(cond.right, negate))
    if isinstance(cond, Binary) and cond.op in _CMP:
        op = cond.op
        if negate:
            op = _negate_op(op)
        return [GuardConstraint(op, cond.left, cond.right)]
    if isinstance(cond, Binary) and cond.op == '==':
        if isinstance(cond.right, Const) and cond.right.value == 0:
            if negate:
                return [GuardConstraint('!=', cond.left, Const(0))]
            return [GuardConstraint('==', cond.left, Const(0))]
        if isinstance(cond.left, Const) and cond.left.value == 0:
            return [GuardConstraint('==', cond.right, Const(0))]
    if isinstance(cond, Binary) and cond.op == '!=':
        if isinstance(cond.right, Const) and cond.right.value == 0:
            if negate:
                return [GuardConstraint('==', cond.left, Const(0))]
            return [GuardConstraint('!=', cond.left, Const(0))]
    if isinstance(cond, Neg):
        return _decompose(cond.operand, not negate)
    return []


def _negate_op(op: str) -> str:
    return {'<': '>=', '<=': '>', '>': '<=', '>=': '<',
            '==': '!=', '!=': '=='}[op]


def _is_dead_end(stmt) -> bool:
    if isinstance(stmt, cp.Return):
        return True
    if isinstance(stmt, cp.Block):
        if not stmt.stmts:
            return False
        last = stmt.stmts[-1]
        return _is_dead_end(last)
    if isinstance(stmt, cp.If):
        return (stmt.then_b is not None and stmt.else_b is not None
                and _is_dead_end(stmt.then_b) and _is_dead_end(stmt.else_b))
    return False


def _for_loop_constraints(f: cp.For) -> List[GuardConstraint]:
    """for(i=0;i<n;i++) → i<n 约束。"""
    if f.cond is None:
        return []
    return _decompose(f.cond, negate=False)


def collect_guards(func: cp.Func) -> Dict[int, List[GuardConstraint]]:
    """返回 id(statement) → 生效中的守卫约束列表。"""
    out: Dict[int, List[GuardConstraint]] = {}

    def as_list(stmt) -> List:
        return stmt.stmts if isinstance(stmt, cp.Block) else [stmt]

    def walk(stmts: List, ctx: List[GuardConstraint]) -> None:
        i = 0
        while i < len(stmts):
            s = stmts[i]
            out[id(s)] = list(ctx)
            if isinstance(s, cp.If):
                conds = _decompose(s.cond)
                negs = _decompose(s.cond, negate=True)
                walk(as_list(s.then_b), ctx + conds)
                if s.else_b is not None:
                    walk(as_list(s.else_b), ctx + negs)
                elif _is_dead_end(s.then_b):
                    # then 分支必然退出: 后续语句受否定约束
                    ctx = ctx + negs
            elif isinstance(s, cp.For):
                loop_conds = _for_loop_constraints(s)
                walk(as_list(s.body), ctx + loop_conds)
            elif isinstance(s, cp.While):
                walk(as_list(s.body), ctx + _decompose(s.cond))
            elif isinstance(s, cp.Block):
                walk(s.stmts, ctx)
            i += 1

    walk(func.body.stmts, [])
    return out
