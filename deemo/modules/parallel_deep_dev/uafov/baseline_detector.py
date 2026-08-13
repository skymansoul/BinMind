"""朴素 UAF 基线 — 变量一旦被释放, 其后的解引用/传参即报。

保留一次别名解析(文本级)以覆盖 q=p 穿透; 不做对象流/分支互斥,
重绑定与空化不重置已释放标记, 构造高误报参照系。
"""

from __future__ import annotations

from typing import List

from heapov.cparser import parse_source_full
from heapov.expr_ast import Var, Deref, Field, Index, Call, Binary, Const
from heapov.stmts import Assign, CallStmt, ExprStmt, Decl
from heapov.dataflow import iter_statements


def _root_var(e) -> str:
    """表达式根变量名。"""
    if isinstance(e, Var):
        return e.name
    if isinstance(e, (Field, Index)):
        return _root_var(e.base)
    if isinstance(e, Deref):
        return _root_var(e.operand)
    if isinstance(e, Binary):
        if isinstance(e.left, Var):
            return e.left.name
        return _root_var(e.left)
    return ''


def _deref_vars(expr) -> List[str]:
    """表达式内解引用的根变量名列表。"""
    out = []
    if isinstance(expr, Var):
        return []
    if isinstance(expr, (Deref, Field, Index)):
        base = expr.base if isinstance(expr, (Field, Index)) else expr.operand
        r = _root_var(base)
        if r:
            out.append(r)
        out.extend(_deref_vars(base))
        if isinstance(expr, Index):
            out.extend(_deref_vars(expr.index))
        return out
    if isinstance(expr, Call):
        for a in expr.args:
            out.extend(_deref_vars(a))
        return out
    if isinstance(expr, Binary):
        out.extend(_deref_vars(expr.left))
        out.extend(_deref_vars(expr.right))
    return out


def _target_vars(tgt) -> List[str]:
    if isinstance(tgt, Var):
        return []
    return _deref_vars(tgt)


def analyze_baseline(src: str) -> List[dict]:
    funcs, _ = parse_source_full(src)
    report: List[dict] = []
    for func in funcs:
        freed: set = set()
        alias: dict = {}

        def resolve(v: str) -> str:
            seen = 0
            while v in alias and seen < 8:
                v = alias[v]
                seen += 1
            return v

        def flag(var: str, pos: int) -> None:
            if resolve(var) in freed:
                report.append(_mk(func.name, var, pos))

        for it in iter_statements(func):
            if isinstance(it, Decl):
                if it.init is not None:
                    if isinstance(it.init, Var):
                        alias[it.name] = it.init.name
                    for v in _deref_vars(it.init):
                        flag(v, 0)
            elif isinstance(it, Assign):
                if isinstance(it.target, Var):
                    if isinstance(it.value, Var):
                        alias[it.target.name] = it.value.name
                    else:
                        for v in _deref_vars(it.value):
                            flag(v, 0)
                else:
                    for v in _target_vars(it.target):
                        flag(v, 0)
                    for v in _deref_vars(it.value):
                        flag(v, 0)
            elif isinstance(it, CallStmt):
                if it.call.name == 'free' and it.call.args:
                    a = it.call.args[0]
                    base = _root_var(a)
                    if base:
                        if base in freed:
                            report.append(_mk(func.name, base, 0, 'double-free'))
                        freed.add(base)
                    continue
                for v in _deref_vars(it.call):
                    flag(v, 0)
                for arg in it.call.args:
                    if isinstance(arg, Var):
                        flag(arg.name, 0)
            elif isinstance(it, ExprStmt):
                for v in _deref_vars(it.expr):
                    flag(v, 0)
    report.sort(key=lambda r: -r['confidence'])
    return report


def _mk(func: str, var: str, pos: int, kind: str = 'uaf') -> dict:
    return {
        'func': func, 'base_var': var, 'verdict': 'DOUBLE_FREE' if kind == 'double-free' else 'UAF',
        'confidence': 0.5, 'reasons': ['naive'],
        'description': 'use after free(%s)' % var, 'kind': kind,
        'free_pos': 0, 'use_pos': pos,
    }
