"""分配点提取 — malloc/calloc/realloc 及其符号大小。

calloc(n, sz) 的大小合并为 n*sz; 同变量多次分配取最后一次
(与 realloc 语义一致), 避免用已被替代的旧分配做判定。
"""


from typing import List

from heapov.expr_ast import (
    Expr, Var, Const, Binary, Call, Sizeof,
)
from heapov import cparser as cp
from heapov.dataflow import iter_statements
from heapov.model import AllocSite


def _size_of_alloc(call: Call, args: List[Expr]) -> Expr:
    """分配调用的字节大小表达式。realloc 大小在参数 1。"""
    name = call.name
    if name == 'calloc':
        if len(args) >= 2:
            return Binary('*', args[0], args[1])
        return args[0] if args else Const(0)
    if name == 'realloc':
        return args[1] if len(args) >= 2 else (args[0] if args else Const(0))
    return args[0] if args else Const(0)


def _is_alloc_call(e: Expr):
    if isinstance(e, Call) and e.name in ('malloc', 'calloc', 'realloc',
                                          'aligned_alloc', 'memalign'):
        return e
    return None


def _const_size(expr: Expr) -> int:
    if isinstance(expr, Const):
        return expr.value
    if isinstance(expr, Sizeof):
        return expr.value
    if isinstance(expr, Binary) and expr.op == '*':
        l = _const_size(expr.left)
        r = _const_size(expr.right)
        if l > 0 and r > 0:
            return l * r
    return 0


def extract_allocs(func: cp.Func) -> List[AllocSite]:
    """提取函数内全部分配点, 同变量取最后一次。"""
    out: dict = {}
    for it in iter_statements(func):
        if isinstance(it, cp.Decl):
            if it.init is not None:
                call = _is_alloc_call(it.init)
                if call:
                    size = _size_of_alloc(call, call.args)
                    out[it.name] = AllocSite(
                        var=it.name, size_expr=size,
                        kind=call.name, func=func.name,
                        const_size=_const_size(size),
                        is_dynamic=_const_size(size) <= 0)
        elif isinstance(it, cp.Assign) and isinstance(it.target, Var):
            call = _is_alloc_call(it.value)
            if call:
                size = _size_of_alloc(call, call.args)
                out[it.target.name] = AllocSite(
                    var=it.target.name, size_expr=size,
                    kind=call.name, func=func.name,
                    const_size=_const_size(size),
                    is_dynamic=_const_size(size) <= 0)
    return list(out.values())
