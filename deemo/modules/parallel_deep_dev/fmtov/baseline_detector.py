"""朴素格式化字符串基线 — 格式参数不是字面量即报。

不做污点/字面量来源分析: 变量格式串一律告警, 构造高误报
参照系, 用于量化 FSV 的误报削减。
"""

from __future__ import annotations

from typing import List

from heapov.cparser import parse_source_full
from heapov.expr_ast import Var, Const
from heapov.stmts import If, For, While, Block, CallStmt
from heapov.dataflow import _stmt_list

from fmtov.taint import FMT_FUNCS


def _is_literal(fmt) -> bool:
    if isinstance(fmt, Var):
        return fmt.name.startswith('__str__')
    return False


def analyze_baseline(src: str) -> List[dict]:
    funcs, _ = parse_source_full(src)
    report: List[dict] = []

    def walk(stmts, func_name) -> None:
        for s in stmts:
            items = s if isinstance(s, list) else [s]
            for it in items:
                if isinstance(it, Block):
                    walk(it.stmts, func_name)
                elif isinstance(it, If):
                    walk(_stmt_list(it.then_b), func_name)
                    if it.else_b is not None:
                        walk(_stmt_list(it.else_b), func_name)
                elif isinstance(it, (For, While)):
                    walk(_stmt_list(it.body), func_name)
                elif isinstance(it, CallStmt) and it.call.name in FMT_FUNCS:
                    idx = FMT_FUNCS[it.call.name]
                    if len(it.call.args) <= idx:
                        continue
                    fmt = it.call.args[idx]
                    if not _is_literal(fmt):
                        report.append(_mk(func_name, it.call.name, fmt))

    for func in funcs:
        walk(_stmt_list(func.body), func.name)
    report.sort(key=lambda r: -r['confidence'])
    return report


def _mk(func: str, call: str, fmt) -> dict:
    from heapov.expr_ast import expr_str
    return {
        'func': func, 'fmt': expr_str(fmt), 'call': call,
        'verdict': 'FORMAT_STRING', 'confidence': 0.5,
        'reasons': ['non-literal-format'],
        'description': f'{call} 使用非字面量格式串', 'pos': 0,
    }
