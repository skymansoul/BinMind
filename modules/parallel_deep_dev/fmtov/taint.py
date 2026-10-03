"""轻量污点传播 — 跟踪攻击者可控变量与字面量来源格式串。

与 heapov 的区间数据流不同, 此处只关心两件事:
  1. 变量是否 tainted (源自参数/输入函数/用户数据缓冲)
  2. 变量是否持有字符串字面量 (literal 来源)

sprintf/strcpy/read 把用户数据写入缓冲 → 目标变量 tainted,
使 "先 sprintf 组装再 printf" 的间接格式串违约可被追溯。
"""

from __future__ import annotations

from typing import Dict, List, Optional, Set

from ..heapov.expr_ast import Expr, Var, Const, Binary, Call, Index, Field, Deref
from ..heapov.stmts import (
    Assign, CallStmt, ExprStmt, If, For, While, Decl, Func,
)
from ..heapov.dataflow import _stmt_list

# 直接产生污点的调用 (返回值/副作用输入)
_TAINT_SOURCES = frozenset([
    'read', 'recv', 'recvfrom', 'scanf', 'fgets', 'gets', 'getenv',
    'strlen', 'atoi', 'atol', 'atoll', 'strtol', 'strtoul',
])
# 把数据写入缓冲的调用: 目标被污点化
_BUF_WRITERS = frozenset([
    'sprintf', 'snprintf', 'vsprintf', 'vsnprintf',
    'strcpy', 'strncpy', 'strcat', 'strncat',
    'memcpy', 'memmove',
])
# 读入输出参数的调用 (scanf 族): 格式位之后的实参被污点化
_SCANF_WRITERS = {
    'scanf': 0, 'sscanf': 1, 'fscanf': 1,
}
# 格式化函数及格式参数位
FMT_FUNCS = {
    'printf': 0, 'vprintf': 0,
    'fprintf': 1, 'vfprintf': 1,
    'sprintf': 1, 'vsprintf': 1, 'snprintf': 2, 'vsnprintf': 2,
    'syslog': 1,
}


class TaintEnv:
    """按语句顺序维护 tainted 集合与 literal 来源变量。"""

    def __init__(self, params: List[str]) -> None:
        self.tainted: Set[str] = set(params)
        self.literal_vars: Set[str] = set()
        self.literal_strs: Dict[str, str] = {}

    def apply_stmt(self, stmt, lits: dict) -> None:
        if isinstance(stmt, Decl):
            if stmt.init is not None:
                self._assign(stmt.name, stmt.init, lits)
        elif isinstance(stmt, Assign):
            if isinstance(stmt.target, Var):
                self._assign(stmt.target.name, stmt.value, lits)
            else:
                # 数组/解引用目标: buf[i] = 污点 → 基变量污点化
                base = _base_var(stmt.target)
                if base and self.expr_tainted(stmt.value):
                    self.tainted.add(base)
        elif isinstance(stmt, CallStmt):
            self._apply_call(stmt.call, lits)
        elif isinstance(stmt, ExprStmt):
            pass

    def _assign(self, var: str, value: Expr, lits: dict) -> None:
        if isinstance(value, Var) and value.name.startswith('__str__'):
            self.literal_vars.add(var)
            self.literal_strs[var] = lits.get(value.name, '')
            self.tainted.discard(var)
            return
        if isinstance(value, Var):
            if value.name in self.literal_vars:
                self.literal_vars.add(var)
                self.literal_strs[var] = self.literal_strs.get(value.name, '')
            self._taint_from_var(var, value.name)
            return
        if isinstance(value, Call) and value.name in _TAINT_SOURCES:
            self.tainted.add(var)
            return
        if isinstance(value, Const):
            self.tainted.discard(var)
            return
        for v in value.vars():
            if v in self.tainted:
                self.tainted.add(var)
                return
        if isinstance(value, Call):
            self.tainted.add(var)

    def _taint_from_var(self, var: str, src: str) -> None:
        if src in self.tainted:
            self.tainted.add(var)

    def _apply_call(self, call: Call, lits: dict) -> None:
        if not call.args:
            return
        name = call.name
        if name in _SCANF_WRITERS:
            fmt_idx = _SCANF_WRITERS[name]
            for a in call.args[fmt_idx + 1:]:
                base = _base_var(a)
                if base:
                    self.tainted.add(base)
            return
        if name in _BUF_WRITERS:
            dst = call.args[0]
            if isinstance(dst, Var):
                for a in call.args[1:]:
                    for v in a.vars():
                        if v in self.tainted:
                            self.tainted.add(dst.name)
                            return
        elif name in _TAINT_SOURCES:
            for a in call.args:
                if isinstance(a, Var):
                    self.tainted.add(a.name)

    def expr_tainted(self, e: Expr) -> bool:
        return any(v in self.tainted for v in e.vars())

    def expr_literal(self, e: Expr) -> bool:
        if isinstance(e, Var):
            return e.name.startswith('__str__') or e.name in self.literal_vars
        return False


def _base_var(e: Expr) -> Optional[str]:
    """取目标表达式的基变量名 (Index/Deref/Field/Addr)。"""
    if isinstance(e, Var):
        return e.name
    if isinstance(e, Index):
        return _base_var(e.base)
    if isinstance(e, Deref):
        return _base_var(e.operand)
    if isinstance(e, Field):
        return _base_var(e.base)
    if isinstance(e, Binary):
        if isinstance(e.left, Var):
            return e.left.name
        return None
    return None
