"""对象流跟踪 — 顺序遍历语句, 维护 变量→对象键 映射与对象生死状态。

分配产生新对象(整数 oid); free 标记对象死亡; 重绑定使变量指向
新对象或空; 字段指针 p->f = malloc 创建子对象键 "oid:f"。
事件携带分支路径, 供分支互斥判定。

对象键语义:
  ptr_key(e)     表达式作为指针值时的对象键 (free 目标)
  deref_keys(e)  对 e 解引用所涉及的全部对象键: 根对象 + 已存在的
                 嵌套字段对象 (free(v) 与 free(v->buf) 两类违约都覆盖)
"""

# TODO: 跨函数 free/use 需过程间摘要, 当前仅函数内配对

from __future__ import annotations

from typing import Dict, List, Optional, Tuple

from heapov.expr_ast import (
    Expr, Var, Const, Binary, Call, Index, Field, Deref, Addr,
)
from heapov.stmts import (
    Assign, CallStmt, ExprStmt, If, For, While, Decl, Func,
)
from heapov.dataflow import _stmt_list

from uafov.model import AllocSite, FreeEvent, UseEvent, RebindEvent

ALLOC_FUNCS = frozenset(['malloc', 'calloc', 'realloc'])
NULL_REFS = frozenset(['NULL', 'nullptr'])


class ObjectFlow:
    """对象身份与生死状态。"""

    def __init__(self) -> None:
        self.var_obj: Dict[str, Optional[str]] = {}
        self.obj_state: Dict[str, str] = {}
        self.next_oid = 1

    def alloc(self, var: str) -> str:
        oid = str(self.next_oid)
        self.next_oid += 1
        self.var_obj[var] = oid
        self.obj_state[oid] = 'alive'
        return oid

    def alloc_field(self, base_key: str, field: str) -> str:
        nk = f'{base_key}:{field}'
        self.obj_state[nk] = 'alive'
        return nk

    def free(self, obj_key: str) -> bool:
        """标记对象死亡。返回是否构成 double-free。"""
        if obj_key in self.obj_state:
            was = self.obj_state[obj_key]
            self.obj_state[obj_key] = 'freed'
            return was == 'freed'
        return False

    def rebind(self, var: str, obj_key: Optional[str]) -> None:
        self.var_obj[var] = obj_key

    def key_of_var(self, var: str) -> Optional[str]:
        return self.var_obj.get(var)


def ptr_key(expr: Expr, flow: ObjectFlow) -> Optional[str]:
    """表达式作为指针值时的对象键。非指针表达式返回 None。"""
    if isinstance(expr, Var):
        return flow.key_of_var(expr.name)
    if isinstance(expr, Field):
        base = ptr_key(expr.base, flow)
        if base is None:
            return None
        return f'{base}:{expr.name}'
    if isinstance(expr, Deref):
        return ptr_key(expr.operand, flow)
    if isinstance(expr, Index):
        return ptr_key(expr.base, flow)
    if isinstance(expr, Binary) and expr.op == '+':
        if isinstance(expr.left, Var):
            return flow.key_of_var(expr.left.name)
        if isinstance(expr.right, Var):
            return flow.key_of_var(expr.right.name)
    return None


def deref_keys(expr: Expr, flow: ObjectFlow) -> List[str]:
    """对 expr 解引用所涉及的对象键列表。

    根对象键始终计入; 字段链上已分配的子对象键(存在 obj_state)也计入。
    """
    node = expr
    chain: List[str] = []
    while isinstance(node, (Field, Deref, Index)):
        if isinstance(node, Field):
            chain.append(node.name)
        node = node.base if isinstance(node, (Field, Index)) else node.operand
    if not isinstance(node, Var):
        return []
    root = flow.key_of_var(node.name)
    if root is None:
        return []
    keys = [root]
    cur = root
    for fname in reversed(chain):
        cur = f'{cur}:{fname}'
        if cur in flow.obj_state:
            keys.append(cur)
    return keys


def _is_alloc_call(e: Expr):
    if isinstance(e, Call) and e.name in ALLOC_FUNCS:
        return e
    return None


class EventExtractor:
    def __init__(self, func: Func):
        self.func = func
        self.flow = ObjectFlow()
        self.allocs: List[AllocSite] = []
        self.frees: List[FreeEvent] = []
        self.uses: List[UseEvent] = []
        self.rebinds: List[RebindEvent] = []
        self.seq = 0
        self._path: Tuple[Tuple[int, str], ...] = ()

    def run(self) -> None:
        self._walk(_stmt_list(self.func.body), ())

    def _walk(self, stmts, path) -> None:
        self._path = path
        for s in stmts:
            self.seq += 1
            items = s if isinstance(s, list) else [s]
            for it in items:
                if isinstance(it, Decl):
                    if it.init is not None:
                        self._on_assign(it.name, it.init, self.seq)
                elif isinstance(it, Assign):
                    self._on_assign_stmt(it, self.seq)
                elif isinstance(it, CallStmt):
                    self._on_call(it.call, self.seq)
                elif isinstance(it, ExprStmt):
                    self._collect_uses(it.expr, self.seq, 'expr')
                elif isinstance(it, If):
                    self._walk(_stmt_list(it.then_b),
                               path + ((id(it), 'then'),))
                    if it.else_b is not None:
                        self._walk(_stmt_list(it.else_b),
                                   path + ((id(it), 'else'),))
                elif isinstance(it, (For, While)):
                    self._walk(_stmt_list(it.body), path)

    # 赋值处理
    def _on_assign_stmt(self, a: Assign, pos: int) -> None:
        tgt = a.target
        if isinstance(tgt, Var):
            self._on_assign(tgt.name, a.value, pos)
            return
        for key in deref_keys(tgt, self.flow):
            self.uses.append(UseEvent(
                base_var=_var_name(tgt), obj_key=key,
                pos=pos, path=self._path, kind='write'))
        if isinstance(tgt, Field) and _is_alloc_call(a.value):
            base = ptr_key(tgt.base, self.flow)
            if base is not None:
                self.flow.alloc_field(base, tgt.name)
        self._collect_uses(a.value, pos, 'expr')

    def _on_assign(self, var: str, value: Expr, pos: int) -> None:
        call = _is_alloc_call(value)
        if call:
            oid = self.flow.alloc(var)
            self.rebinds.append(RebindEvent(var, oid, pos, 'alloc'))
            self.allocs.append(AllocSite(var, pos, int(oid)))
            return
        if isinstance(value, Var):
            key = self.flow.key_of_var(value.name)
            self.flow.rebind(var, key)
            self.rebinds.append(RebindEvent(
                var, key, pos, 'null' if key is None else 'alias'))
            return
        if isinstance(value, Const) and value.value == 0:
            self.flow.rebind(var, None)
            self.rebinds.append(RebindEvent(var, None, pos, 'null'))
            return
        if isinstance(value, Var) and value.name in NULL_REFS:
            self.flow.rebind(var, None)
            self.rebinds.append(RebindEvent(var, None, pos, 'null'))
            return
        self.flow.rebind(var, None)
        self.rebinds.append(RebindEvent(var, None, pos, 'other'))
        self._collect_uses(value, pos, 'expr')

    # 调用处理
    def _on_call(self, call: Call, pos: int) -> None:
        if call.name == 'free' and call.args:
            arg = call.args[0]
            key = ptr_key(arg, self.flow)
            if key is not None:
                df = self.flow.free(key)
                self.frees.append(FreeEvent(
                    base_var=_var_name(arg), obj_key=key,
                    pos=pos, path=self._path, double_free=df))
            return
        for arg in call.args:
            if isinstance(arg, Var):
                key = self.flow.key_of_var(arg.name)
                if key is not None:
                    self.uses.append(UseEvent(
                        base_var=arg.name, obj_key=key,
                        pos=pos, path=self._path, kind='callarg'))
            self._collect_uses(arg, pos, 'callarg')

    def _collect_uses(self, e: Expr, pos: int, kind: str) -> None:
        if e is None:
            return
        if isinstance(e, (Deref, Index, Field)):
            for key in deref_keys(e, self.flow):
                self.uses.append(UseEvent(
                    base_var=_var_name(e), obj_key=key,
                    pos=pos, path=self._path, kind=kind))
            if isinstance(e, Field):
                self._collect_uses(e.base, pos, kind)
            elif isinstance(e, Index):
                self._collect_uses(e.base, pos, kind)
                self._collect_uses(e.index, pos, kind)
            else:
                self._collect_uses(e.operand, pos, kind)
            return
        if isinstance(e, Binary):
            self._collect_uses(e.left, pos, kind)
            self._collect_uses(e.right, pos, kind)
            return
        if isinstance(e, Call):
            for arg in e.args:
                self._collect_uses(arg, pos, kind)
            return
        if isinstance(e, Addr):
            return


def _var_name(e: Expr) -> str:
    """取表达式根变量名, 用于报告。"""
    if isinstance(e, Var):
        return e.name
    if isinstance(e, (Index, Field)):
        return _var_name(e.base)
    if isinstance(e, Deref):
        return _var_name(e.operand)
    if isinstance(e, Binary):
        if isinstance(e.left, Var):
            return e.left.name
        return _var_name(e.left)
    return ''


def extract_events(func: Func):
    """提取函数内全部 UAF 相关事件。返回 EventExtractor。"""
    ex = EventExtractor(func)
    ex.run()
    return ex
