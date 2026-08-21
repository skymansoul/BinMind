"""函数内数据流环境 — 区间、污点来源、指针别名。

单遍近似: 变量按语句顺序更新, 不做 CFG 不动点。
样本集中分配/写点通常是顺序出现的, 单遍足以支撑
耦合验证所需的数值与别名信息。
"""


from typing import Dict, List, Optional, Tuple

from .expr_ast import (
    Expr, Const, Var, Binary, Call, Index, Field, Deref, Addr,
    expr_str,
)
from .interval import Interval, eval_expr
from . import cparser as cp
from .model import AllocSite

# 视为外部输入的调用(返回值污点)
_TAINT_SOURCES = frozenset([
    'recv', 'recvfrom', 'read', 'fread', 'fgets', 'gets', 'scanf',
    'getenv', 'strlen', 'strtoul', 'strtol', 'atoi', 'atol', 'atoll',
    'memcpy', 'memmove', 'strcpy', 'sprintf', 'snprintf', 'vsnprintf',
])
# 安全计算(不引入污点)
_SAFE_CALLS = frozenset(['malloc', 'calloc', 'realloc', 'free',
                         'sizeof', 'min', 'max'])

_BASE_TYPE_SIZES = {
    'char': 1, 'int': 4, 'short': 2, 'long': 8, 'float': 4,
    'double': 8, 'size_t': 8, 'ssize_t': 8, 'void': 1,
}


class DataflowEnv:
    """每函数的顺序数据流状态。"""

    def __init__(self, params: List[str], func_name: str):
        self.func_name = func_name
        self.intervals: Dict[str, Interval] = {}
        self.tainted: set = set()
        self.alias: Dict[str, Tuple[str, int]] = {}
        self.elem_size: Dict[str, int] = {}
        # 参数默认 tainted — 攻击面不可知时保守视为外部可控
        for p in params:
            self.intervals[p] = Interval.top()
            self.tainted.add(p)
        if func_name == 'main':
            for p in ('argc', 'argv'):
                self.intervals[p] = Interval.top()
                self.tainted.add(p)

# 别名
    def resolve(self, var: str) -> Tuple[str, int]:
        """解析 var 到 (分配变量, 字节偏移)。未命中返回自身。"""
        seen = 0
        cur, off = var, 0
        while cur in self.alias and seen < 8:
            base, d = self.alias[cur]
            off += d
            cur = base
            seen += 1
        return cur, off

    def assign_alias(self, var: str, expr: Expr) -> None:
        """尝试从赋值推导别名关系 p = buf / p = buf + k / p = &buf[k]."""
        if isinstance(expr, Var):
            if expr.name in self.alias:
                self.alias[var] = self.alias[expr.name]
            elif expr.name != var:
                self.alias[var] = (expr.name, 0)
        elif isinstance(expr, Binary) and expr.op == '+' and isinstance(expr.right, Const):
            if isinstance(expr.left, Var):
                if expr.left.name in self.alias:
                    b, o = self.alias[expr.left.name]
                    self.alias[var] = (b, o + expr.right.value)
                else:
                    self.alias[var] = (expr.left.name, expr.right.value)
        elif isinstance(expr, Binary) and expr.op == '+' and isinstance(expr.left, Const):
            if isinstance(expr.right, Var):
                self.alias[var] = (expr.right.name, expr.left.value)
        elif isinstance(expr, Addr) and isinstance(expr.operand, Index):
            idx = expr.operand.index
            if isinstance(idx, Const):
                base = expr.operand.base
                bname = base.name if isinstance(base, Var) else ''
                if bname:
                    es = self.elem_size.get(bname, 1)
                    if bname in self.alias:
                        bb, bo = self.alias[bname]
                        self.alias[var] = (bb, bo + idx.value * es)
                    else:
                        self.alias[var] = (bname, idx.value * es)

    def assign(self, target: Expr, value: Expr) -> None:
        if isinstance(target, Var):
            self._assign_var(target.name, value)
        elif isinstance(target, Deref) and isinstance(target.operand, Var):
# p = x: 通过别名对底层变量写入
            self._assign_var(target.operand.name, value)

    def _assign_var(self, name: str, value: Expr) -> None:
        self.intervals[name] = eval_expr(value, self.intervals, self.tainted)
        self._update_taint(name, value)
        self.assign_alias(name, value)

    def _update_taint(self, name: str, value: Expr) -> None:
        vars_used = value.vars()
        if any(v in self.tainted for v in vars_used):
            self.tainted.add(name)
            return
        if isinstance(value, Call) and value.name in _TAINT_SOURCES:
            self.tainted.add(name)
            return
        if isinstance(value, Binary) and value.op == '+':
            if isinstance(value.left, Var) and value.left.name in self.tainted:
                self.tainted.add(name)
            if isinstance(value.right, Var) and value.right.name in self.tainted:
                self.tainted.add(name)

    def declare_var_types(self, func) -> None:
        """预收集全部声明的元素尺寸, 供数组写换算。

        指针变量的元素尺寸取指向类型的尺寸(char*→1, int*→4),
        而非指针自身的 8 字节 — 数组写 buf[i] 按元素大小推进。
        """
        for stmt in _flatten_stmts(func.body):
            if isinstance(stmt, cp.Decl):
                base = stmt.base_type.strip().split(' ')[-1]
                size = _BASE_TYPE_SIZES.get(base, 0)
                if size <= 0:
                    size = 1
                self.elem_size.setdefault(stmt.name, size)

    def declare(self, decl: cp.Decl) -> None:
        """登记声明: 元素尺寸 + 初始化。"""
        base = decl.base_type.strip().split(' ')[-1]
        size = _BASE_TYPE_SIZES.get(base, 0)
        if decl.is_pointer:
            size = 8
        self.elem_size.setdefault(decl.name, size if size > 0 else 1)
        if decl.init is not None:
            self.assign(Var(decl.name), decl.init)

    def taint_of(self, expr: Expr) -> bool:
        """表达式是否依赖污点变量。"""
        return any(v in self.tainted for v in expr.vars())

    def expr_interval(self, expr: Expr) -> Interval:
        return eval_expr(expr, self.intervals, self.tainted)


def build_env(func) -> DataflowEnv:
    """顺序构建函数环境: 声明/赋值/循环变量的区间与别名。"""
    env = DataflowEnv(func.params, func.name)
    env.declare_var_types(func)
    for stmt in _flatten_stmts(func.body):
        _apply_env_stmt(env, stmt)
    return env


def _stmt_list(stmt) -> list:
    """把语句归一化为语句列表(Block 展开, 单语句包装)。"""
    if isinstance(stmt, cp.Block):
        return stmt.stmts
    if stmt is None:
        return []
    return [stmt]


def _flatten_stmts(block) -> list:
    out = []
    for s in block.stmts:
        items = s if isinstance(s, list) else [s]
        for it in items:
            out.append(it)
            if isinstance(it, cp.Block):
                out.extend(_flatten_stmts(it))
            elif isinstance(it, cp.If):
                out.extend(_flatten_stmts_any(it.then_b))
                out.extend(_flatten_stmts_any(it.else_b))
            elif isinstance(it, cp.For):
                out.extend(_flatten_stmts_any(it.body))
            elif isinstance(it, cp.While):
                out.extend(_flatten_stmts_any(it.body))
    return out


def _flatten_stmts_any(stmt) -> list:
    """递归展开任意语句(Block 或单语句)。"""
    if isinstance(stmt, cp.Block):
        return _flatten_stmts(stmt)
    if stmt is None:
        return []
    return [stmt]


def iter_statements(func) -> list:
    """程序顺序展开的全部语句(含 if/循环体)。"""
    return _flatten_stmts(func.body)


def _apply_env_stmt(env, stmt) -> None:
    if isinstance(stmt, cp.Decl):
        env.declare(stmt)
    elif isinstance(stmt, cp.Assign):
        env.assign(stmt.target, stmt.value)
    elif isinstance(stmt, cp.For):
        _apply_loop_bound(env, stmt)


def _apply_loop_bound(env, f: cp.For) -> None:
    """for(i=0;i<n;i++) 体循环变量区间 [0, n-1]。"""
    if f.cond is None or not isinstance(f.cond, Binary):
        return
    op, lhs, rhs = f.cond.op, f.cond.left, f.cond.right
    if not isinstance(lhs, Var) or op not in ('<', '<='):
        return
    b_iv = env.expr_interval(rhs)
    if op == '<':
        hi = (b_iv.hi - 1) if b_iv.hi is not None else None
    else:
        hi = b_iv.hi
    cur = env.intervals.get(lhs.name, Interval.top())
    lo = cur.lo if cur.lo is not None else 0
    env.intervals[lhs.name] = Interval(lo, hi)
