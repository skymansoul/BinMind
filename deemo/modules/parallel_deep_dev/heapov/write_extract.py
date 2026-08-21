"""写点提取 — 命中堆缓冲区的写操作与字节范围表达式。

memcpy 类调用取长度参数; 数组写 `buf[i]=x` 换算为
偏移=idx*es, 范围=(idx+1)*es; 别名偏移并入范围,
保证耦合验证在统一字节域上比较。
"""

# TODO: strcpy/strcat 动态源需 strlen 建模, 现仅字面量与守卫可证安全


from typing import List

from .expr_ast import (
    Expr, Var, Const, Binary, Call, Index, Field, Deref,
)
from . import cparser as cp
from .dataflow import DataflowEnv, iter_statements
from .model import WriteSite

_CALLS_LEN_ARG = {
    'memcpy': 2, 'memmove': 2, 'memset': 1, 'strncpy': 2,
    'read': 2, 'recv': 2, 'recvfrom': 2, 'fread': None,
}
_DYNAMIC_CALLS = frozenset(['strcpy', 'strcat', 'sprintf', 'gets',
                            'readlink'])


def _ptr_parts(env: DataflowEnv, e: Expr, acc_const: int, acc_dyn):
    """递归展开指针表达式 → (基变量, 常量偏移, 动态偏移表达式)。

    支持 buf+k, buf+x, buf+k+x, &buf[k], &buf[i], *p 等形态。
    动态偏移累加为单一表达式; 基变量不可解析时返回 ('', 0, None)。
    """
    if isinstance(e, Var):
        base, off = env.resolve(e.name)
        return base, off + acc_const, acc_dyn
    if isinstance(e, Const):
        return '', acc_const + e.value, acc_dyn
    if isinstance(e, Binary) and e.op == '+':
        if isinstance(e.left, Const):
            return _ptr_parts(env, e.right, acc_const + e.left.value, acc_dyn)
        if isinstance(e.right, Const):
            return _ptr_parts(env, e.left, acc_const + e.right.value, acc_dyn)
        # buf + x: 左侧解析基变量, 右侧为动态偏移
        base, off, dyn = _ptr_parts(env, e.left, acc_const, acc_dyn)
        new_dyn = _add_dyn(dyn, e.right)
        return base, off, new_dyn
    if isinstance(e, Index) and isinstance(e.base, Var):
        base, off = env.resolve(e.base.name)
        es = env.elem_size.get(e.base.name, 1)
        if isinstance(e.index, Const):
            return base, off + e.index.value * es + acc_const, acc_dyn
        dyn = _add_dyn(acc_dyn, Binary('*', e.index, Const(es)))
        return base, off + acc_const, dyn
    if isinstance(e, Deref) and isinstance(e.operand, Var):
        base, off = env.resolve(e.operand.name)
        return base, off + acc_const, acc_dyn
    return '', 0, None


def _add_dyn(a, b):
    if a is None:
        return b
    if b is None:
        return a
    return Binary('+', a, b)


def _resolve(env: DataflowEnv, dst: Expr):
    """解析写目标到 (分配变量, 常量偏移, 动态偏移, 字段名)。"""
    if isinstance(dst, Field) and isinstance(dst.base, Var):
        base, _ = env.resolve(dst.base.name)
        return base, 0, None, dst.name
    if isinstance(dst, Field):
        base, off, dyn, _ = _resolve(env, dst.base)
        return base, off, dyn, dst.name
    base, off, dyn = _ptr_parts(env, dst, 0, None)
    return base, off, dyn, ''


def _extent(off: int, dyn, base: Expr) -> Expr:
    """常量偏移+动态偏移+长度 → 统一范围表达式。"""
    total = base
    if dyn is not None:
        total = Binary('+', dyn, total)
    if off > 0:
        total = Binary('+', Const(off), total)
    return total


def _extract_assign(a: cp.Assign, env, out, func) -> None:
    tgt = a.target
    if isinstance(tgt, Index):
        if isinstance(tgt.base, Var) and isinstance(tgt.index, (Var, Binary, Const)):
            # 数组写: 偏移=别名偏移 + idx*es, 范围=别名偏移+(idx+1)*es
            base, alias_off = env.resolve(tgt.base.name)
            if not base:
                return
            es = env.elem_size.get(tgt.base.name, 1)
            idx = tgt.index
            extent = Binary('*', Binary('+', idx, Const(1)), Const(es))
            if alias_off > 0:
                extent = Binary('+', Const(alias_off), extent)
            out.append(WriteSite(
                dst_var=tgt.base.name, kind='array_write',
                extent_expr=extent, index_expr=idx, elem_size=es,
                alias_base=base, alias_offset=alias_off,
                func=func, pos=a.pos,
                desc=f'{tgt.base.name}[{_sexpr(idx)}] = ...', stmt=a))
    elif isinstance(tgt, Field):
        base, off, dyn, fname = _resolve(env, tgt)
        if not base:
            return
        out.append(WriteSite(
            dst_var=tgt.base.name if isinstance(tgt.base, Var) else '',
            kind='field_write', extent_expr=None, index_expr=None,
            alias_base=base, alias_offset=off, field_name=fname,
            func=func, pos=a.pos,
            desc=f'{tgt.base.name if isinstance(tgt.base, Var) else "?"}->{fname} = ...',
            stmt=a))
    elif isinstance(tgt, Deref) and isinstance(tgt.operand, Var):
        base, off, dyn, _ = _resolve(env, tgt)
        if not base:
            return
        es = env.elem_size.get(tgt.operand.name, 1)
        extent = _extent(off, dyn, Const(es)) if (off >= 0 or dyn is not None) else None
        out.append(WriteSite(
            dst_var=tgt.operand.name, kind='ptr_write',
            extent_expr=extent, index_expr=None, alias_base=base,
            alias_offset=off, elem_size=es, func=func, pos=a.pos,
            desc=f'*{tgt.operand.name} = ...', stmt=a))


def _extract_call(call, env, out, func, stmt) -> None:
    if not isinstance(call, Call):
        return
    name = call.name
    if name not in _CALLS_LEN_ARG and name not in _DYNAMIC_CALLS:
        return
    if not call.args:
        return
    dst, off, dyn, field = _resolve(env, call.args[0])
    if not dst:
        return
    if name == 'fread' and len(call.args) >= 3:
        extent = Binary('*', call.args[1], call.args[2])
        extent = _extent(off, dyn, extent)
    elif name in _DYNAMIC_CALLS:
        extent = None
    else:
        arg_idx = _CALLS_LEN_ARG[name]
        if arg_idx is None or len(call.args) <= arg_idx:
            return
        extent = _extent(off, dyn, call.args[arg_idx])
    out.append(WriteSite(
        dst_var=call.args[0] if isinstance(call.args[0], Var)
        else '', kind=name, extent_expr=extent,
        index_expr=None, alias_base=dst, alias_offset=off,
        field_name=field,
        src_expr=call.args[1] if len(call.args) >= 2 else None,
        func=func, pos=stmt.pos if hasattr(stmt, 'pos') else 0,
        desc=f'{name}({_sexpr(call.args[0])}, ...)', stmt=stmt))


def extract_writes(func: cp.Func, env: DataflowEnv) -> List[WriteSite]:
    out: List[WriteSite] = []
    for it in iter_statements(func):
        if isinstance(it, cp.Assign):
            _extract_assign(it, env, out, func.name)
        elif isinstance(it, (cp.CallStmt, cp.ExprStmt)):
            call = it.call if isinstance(it, cp.CallStmt) else it.expr
            _extract_call(call, env, out, func.name, it)
    return out


def _sexpr(e: Expr) -> str:
    from .expr_ast import expr_str
    return expr_str(e)
