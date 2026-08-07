"""容量-写范围耦合验证 — CACBV 核心判定。

两层比较:
  1. 区间层: 写范围与对齐后容量直接比较(处理常量偏移与对齐冗余)。
  2. 仿射层: 将 extent 与 size 线性化, 在同一变量值上求差值,
     消除"独立区间"带来的假阳性 — 耦合变量不再被错误放大。
守卫先精化环境, 使 if(len>size)return 后的写范围被约束为 <=size。
"""

# TODO: 跨函数分配/写入需过程间摘要, 当前仅在函数内配对分配变量


from typing import Dict, List, Tuple

from heapov.expr_ast import (
    Expr, Var, Const, Binary, Call, Sizeof, linearize, substitute,
    substitute_sizeof,
)
from heapov.interval import Interval, eval_expr, align_up, le_provable, gt_provable
from heapov import cparser as cp
from heapov.model import AllocSite, WriteSite, GuardConstraint
from heapov import verdict as V

_GLIBC_ALIGN = 16


def refine_env(env, guards: List[GuardConstraint]) -> Dict[str, Interval]:
    """守卫精化环境: v < b → v.hi = b.hi-1 等。"""
    ivars: Dict[str, Interval] = dict(env.intervals)
    for g in guards:
        if not isinstance(g.lhs, Var):
            continue
        v = g.lhs.name
        b_iv = eval_expr(g.rhs, ivars, env.tainted)
        cur = ivars.get(v, Interval.top())
        if g.op == '<':
            hi = (b_iv.hi - 1) if b_iv.hi is not None else cur.hi
            lo = cur.lo
            if b_iv.hi is not None and b_iv.hi <= 0:
                lo = 0  # 下界未知时索引至少非负
            ivars[v] = Interval(lo, hi)
        elif g.op == '<=':
            ivars[v] = Interval(cur.lo, b_iv.hi if b_iv.hi is not None else cur.hi)
        elif g.op == '>':
            lo = (b_iv.lo + 1) if b_iv.lo is not None else cur.lo
            ivars[v] = Interval(lo, cur.hi)
        elif g.op == '>=':
            lo = b_iv.lo if b_iv.lo is not None else cur.lo
            ivars[v] = Interval(lo, cur.hi)
    return ivars


def _eval_linear(lin: Tuple[dict, int], env: Dict[str, Interval]) -> Interval:
    """仿射形式在各变量区间上求值。缺失变量→top。"""
    coefs, const = lin
    lo = const
    hi = const
    for v, c in coefs.items():
        iv = env.get(v)
        if iv is None or iv.lo is None or iv.hi is None:
            return Interval.top()
        if c >= 0:
            lo += c * iv.lo
            hi += c * iv.hi
        else:
            lo += c * iv.hi
            hi += c * iv.lo
    return Interval(lo, hi)


def _is_struct_alloc(alloc: AllocSite) -> bool:
    return (isinstance(alloc.size_expr, Sizeof)
            and alloc.size_expr.value == 0)


def verify_pair(
    alloc: AllocSite,
    write: WriteSite,
    env,
    guards: List[GuardConstraint],
    str_lits: dict,
    array_sizes: dict = None,
) -> Tuple[str, float, List[str], int]:
    """验证一个分配-写点对。返回 (verdict, conf, reasons, overflow_bytes)。"""
    reasons: List[str] = []
    ref_env = refine_env(env, guards)
    sizes = array_sizes or {}

    # sizeof(数组变量) 代换为常量尺寸
    alloc_expr = substitute_sizeof(alloc.size_expr, sizes)
    if write.extent_expr is not None:
        write.extent_expr = substitute_sizeof(write.extent_expr, sizes)

# 结构化安全信号
    # 堆结构体分配 + 字段写: sizeof(struct) 未求值时按布局安全
    if _is_struct_alloc(alloc) and write.kind == 'field_write':
        if write.alias_base == alloc.var:
            return V.SAFE, V.CONF_OVERFLOW * 0.3, ['struct-layout'], 0

    # strcpy/strcat 到字符串字面量: 长度已知则安全判定
    if write.kind in ('strcpy', 'strcat') and write.extent_expr is None:
        src = write.src_expr
        if src is not None and isinstance(src, Var) and src.name.startswith('__str__'):
            content = str_lits.get(src.name)
            if content is not None:
                lit_len = len(content) + 1
                write.extent_expr = Const(lit_len)
                reasons.append('string-literal-len')
        if write.extent_expr is None:
            return (V.LIKELY, V.CONF_LIKELY, ['dynamic-copy'], 0)

# 区间层
    size_iv = eval_expr(alloc_expr, ref_env, env.tainted)
    cap_lo = align_up(size_iv.lo, _GLIBC_ALIGN) if size_iv.lo is not None else None
    cap_hi = align_up(size_iv.hi, _GLIBC_ALIGN) if size_iv.hi is not None else None

    if write.extent_expr is None:
        # 无法表达范围(字段写等): 保守视为可疑
        return V.LIKELY, V.CONF_LIKELY, ['dynamic-extent'], 0

    ext_iv = eval_expr(write.extent_expr, ref_env, env.tainted)

    # 常量范围 vs 对齐容量: 对齐冗余的误报在此消除
    if cap_lo is not None and ext_iv.hi is not None and ext_iv.hi <= cap_lo:
        return V.SAFE, V.CONF_OVERFLOW * 0.3, ['aligned-capacity'], 0
    if cap_hi is not None and ext_iv.lo is not None and ext_iv.lo > cap_hi:
        ov = ext_iv.lo - cap_hi
        return V.OVERFLOW, V.CONF_OVERFLOW, ['interval'], ov

# 仿射层: 同一变量值上的差值比较
    lin_ext = linearize(write.extent_expr)
    lin_size = linearize(alloc_expr)
    if lin_ext != ({}, 0) or lin_size != ({}, 0):
        delta_iv = _delta_interval(lin_ext, lin_size, ref_env)
        if not delta_iv.is_top():
            if delta_iv.hi is not None and delta_iv.hi <= 0:
                return V.SAFE, V.CONF_OVERFLOW * 0.3, ['coupled-delta'], 0
            if delta_iv.lo is not None and delta_iv.lo > 0:
                return V.OVERFLOW, V.CONF_OVERFLOW, ['coupled-delta'], delta_iv.lo
        elif lin_ext == lin_size:
            return V.SAFE, V.CONF_OVERFLOW * 0.3, ['coupled-equal'], 0

    # 守卫上界代换: v < b 且 v 在 extent 中 → extent 取 b-1 最大 --
    for g in guards:
        if isinstance(g.lhs, Var) and g.op in ('<', '<='):
            v = g.lhs.name
            if v in write.extent_expr.vars():
                repl = (Binary('-', g.rhs, Const(1)) if g.op == '<'
                        else g.rhs)
                sub_ext = substitute(write.extent_expr, v, repl)
                lin_sub = linearize(sub_ext)
                d_sub = _delta_interval(lin_sub, lin_size, env.intervals)
                if not d_sub.is_top() and d_sub.hi is not None and d_sub.hi <= 0:
                    return V.SAFE, V.CONF_OVERFLOW * 0.3, ['guard-subst'], 0

# 残差判定
    relevant = (write.extent_expr.vars() if write.extent_expr else set()) \
        | alloc_expr.vars()
    guarded = any(isinstance(g.lhs, Var) and g.lhs.name in relevant
                  for g in guards)
    coupled = bool(alloc_expr.vars() & write.extent_expr.vars())
    verdict, conf = V.decide(
        le_provable(ext_iv, Interval(cap_lo, cap_hi)) if cap_lo else False,
        gt_provable(ext_iv, Interval(cap_lo, cap_hi)) if cap_hi else False,
        coupled, guarded)
    if not coupled:
        reasons.append('uncoupled-or-unguarded')
    elif guarded:
        reasons.append('coupled+guard-unproven')
    else:
        reasons.append('coupled-superset')
    ov = 0
    if verdict == V.OVERFLOW and ext_iv.lo is not None and cap_hi is not None:
        ov = ext_iv.lo - cap_hi
    elif verdict in (V.LIKELY, V.UNCERTAIN) and ext_iv.hi is not None and cap_lo is not None:
        ov = max(0, ext_iv.hi - cap_lo)
    return verdict, conf, reasons, ov


def _delta_interval(lin_ext, lin_size, env) -> Interval:
    """extent - size 的仿射差值区间(同变量值上求值)。"""
    coefs = dict(lin_ext[0])
    for v, c in lin_size[0].items():
        coefs[v] = coefs.get(v, 0) - c
    coefs = {v: c for v, c in coefs.items() if c != 0}
    delta_const = lin_ext[1] - lin_size[1]
    return _eval_linear((coefs, delta_const), env)
