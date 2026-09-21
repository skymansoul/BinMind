"""
路径条件后向值流 约束感知相关性判定器 — 利用路径约束收紧变量值域后重新判定: 从告警点提取路径约束 (VarBound) 注入 alloc/write 表达式, 对受约束变量求值或收紧范围后重新判定安全性/溢出。
判定规则: 子集安全 + 路径约束收紧 → SAFE; 约束证明溢出不可达 → SAFE; 约束证明溢出必然 → OVERFLOW; 非 tainted 参数变量无约束 → OVERFLOW; 非约束变量沿用 后向值流 原逻辑。
关键技术: 系数差分析 — alloc_coef[v]==write_coef[v] 但 write_const>alloc_const 时, 用 v 的上界 N 与 alloc 非共享变量 w 的下界计算 max(write_end) 与 min(alloc) 并比较。
"""
from typing import Dict, Optional, Set

from core.constraint_value_flow_types import SymbolicExpr, CorrelationResult
from core.constraint_pc_value_flow_constraints import VarBound
from core.constraint_pc_value_flow_correlator_helpers import (
    check_taint_constrained, check_param_constrained)


def correlate_with_constraints(
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    bounds: Dict[str, VarBound],
) -> CorrelationResult:
    """利用路径约束收紧后判定alloc-write相关性."""
    result = CorrelationResult(
        alloc_expr=alloc_expr, write_expr=write_expr)

    offset_val = offset_expr.eval_const() if offset_expr else 0.0
    if offset_val is None:
        result.reason = "PC-BVF: offset not constant, cannot refine"
        return result

    if not bounds:
        result.reason = "PC-BVF: no path constraints to refine"
        return result

    shared = alloc_expr.vars() & write_expr.vars()
    result.shared_vars = list(shared)

    if _check_constrained_safe(
            alloc_expr, write_expr, offset_val, shared, bounds, result):
        return result

    if _check_constrained_overflow(
            alloc_expr, write_expr, offset_val, shared, bounds, result):
        return result

    if check_taint_constrained(
            alloc_expr, write_expr, offset_val, bounds, result):
        return result

    if check_param_constrained(
            alloc_expr, write_expr, offset_val, bounds, result):
        return result

    result.reason = (
        f"PC-BVF: constraints insufficient after refinement; "
        f"bounds={ {k: str(v) for k, v in bounds.items()} }")
    return result


def _check_constrained_safe(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    shared: Set[str],
    bounds: Dict[str, VarBound],
    result: CorrelationResult,
) -> bool:
    """路径约束收紧后证明写安全.

    核心洞察: 当alloc和write共享变量v且系数相等时,
    write_end = alloc_size + write_const + offset(当write_coef==alloc_coef时).
    此时仅需判定 write_const + offset <= 0 → SAFE.

    当alloc_coef > write_coef时, alloc增长更快:
    write_end - alloc = (wc-ac)*v + write_const + offset
    v取上界时差最大: (wc-ac)*v.hi + write_const + offset <= 0 → SAFE.
    """
    if not shared:
        return False

    for v in shared:
        ac = alloc.coefs.get(v, 0)
        wc = write.coefs.get(v, 0)
        if ac < wc:
            return False

    max_diff = write.const + offset_val - alloc.const

    for v in shared:
        ac = alloc.coefs.get(v, 0)
        wc = write.coefs.get(v, 0)
        gap = wc - ac
        if gap < 0:
            b = bounds.get(v)
            if b is None or b.hi is None:
                return False
            max_diff += gap * b.hi

    non_shared_write_vars = [
        v for v in write.coefs
        if v not in shared and v != '' and write.coefs[v] > 0
    ]
    for v in non_shared_write_vars:
        b = bounds.get(v)
        if b is None or b.hi is None:
            return False
        max_diff += write.coefs[v] * b.hi

    non_shared_alloc_vars = [
        v for v in alloc.coefs
        if v not in shared and v != '' and alloc.coefs[v] > 0
    ]
    for v in non_shared_alloc_vars:
        b = bounds.get(v)
        if b and b.lo is not None:
            max_diff -= alloc.coefs[v] * b.lo

    if max_diff <= 1e-9:
        result.proven_safe = True
        shared_str = ", ".join(
            f"{v}∈[{bounds[v].lo},{bounds[v].hi}]"
            for v in shared if v in bounds)
        result.reason = (
            f"PC-BVF SAFE: max_write_end - min_alloc = {max_diff} <= 0; "
            f"constraints: {shared_str}")
        result.certificate = _build_safe_cert(
            alloc, write, offset_val, shared, bounds,
            max_diff, 0.0)
        return True

    return False


def _check_constrained_overflow(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    shared: Set[str],
    bounds: Dict[str, VarBound],
    result: CorrelationResult,
) -> bool:
    """路径约束收紧后证明溢出.

    条件: 存在共享变量v, write_coef[v]>=alloc_coef[v] 且
    路径约束给出v的下界, 使得 min(write_end) > max(alloc).
    或: 所有系数相等但min(write_end - alloc) > 0.
    """
    min_write = write.const + offset_val
    max_alloc = alloc.const

    for v in shared:
        wc = write.coefs.get(v, 0)
        ac = alloc.coefs.get(v, 0)
        b = bounds.get(v)
        if b and b.lo is not None and wc > 0:
            min_write += wc * b.lo
        if b and b.hi is not None and ac > 0:
            max_alloc += ac * b.hi

    if min_write > max_alloc + 1e-9:
        result.proven_overflow = True
        result.reason = (
            f"PC-BVF OVERFLOW: constrained min_write({min_write}) "
            f"> max_alloc({max_alloc}); "
            f"bounds={ {v: str(bounds[v]) for v in shared} }")
        return True

    return False


def _build_safe_cert(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    shared: Set[str],
    bounds: Dict[str, VarBound],
    max_write: float,
    min_alloc: float,
) -> str:
    """构建路径条件后向值流安全证书."""
    bound_str = "; ".join(
        f"{v}∈[{bounds[v].lo},{bounds[v].hi}]"
        for v in shared if v in bounds)
    return (
        f"PC-BVF Certificate [SAFE]\n"
        f"  alloc_expr  = {alloc}\n"
        f"  write_expr  = {write}\n"
        f"  offset      = {offset_val}\n"
        f"  path_bounds = {bound_str}\n"
        f"  max_write_end = {max_write}\n"
        f"  min_alloc     = {min_alloc}\n"
        f"  proof       = max(write) <= min(alloc) under constraints"
    )


__all__ = ['correlate_with_constraints']
