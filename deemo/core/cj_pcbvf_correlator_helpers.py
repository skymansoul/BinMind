"""
PC-BVF相关性判定辅助函数 — taint约束判定与参数约束判定.

从cj_pcbvf_correlator.py拆分, 提供两种约束感知判定:
  1. tainted变量被路径约束限制时的安全/溢出判定
  2. 非tainted参数变量被路径约束限制时的安全/溢出判定
"""
from typing import Dict

from core.cj_bvf_types import SymbolicExpr, CorrelationResult
from core.cj_pcbvf_constraints import VarBound


def check_taint_constrained(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    bounds: Dict[str, VarBound],
    result: CorrelationResult,
) -> bool:
    """tainted变量被路径约束限制时的判定.

    1. tainted变量有上界N: max_write = N*coef + write_const + offset, 比较
    2. tainted变量有下界N但无上界: min_write = N*coef + ..., 若min_write > alloc → OVERFLOW
    """
    if not write.tainted or not alloc.is_constant():
        return False

    tainted_vars = [v for v in write.coefs if write.coefs[v] != 0]
    if not tainted_vars:
        return False

    max_write = write.const + offset_val
    all_bounded_hi = True
    for v in tainted_vars:
        b = bounds.get(v)
        if b is None or b.hi is None:
            all_bounded_hi = False
            break
        max_write += write.coefs[v] * b.hi

    if all_bounded_hi:
        if max_write <= alloc.const + 1e-9:
            result.proven_safe = True
            result.reason = (
                f"PC-BVF SAFE: tainted write bounded by path constraint; "
                f"max_write={max_write} <= alloc={alloc.const}")
            return True
        if max_write > alloc.const + 1e-9:
            result.proven_overflow = True
            result.reason = (
                f"PC-BVF OVERFLOW: tainted write exceeds alloc under constraint; "
                f"max_write={max_write} > alloc={alloc.const}")
            return True

    min_write = write.const + offset_val
    any_lo = False
    for v in tainted_vars:
        b = bounds.get(v)
        if b and b.lo is not None and write.coefs[v] > 0:
            min_write += write.coefs[v] * b.lo
            any_lo = True

    if any_lo and min_write > alloc.const + 1e-9:
        # alloc_expr为0常量说明跨函数分析缺失, 保守不判溢出
        if alloc.is_constant() and abs(alloc.const) < 1e-9:
            return False
        result.proven_overflow = True
        result.reason = (
            f"PC-BVF OVERFLOW: tainted write min({min_write}) "
            f"> alloc({alloc.const}) under lower-bound constraint")
        return True

    return False


def check_param_constrained(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    bounds: Dict[str, VarBound],
    result: CorrelationResult,
) -> bool:
    """非tainted参数变量被路径约束限制时的判定.

    场景: fixed alloc + param write var + path constraint:
      1. write var有上界N: max_write = N*coef + write_const + offset
         - max_write <= alloc → SAFE
         - max_write > alloc → OVERFLOW
      2. write var有下界N但无上界: min_write = N*coef + ...
         - min_write > alloc → OVERFLOW(约束反而证明溢出)
         - min_write <= alloc → 无法确定(保守返回INCONCLUSIVE)
      3. write var无任何约束(但有bounds且alloc为常量):
         说明write var是外部可控参数且路径约束未限制其上界 → OVERFLOW
    """
    if not alloc.is_constant():
        return False

    write_vars = [v for v in write.coefs if write.coefs[v] > 0]
    if not write_vars:
        return False

    unconstrained_vars = [v for v in write_vars if v not in bounds]

    if unconstrained_vars:
        # 当alloc_expr是常量0(跨函数分析缺失导致未知, 非真正分配0字节),
        # 不应将"write有参数无约束"判为OVERFLOW — 保守返回INCONCLUSIVE
        if alloc.is_constant() and abs(alloc.const) < 1e-9:
            return False
        result.proven_overflow = True
        result.reason = (
            f"PC-BVF OVERFLOW: fixed alloc({alloc.const}) with "
            f"unconstrained write var {unconstrained_vars} "
            f"(parameter, unbounded)")
        return True

    max_write = write.const + offset_val
    all_hi = True
    for v in write_vars:
        b = bounds[v]
        if b.hi is not None:
            max_write += write.coefs[v] * b.hi
        else:
            all_hi = False

    if all_hi:
        if max_write <= alloc.const + 1e-9:
            result.proven_safe = True
            result.reason = (
                f"PC-BVF SAFE: param write bounded by path constraint; "
                f"max_write={max_write} <= alloc={alloc.const}")
            return True
        if max_write > alloc.const + 1e-9:
            result.proven_overflow = True
            result.reason = (
                f"PC-BVF OVERFLOW: param write max({max_write}) "
                f"> alloc({alloc.const}) under upper-bound constraint")
            return True

    min_write = write.const + offset_val
    any_lo = False
    for v in write_vars:
        b = bounds[v]
        if b.lo is not None and write.coefs[v] > 0:
            min_write += write.coefs[v] * b.lo
            any_lo = True

    if any_lo and min_write > alloc.const + 1e-9:
        # alloc_expr为0常量说明跨函数分析缺失, 保守不判溢出
        if alloc.is_constant() and abs(alloc.const) < 1e-9:
            return False
        result.proven_overflow = True
        result.reason = (
            f"PC-BVF OVERFLOW: param write min({min_write}) "
            f"> alloc({alloc.const}) under lower-bound constraint")
        return True

    # write var有约束但无上界 → 参数仅有下界限制, 可无限增长
    # 但当alloc为0(跨函数分析缺失), 不应判溢出
    unbounded_hi_vars = [
        v for v in write_vars
        if bounds[v].hi is None
    ]
    if unbounded_hi_vars:
        if alloc.is_constant() and abs(alloc.const) < 1e-9:
            return False
        result.proven_overflow = True
        result.reason = (
            f"PC-BVF OVERFLOW: param write var {unbounded_hi_vars} "
            f"has no upper-bound in path constraints "
            f"(unbounded, alloc={alloc.const})")
        return True

    return False


__all__ = ['check_taint_constrained', 'check_param_constrained']
