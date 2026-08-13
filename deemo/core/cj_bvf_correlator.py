"""
DD-BVF相关性判定器 — alloc-write符号相关性安全证明.

提供correlate判定逻辑:
常量比较、共享变量子集安全性检查、溢出检查、证书构建.
"""

from typing import Optional, Set

from core.cj_bvf_types import SymbolicExpr, CorrelationResult


def correlate(
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: SymbolicExpr = None,
) -> CorrelationResult:
    """判定alloc-write符号相关性.

    安全条件: write_end = write_expr + offset_expr
               <= alloc_expr (含分配器对齐余量)
    """
    result = CorrelationResult(
        alloc_expr=alloc_expr, write_expr=write_expr)

    if alloc_expr.is_tainted() and write_expr.is_tainted():
        result.reason = "both tainted, cannot correlate"
        return result

    if alloc_expr.is_constant() and write_expr.is_constant():
        return _correlate_constants(
            alloc_expr, write_expr, offset_expr, result)

    if write_expr.is_tainted():
        if alloc_expr.is_constant():
            offset_val = offset_expr.eval_const() if offset_expr else 0.0
            if offset_val is not None:
                result.proven_overflow = True
                result.reason = (
                    f"tainted write into fixed alloc: "
                    f"alloc={alloc_expr.const}, offset={offset_val}, "
                    f"write=tainted(unbounded)")
                return result
        # write tainted, alloc有变量 — 若alloc变量不来自同一taint源, 判溢出
        if alloc_expr.has_vars() and not alloc_expr.is_tainted():
            offset_val = offset_expr.eval_const() if offset_expr else 0.0
            if offset_val is not None:
                result.proven_overflow = True
                result.reason = (
                    f"tainted write into variable alloc "
                    f"(unrelated source): "
                    f"alloc={alloc_expr}, offset={offset_val}, "
                    f"write=tainted(unbounded)")
                return result
        result.reason = "write size tainted (user-controlled)"
        return result

    shared = alloc_expr.vars() & write_expr.vars()
    result.shared_vars = list(shared)

    if not shared:
        if write_expr.is_constant() and alloc_expr.is_constant():
            return _correlate_constants(
                alloc_expr, write_expr, offset_expr, result)

        if alloc_expr.is_constant() and write_expr.has_vars():
            if write_expr.is_tainted():
                offset_val = offset_expr.eval_const() if offset_expr else 0.0
                if offset_val is not None:
                    result.proven_overflow = True
                    result.reason = (
                        f"fixed alloc with tainted write: "
                        f"alloc={alloc_expr.const}, "
                        f"write={write_expr} (tainted, unbounded)")
                    return result
            result.reason = (
                f"fixed alloc with write var but no shared var: "
                f"alloc={alloc_expr.const}, "
                f"write={write_expr} (PC-BVF may refine with path constraints)")
            return result

        if write_expr.is_constant() and alloc_expr.has_vars():
            result.reason = (
                f"alloc has vars, write is const, no shared var: "
                f"cannot prove safe or overflow")
            return result

        result.reason = (
            f"no shared vars: alloc={alloc_expr.vars()}, "
            f"write={write_expr.vars()}")
        return result

    offset_val = offset_expr.eval_const() if offset_expr else 0.0
    if offset_val is None:
        result.reason = "offset not constant, cannot prove"
        return result

    if _check_subset_safety(
            alloc_expr, write_expr, offset_val, shared, result):
        return result

    if _check_overflow(
            alloc_expr, write_expr, offset_val, shared, result):
        return result

    result.reason = (
        f"shared vars {shared} but coefficient ratio inconclusive")
    return result


def _correlate_constants(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    result: CorrelationResult,
) -> CorrelationResult:
    """两个表达式都是常量时的直接比较.

    当偏移非常量时无法判定安全/溢出, 返回INCONCLUSIVE.
    """
    if offset_expr and not offset_expr.is_constant() and \
            offset_expr.has_vars():
        result.reason = (
            f"both alloc and write are constant but "
            f"offset is variable: {offset_expr}")
        return result

    offset_val = 0.0
    if offset_expr and offset_expr.is_constant():
        offset_val = offset_expr.const

    write_end = write.const + offset_val
    alloc_val = alloc.const

    if write_end <= alloc_val + 1e-9:
        result.proven_safe = True
        result.reason = (
            f"constant: write_end({write_end}) "
            f"<= alloc({alloc_val})")
        result.certificate = (
            f"DD-BVF Certificate [SAFE]\n"
            f"  alloc = {alloc_val}\n"
            f"  write_end = {write.const} + {offset_val} = {write_end}")
    elif write_end > alloc_val + 1e-9:
        result.proven_overflow = True
        result.reason = (
            f"constant: write_end({write_end}) "
            f"> alloc({alloc_val})")

    return result


def _check_subset_safety(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    shared: Set[str],
    result: CorrelationResult,
) -> bool:
    """检查子集安全性: write_end <= alloc_size.

    条件:
      1. 所有共享变量: alloc_coef >= write_coef
      2. write无非共享正系数变量(不自引入额外变量)
      3. write_const + offset <= alloc_const + 非共享alloc正系数之和
    """
    for v in shared:
        ac = alloc.coefs.get(v, 0)
        wc = write.coefs.get(v, 0)
        if ac < wc:
            return False

    non_shared_write = sum(
        c for v, c in write.coefs.items()
        if v not in shared and v != '' and c > 0)
    if non_shared_write > 0:
        return False

    non_shared_alloc = sum(
        c for v, c in alloc.coefs.items()
        if v not in shared and v != '' and c > 0)

    write_const_total = write.const + offset_val
    alloc_const_total = alloc.const + non_shared_alloc

    if write_const_total <= alloc_const_total + 1e-9:
        cert = _build_certificate(
            alloc, write, offset_val, shared, "SAFE")
        result.proven_safe = True
        result.reason = (
            f"subset relation: alloc={alloc}, write={write}, "
            f"offset={offset_val}; shared={list(shared)}; "
            f"write_const({write_const_total}) <= "
            f"alloc_const({alloc_const_total})")
        result.certificate = cert
        return True
    return False


def _check_overflow(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    shared: Set[str],
    result: CorrelationResult,
) -> bool:
    """检查溢出: write_end > alloc_size 在变量取正值时.

    条件(任一满足即溢出):
      1. 存在共享变量v: write_coef[v] > alloc_coef[v]
         (v取任意正值: write增长快于alloc)
      2. 所有共享变量系数相等, 但 write_const+offset > alloc_const
    """
    for v in shared:
        ac = alloc.coefs.get(v, 0)
        wc = write.coefs.get(v, 0)
        if wc > ac:
            result.proven_overflow = True
            result.reason = (
                f"overflow: write_coef[{v}]={wc} > "
                f"alloc_coef[{v}]={ac}, "
                f"variable {v} at any positive value "
                f"causes write > alloc")
            return True

    all_equal = all(
        alloc.coefs.get(v, 0) == write.coefs.get(v, 0)
        for v in shared)
    if all_equal:
        write_const_total = write.const + offset_val
        alloc_const_total = alloc.const
        if write_const_total > alloc_const_total + 1e-9:
            result.proven_overflow = True
            result.reason = (
                f"overflow: equal coefficients but "
                f"write_const({write_const_total}) > "
                f"alloc_const({alloc_const_total})")
            return True

    return False


def _build_certificate(
    alloc: SymbolicExpr,
    write: SymbolicExpr,
    offset_val: float,
    shared: Set[str],
    verdict: str,
) -> str:
    """构建形式化安全证书字符串."""
    return (
        f"DD-BVF Certificate [{verdict}]\n"
        f"  alloc_expr  = {alloc}\n"
        f"  write_expr  = {write}\n"
        f"  offset      = {offset_val}\n"
        f"  write_end   = {write} + {offset_val}\n"
        f"  shared_vars = {list(shared)}\n"
        f"  proof       = forall v in shared: "
        f"alloc_coef[v] >= write_coef[v]"
    )


__all__ = ['correlate']
