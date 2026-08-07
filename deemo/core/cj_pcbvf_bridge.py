"""
PC-BVF求解器桥接 — BVF INCONCLUSIVE时触发路径约束感知判定.

集成策略:
  1. CJ → INCONCLUSIVE → BVF → INCONCLUSIVE → PC-BVF
  2. PC-BVF从告警点提取路径约束, 收紧变量值域
  3. 受约束后重新判定安全性/溢出
  4. PC-BVF无法判定时返回None, 调用方保留原始结果(零召回损失)

与BVF的关系:
  - BVF在前, PC-BVF在后: BVF能判定的不触发PC-BVF
  - PC-BVF是BVF的约束增强: 利用BVF无法获取的路径条件信息
  - PC-BVF不重复BVF的工作: 只在BVF返回INCONCLUSIVE时启动
"""
from typing import Optional

from core.cj_constraint_types import SolverVerdict, SolverResult


def try_pcbvf_proof(
    candidate,
    ir_lines: list[str],
    platform: str,
) -> Optional[SolverResult]:
    """PC-BVF路径约束感知证明 — BVF INCONCLUSIVE时的约束增强判定.

    从告警点提取路径约束, 将其注入BVF相关性判定.
    不影响召回率: PC-BVF无法判定时返回None.
    """
    from core.cj_bvf_tracer import BackwardValueFlow, SymbolicExpr
    from core.cj_pcbvf_constraints import extract_path_constraints
    from core.cj_pcbvf_correlator import correlate_with_constraints

    bvf = BackwardValueFlow()
    alloc = candidate.alloc_site
    store = candidate.overflow_store

    bounds = extract_path_constraints(
        ir_lines, store.pc, window=60)

    if not bounds:
        return None

    alloc_expr = bvf.trace_alloc_size(
        ir_lines, alloc.alloc_func,
        alloc.size_expr if alloc.size_is_dynamic else str(alloc.size_arg),
        alloc.pc)
    if alloc.size_arg > 0 and not alloc.size_is_dynamic:
        alloc_expr = SymbolicExpr(
            const=float(alloc.size_arg),
            origin=f"const_alloc:{alloc.size_arg}")

    if store.mnemonic in ('strcpy', 'strcat'):
        return None

    if store.store_size > 0:
        write_expr = SymbolicExpr(
            const=float(store.store_size),
            origin=f"store_size:{store.store_size}")
    elif store.mnemonic in ('memcpy', 'memmove', 'strncpy', 'memset',
                             'strncat'):
        write_expr = bvf.trace_write_size(
            ir_lines, store.pc, store.mnemonic, store.store_size)
    else:
        write_expr = SymbolicExpr(
            const=float(store.store_size if store.store_size > 0 else 4))

    if not store.offset_is_dynamic and store.offset >= 0:
        offset_expr = SymbolicExpr(const=float(store.offset))
    elif store.offset_is_dynamic:
        offset_expr = bvf.trace_var(ir_lines, "offset", store.pc)
    else:
        offset_expr = SymbolicExpr(const=0.0)

    result = correlate_with_constraints(
        alloc_expr, write_expr, offset_expr, bounds)

    if result.proven_safe:
        sr = SolverResult()
        sr.verdict = SolverVerdict.PROVEN_SAFE
        sr.reason = f"PC-BVF: {result.reason}"
        sr.confidence_delta = -0.40
        sr.proof_chain = [
            f"PC-BVF: path constraints = "
            f"{ {k: str(v) for k, v in bounds.items()} }",
            f"PC-BVF: alloc_expr = {alloc_expr}",
            f"PC-BVF: write_expr = {write_expr}",
            f"PC-BVF: offset_expr = {offset_expr}",
            f"PC-BVF: {result.reason}",
            f"PC-BVF Certificate:\n{result.certificate}",
        ]
        return sr

    if result.proven_overflow:
        sr = SolverResult()
        sr.verdict = SolverVerdict.PROVEN_OVERFLOW
        sr.reason = f"PC-BVF: {result.reason}"
        sr.confidence_delta = +0.15
        sr.proof_chain = [
            f"PC-BVF: path constraints = "
            f"{ {k: str(v) for k, v in bounds.items()} }",
            f"PC-BVF: alloc_expr = {alloc_expr}",
            f"PC-BVF: write_expr = {write_expr}",
            f"PC-BVF: {result.reason}",
        ]
        return sr

    return None


def try_pcbvf_after_bvf(
    candidate,
    ir_lines: list[str],
    platform: str,
    bvf_result,
) -> Optional[SolverResult]:
    """BVF返回INCONCLUSIVE后, 尝试PC-BVF约束增强.

    参数bvf_result是BVF的返回结果(可为None).
    """
    if bvf_result is not None:
        return None

    return try_pcbvf_proof(candidate, ir_lines, platform)


__all__ = ['try_pcbvf_proof', 'try_pcbvf_after_bvf']
