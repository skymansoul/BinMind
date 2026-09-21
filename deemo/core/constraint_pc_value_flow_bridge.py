"""
路径条件后向值流求解器桥接 — 后向值流 INCONCLUSIVE 时触发路径约束感知判定: 从告警点提取路径约束收紧变量值域, 受约束后重新判定安全性/溢出, 无法判定时返回 None (零召回损失)。
后向值流在前, 路径条件后向值流在后: 只在后向值流返回 INCONCLUSIVE 时启动, 利用后向值流无法获取的路径条件信息, 不重复后向值流的工作。
"""
from typing import Optional

from core.constraint_constraint_types import SolverVerdict, SolverResult


def try_pcbvf_proof(
    candidate,
    ir_lines: list[str],
    platform: str,
) -> Optional[SolverResult]:
    """路径条件后向值流路径约束感知证明 — 后向值流 INCONCLUSIVE时的约束增强判定.

    从告警点提取路径约束, 将其注入后向值流相关性判定.
    不影响召回率: 路径条件后向值流无法判定时返回None.
    """
    from core.constraint_value_flow_tracer import BackwardValueFlow, SymbolicExpr
    from core.constraint_pc_value_flow_constraints import extract_path_constraints
    from core.constraint_pc_value_flow_correlator import correlate_with_constraints

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
        sr.reason = f"路径条件后向值流: {result.reason}"
        sr.confidence_delta = -0.40
        sr.proof_chain = [
            f"路径条件后向值流: path constraints = "
            f"{ {k: str(v) for k, v in bounds.items()} }",
            f"路径条件后向值流: alloc_expr = {alloc_expr}",
            f"路径条件后向值流: write_expr = {write_expr}",
            f"路径条件后向值流: offset_expr = {offset_expr}",
            f"路径条件后向值流: {result.reason}",
            f"路径条件后向值流 Certificate:\n{result.certificate}",
        ]
        return sr

    if result.proven_overflow:
        sr = SolverResult()
        sr.verdict = SolverVerdict.PROVEN_OVERFLOW
        sr.reason = f"路径条件后向值流: {result.reason}"
        sr.confidence_delta = +0.15
        sr.proof_chain = [
            f"路径条件后向值流: path constraints = "
            f"{ {k: str(v) for k, v in bounds.items()} }",
            f"路径条件后向值流: alloc_expr = {alloc_expr}",
            f"路径条件后向值流: write_expr = {write_expr}",
            f"路径条件后向值流: {result.reason}",
        ]
        return sr

    return None


def try_pcbvf_after_bvf(
    candidate,
    ir_lines: list[str],
    platform: str,
    bvf_result,
) -> Optional[SolverResult]:
    """后向值流返回INCONCLUSIVE后, 尝试路径条件后向值流约束增强.

    参数bvf_result是后向值流的返回结果(可为None).
    """
    if bvf_result is not None:
        return None

    return try_pcbvf_proof(candidate, ir_lines, platform)


__all__ = ['try_pcbvf_proof', 'try_pcbvf_after_bvf']
