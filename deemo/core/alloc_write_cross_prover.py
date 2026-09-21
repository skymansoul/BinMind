"""
跨上下文分配-写溯源 证明器: 上下文敏感的分配-写入安全性证明。
约束求解 (Constraint Solving) 求解器返回 INCONCLUSIVE 时运行 CAAWPInterpreter 获取各函数上下文敏感仿射快照, 匹配 (alloc, write) 候选对,
用 can_prove_safe/can_prove_overflow 证明并生成证书。与 DD-后向值流 (Backward Value Flow) 互补, 后者适合单函数内, 前者适合跨函数上下文区分。
证明失败不影响后续步骤, 不引入假阴性。
"""

from typing import Dict, List, Optional, Tuple

from core.alloc_write_cross_types import CallContext, AffineSnapshot, ProofResult
from core.alloc_write_cross_interpreter import CAAWPInterpreter, _parse_size_expr
from core.alloc_write_cross_cross_ctx import try_cross_context_proof
from core.alloc_write_cross_helpers import (
    find_best_snapshot, direct_proof, build_certificate)


def prove_candidate(
    code: str,
    alloc_var: str,
    write_var: str,
    alloc_size_expr: str = "",
    write_size_expr: str = "",
    offset: int = 0,
    chunk_slack: int = 0,
) -> ProofResult:
    """对单个(alloc, write)候选执行跨上下文分配-写溯源证明."""
    result = ProofResult(
        alloc_var=alloc_var, write_var=write_var,
        chunk_slack=chunk_slack)

    interpreter = CAAWPInterpreter()
    snapshots = interpreter.analyze(code)

    alloc_size_var = f"{alloc_var}_size"

    # 尝试跨上下文证明
    ctx_result = try_cross_context_proof(
        snapshots, alloc_var, write_var,
        alloc_size_expr, write_size_expr,
        offset, chunk_slack, result)
    if ctx_result is not None:
        return ctx_result

    write_size_var = f"{write_var}_writesize"
    best_snapshot = find_best_snapshot(
        snapshots, alloc_var, write_var,
        alloc_size_var, write_size_var)

    if best_snapshot is None:
        if alloc_size_expr and write_size_expr:
            return direct_proof(
                alloc_size_expr, write_size_expr,
                offset, chunk_slack, result)
        result.reason = "no matching affine snapshot found"
        return result

    result.ctx_key = best_snapshot.ctx.key()

    if alloc_size_var in best_snapshot.var_relations:
        alloc_expr = best_snapshot.var_relations[alloc_size_var]
    elif alloc_size_expr:
        alloc_expr = _parse_size_expr(alloc_size_expr)
        best_snapshot.var_relations[alloc_size_var] = alloc_expr
    else:
        result.reason = f"alloc size expression not found for {alloc_var}"
        return result

    if write_size_var in best_snapshot.var_relations:
        write_expr = best_snapshot.var_relations[write_size_var]
    elif write_size_expr:
        write_expr = _parse_size_expr(write_size_expr)
        best_snapshot.var_relations[write_size_var] = write_expr
    else:
        result.reason = f"write size expression not found for {write_var}"
        return result

    safe, safe_reason = best_snapshot.can_prove_safe(
        alloc_size_var, write_size_var, chunk_slack, offset)
    if safe:
        result.proven_safe = True
        result.reason = f"跨上下文分配-写溯源 safe: {safe_reason}"
        result.certificate = build_certificate(
            alloc_var, write_var, alloc_expr, write_expr,
            offset, chunk_slack, "SAFE", result.ctx_key)
        result.proof_chain = [
            f"Context: {result.ctx_key}",
            f"alloc({alloc_var}) = {alloc_expr}",
            f"write({write_var}) = {write_expr}",
            f"offset = {offset}, chunk_slack = {chunk_slack}",
            f"Proof: {safe_reason}",
        ]
        return result

    overflow, overflow_reason = best_snapshot.can_prove_overflow(
        alloc_size_var, write_size_var, offset)
    if overflow:
        result.proven_overflow = True
        result.reason = f"跨上下文分配-写溯源 overflow: {overflow_reason}"
        result.certificate = build_certificate(
            alloc_var, write_var, alloc_expr, write_expr,
            offset, chunk_slack, "OVERFLOW", result.ctx_key)
        result.proof_chain = [
            f"Context: {result.ctx_key}",
            f"alloc({alloc_var}) = {alloc_expr}",
            f"write({write_var}) = {write_expr}",
            f"offset = {offset}",
            f"Proof: {overflow_reason}",
        ]
        return result

    result.reason = f"跨上下文分配-写溯源 inconclusive: {safe_reason}"
    return result


__all__ = ['prove_candidate']
