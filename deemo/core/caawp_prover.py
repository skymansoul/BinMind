"""
CAAWP证明器 — 上下文敏感的分配-写入安全性证明.

当CJ求解器返回INCONCLUSIVE时, 调用本模块:
  1. 运行CAAWPInterpreter获取所有函数的上下文敏感仿射快照
  2. 对每个(alloc, write)候选对, 匹配对应上下文快照
  3. 使用AffineSnapshot.can_prove_safe/can_prove_overflow证明
  4. 生成形式化安全证书

与DD-BVF(cj_bvf_tracer)的关系:
  DD-BVF做反向值流追踪, 从告警点反向找定义链.
  CAAWP做前向上下文敏感传播, 预计算所有调用点的仿射状态.
  两者互补: DD-BVF适合单函数内, CAAWP适合跨函数上下文区分.

保守性保证:
  证明失败不影响后续步骤, 不引入假阴性.
  仅在能明确证明safe时滤除, 能明确证明overflow时确认.
"""

from typing import Dict, List, Optional, Tuple

from core.caawp_types import CallContext, AffineSnapshot, ProofResult
from core.caawp_interpreter import CAAWPInterpreter, _parse_size_expr
from core.caawp_cross_ctx import try_cross_context_proof
from core.caawp_helpers import (
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
    """对单个(alloc, write)候选执行CAAWP证明."""
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
        result.reason = f"CAAWP safe: {safe_reason}"
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
        result.reason = f"CAAWP overflow: {overflow_reason}"
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

    result.reason = f"CAAWP inconclusive: {safe_reason}"
    return result


__all__ = ['prove_candidate']
