"""
CAAWP跨上下文证明模块 — 从caawp_prover.py拆分.

当write在callee函数, alloc在caller函数时, 通过调用链关联两者.
优先选择上下文链最深的快照(参数已完全展开).
对于多调用点场景, 通过alloc_size匹配正确的调用上下文.
"""

from typing import Dict, List, Optional, Tuple

from core.caawp_types import AffineSnapshot, ProofResult
from core.caawp_interpreter import _parse_size_expr


def try_cross_context_proof(
    snapshots: Dict[str, List[AffineSnapshot]],
    alloc_var: str,
    write_var: str,
    alloc_size_expr: str,
    write_size_expr: str,
    offset: int,
    chunk_slack: int,
    result: ProofResult,
) -> Optional[ProofResult]:
    """跨上下文证明 — write在callee, alloc在caller."""
    write_size_var = f"{write_var}_writesize"

    expected_alloc_const = None
    if alloc_size_expr:
        try:
            _, ac = _parse_size_expr(alloc_size_expr)
            expected_alloc_const = ac
        except Exception:
            pass

    candidates = []
    for func_name, snap_list in snapshots.items():
        for snap in snap_list:
            if write_size_var not in snap.var_relations:
                continue
            if not snap.ctx.call_chain:
                continue
            candidates.append((len(snap.ctx.call_chain), func_name, snap))

    candidates.sort(key=lambda x: -x[0])

    for _, func_name, snap in candidates:
        write_coefs, write_const = snap.var_relations[write_size_var]
        if _is_unresolved(write_coefs, write_var, snap):
            continue

        resolved_alloc_var = _resolve_alloc_var(alloc_var, write_var, snap)
        if resolved_alloc_var is None:
            continue

        resolved_size_var = f"{resolved_alloc_var}_size"
        match = _find_caller_snapshot(
            snapshots, resolved_size_var, expected_alloc_const)

        for caller_snap, alloc_coefs, alloc_const in match:
            temp = AffineSnapshot()
            temp.var_relations[resolved_size_var] = (alloc_coefs, alloc_const)
            temp.var_relations[write_size_var] = (write_coefs, write_const)

            safe, safe_reason = temp.can_prove_safe(
                resolved_size_var, write_size_var,
                chunk_slack, offset)
            if safe:
                _fill_result(
                    result, True, False,
                    f"CAAWP safe (cross-ctx): {safe_reason}",
                    f"{caller_snap.ctx.key()}>{snap.ctx.key()}",
                    resolved_alloc_var, resolved_size_var,
                    write_var, write_size_var,
                    alloc_coefs, alloc_const,
                    write_coefs, write_const,
                    offset, chunk_slack, safe_reason)
                return result

            overflow, overflow_reason = temp.can_prove_overflow(
                resolved_size_var, write_size_var, offset)
            if overflow:
                _fill_result(
                    result, False, True,
                    f"CAAWP overflow (cross-ctx): {overflow_reason}",
                    f"{caller_snap.ctx.key()}>{snap.ctx.key()}",
                    resolved_alloc_var, resolved_size_var,
                    write_var, write_size_var,
                    alloc_coefs, alloc_const,
                    write_coefs, write_const,
                    offset, chunk_slack, overflow_reason)
                return result

    return None


def _is_unresolved(write_coefs, write_var, snap):
    """检查write_coefs中是否仍有未展开的参数."""
    for var in write_coefs:
        if var in (write_var, 'sz', 'len', 'size', 'count'):
            if var in snap.var_relations:
                sub_coefs, _ = snap.var_relations[var]
                if not sub_coefs or (len(sub_coefs) == 1 and var in sub_coefs):
                    return True
    return False


def _resolve_alloc_var(alloc_var, write_var, snap):
    """从write_var映射推断caller中的alloc_var."""
    if write_var not in snap.var_relations:
        return alloc_var
    dst_coefs, _ = snap.var_relations[write_var]
    if len(dst_coefs) == 1:
        mapped_var = list(dst_coefs.keys())[0]
        if dst_coefs[mapped_var] == 1.0:
            if alloc_var and mapped_var != alloc_var:
                return None
            return mapped_var
    return alloc_var


def _find_caller_snapshot(snapshots, resolved_size_var, expected_alloc_const):
    """查找匹配的caller快照, 优先精确匹配alloc常量."""
    matching = []
    fallback = []
    for caller_func, caller_snaps in snapshots.items():
        for caller_snap in caller_snaps:
            if resolved_size_var not in caller_snap.var_relations:
                continue
            ac, av = caller_snap.var_relations[resolved_size_var]
            if expected_alloc_const is not None and \
                    not ac and abs(av - expected_alloc_const) < 1e-9:
                matching.append((caller_snap, ac, av))
            else:
                fallback.append((caller_snap, ac, av))
    return matching + fallback


def _fill_result(result, safe, overflow, reason, ctx_key,
                 resolved_alloc_var, resolved_size_var,
                 write_var, write_size_var,
                 alloc_coefs, alloc_const,
                 write_coefs, write_const,
                 offset, chunk_slack, proof_reason):
    """填充证明结果."""
    if safe:
        result.proven_safe = True
    if overflow:
        result.proven_overflow = True
    result.reason = reason
    result.ctx_key = ctx_key
    suffix = f"offset = {offset}, chunk_slack = {chunk_slack}" if safe \
        else f"offset = {offset}"
    result.proof_chain = [
        f"Cross-context: {ctx_key}",
        f"alloc({resolved_alloc_var}) = ({alloc_coefs}, {alloc_const})",
        f"write({write_var}) = ({write_coefs}, {write_const})",
        suffix,
        f"Proof: {proof_reason}",
    ]


__all__ = ['try_cross_context_proof']
