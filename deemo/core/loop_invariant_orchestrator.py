"""循环不变式分层证明编排器 — 协调Layer 1→2→3级联安全证明: 路径谓词约束变量边界、
不变式推导write_end边界、分配器对齐处理padding区。任一层证明SAFE→滤误报，
OVERFLOW→确认漏洞，全部无法判定→INCONCLUSIVE_RETAIN保守保留(零召回损失)。"""
from typing import Optional

from core.constraint_value_flow_types import SymbolicExpr, CorrelationResult
from core.constraint_constraint_types import SolverResult, SolverVerdict
from core.loop_invariant_types import (
    LSPProofResult, LSPVerdict, LSPStats,
)
from core.loop_invariant_invariant_prover import prove_with_invariants
from core.loop_invariant_allocator_prover import prove_with_allocator_alignment


_lsp_stats = LSPStats()


def try_lsp_proof(
    candidate,
    ir_lines: list,
    platform: str,
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    bvf_result: Optional[CorrelationResult],
) -> Optional[SolverResult]:
    """循环不变式分层证明分层安全证明 — 后向值流-INCONCLUSIVE时的精确化判定.

    级联执行Layer 2→3, 任一层判定成功即返回SolverResult.
    """
    global _lsp_stats

    alloc = candidate.alloc_site
    store = candidate.overflow_store

    alloc_size_const = 0
    if not alloc.size_is_dynamic and alloc.size_arg > 0:
        alloc_size_const = alloc.size_arg
    elif alloc_expr.is_constant():
        alloc_size_const = int(alloc_expr.const)

    result = _try_layer2(
        alloc_expr, write_expr, offset_expr,
        ir_lines, alloc.pc, store.pc,
        alloc_size_const, platform)
    if result is not None:
        _lsp_stats.record(result)
        return _convert_to_solver_result(result)

    result = _try_layer3(
        alloc_expr, write_expr, offset_expr,
        alloc_size_const, platform)
    if result is not None:
        _lsp_stats.record(result)
        return _convert_to_solver_result(result)

    placeholder = LSPProofResult(
        verdict=LSPVerdict.INCONCLUSIVE_RETAIN)
    _lsp_stats.record(placeholder)
    return None


def _try_layer2(
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    ir_lines: list,
    alloc_pc: int,
    write_pc: int,
    alloc_size_const: int,
    platform: str,
) -> Optional[LSPProofResult]:
    """Layer 2: 谓词不变式推导."""
    if write_expr.is_tainted():
        return None
    if write_expr.is_constant() and alloc_expr.is_constant():
        return None
    return prove_with_invariants(
        alloc_expr, write_expr, offset_expr,
        ir_lines, alloc_pc, write_pc,
        alloc_size_const, platform)


def _try_layer3(
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    alloc_size_const: int,
    platform: str,
) -> Optional[LSPProofResult]:
    """Layer 3: 分配器语义对齐."""
    if alloc_size_const <= 0 and alloc_expr.is_constant():
        alloc_size_const = int(alloc_expr.const)
    if alloc_size_const <= 0:
        return None
    return prove_with_allocator_alignment(
        alloc_expr, write_expr, offset_expr,
        alloc_size_const, platform)


def _convert_to_solver_result(
    lsp_result: LSPProofResult,
) -> Optional[SolverResult]:
    """将循环不变式分层证明判定转化为约束求解兼容的SolverResult."""
    sr = SolverResult()
    if lsp_result.verdict == LSPVerdict.PROVEN_SAFE:
        sr.verdict = SolverVerdict.PROVEN_SAFE
        sr.reason = f"循环不变式分层证明: {lsp_result.reason}"
        sr.confidence_delta = lsp_result.confidence_delta
        sr.proof_chain = lsp_result.proof_chain
        return sr
    if lsp_result.verdict == LSPVerdict.PROVEN_OVERFLOW:
        sr.verdict = SolverVerdict.PROVEN_OVERFLOW
        sr.reason = f"循环不变式分层证明: {lsp_result.reason}"
        sr.confidence_delta = lsp_result.confidence_delta
        sr.proof_chain = lsp_result.proof_chain
        return sr
    return None


def get_lsp_stats() -> LSPStats:
    """获取循环不变式分层证明运行统计."""
    return _lsp_stats


def reset_lsp_stats() -> None:
    """重置循环不变式分层证明统计(测试用)."""
    global _lsp_stats
    _lsp_stats = LSPStats()


__all__ = [
    'try_lsp_proof', 'get_lsp_stats', 'reset_lsp_stats',
]
