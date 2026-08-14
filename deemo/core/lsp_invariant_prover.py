"""
LSP Layer 2 — 谓词不变式推导器: 将路径谓词代入符号表达式，
推导write_end与alloc_size的确切关系（有界变量安全/溢出、仿射增强三类推导）。
无法判定时返回None，不影响后续层。
"""
from typing import Dict, List, Optional, Set, Tuple

from core.cj_bvf_types import SymbolicExpr
from core.lsp_types import (
    LSPProofResult, LSPVerdict, LSPProofLayer, PathPredicate,
)
from core.lsp_path_collector import (
    collect_path_predicates, derive_variable_bounds,
)


def prove_with_invariants(
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    ir_lines: List[str],
    alloc_pc: int,
    write_pc: int,
    alloc_size_const: int = 0,
    platform: str = "x86_64",
) -> Optional[LSPProofResult]:
    """Layer 2: 谓词不变式推导证明.

    流程:
      1. 收集路径谓词
      2. 对write_expr中的每个变量提取边界
      3. 计算write_end的紧致上下界
      4. 与alloc_size(含分配器对齐)比较

    返回LSPProofResult或None(无法判定).
    """
    predicates = collect_path_predicates(ir_lines, alloc_pc, write_pc)
    if not predicates:
        return None

    offset_val = 0.0
    if offset_expr and offset_expr.is_constant():
        offset_val = offset_expr.const

    alloc_const = alloc_size_const
    if alloc_expr.is_constant():
        alloc_const = int(alloc_expr.const)
    if alloc_const <= 0:
        return None

    usable = _compute_usable(alloc_const, platform)
    if usable <= 0:
        usable = alloc_const

    write_end_lo, write_end_hi = _bound_write_end(
        write_expr, offset_val, predicates)

    if write_end_hi is not None and write_end_hi <= usable + 1e-9:
        return LSPProofResult(
            verdict=LSPVerdict.PROVEN_SAFE,
            proven_layer=LSPProofLayer.INVARIANT_INFERENCE,
            reason=(
                f"path-bounded safe: write_end_hi={write_end_hi} "
                f"<= usable={usable}, predicates={len(predicates)}"),
            confidence_delta=-0.40,
            proof_chain=[
                f"Step 1: collect {len(predicates)} path predicates",
                f"Step 2: bound write_expr={write_expr} → "
                f"[{write_end_lo}, {write_end_hi}]",
                f"Step 3: usable_size={usable} for alloc({alloc_const})",
                f"Step 4: {write_end_hi} <= {usable} → SAFE",
            ],
            predicates_collected=predicates,
        )

    if write_end_lo is not None and write_end_lo > usable + 1e-9:
        return LSPProofResult(
            verdict=LSPVerdict.PROVEN_OVERFLOW,
            proven_layer=LSPProofLayer.INVARIANT_INFERENCE,
            reason=(
                f"path-bounded overflow: write_end_lo={write_end_lo} "
                f"> usable={usable}, predicates={len(predicates)}"),
            confidence_delta=+0.15,
            proof_chain=[
                f"Step 1: collect {len(predicates)} path predicates",
                f"Step 2: bound write_expr={write_expr} → "
                f"[{write_end_lo}, {write_end_hi}]",
                f"Step 3: usable_size={usable} for alloc({alloc_const})",
                f"Step 4: {write_end_lo} > {usable} → OVERFLOW",
            ],
            predicates_collected=predicates,
        )

    return None


def _bound_write_end(
    write_expr: SymbolicExpr,
    offset_val: float,
    predicates: List[PathPredicate],
) -> Tuple[Optional[float], Optional[float]]:
    """计算write_end = write_expr + offset的紧致上下界.

    对每个变量提取路径谓词中的[lo, hi], 然后线性组合:
      write_end = sum(coef_i * var_i) + const + offset
      上下界 = sum(coef_i * bound_i) + const + offset
    """
    if write_expr.is_constant():
        val = write_expr.const + offset_val
        return val, val

    if write_expr.is_tainted():
        return None, None

    lo_sum = write_expr.const + offset_val
    hi_sum = write_expr.const + offset_val

    for var, coef in write_expr.coefs.items():
        if coef == 0:
            continue
        v_lo, v_hi = derive_variable_bounds(predicates, var)
        if v_lo is None and v_hi is None:
            return None, None

        if coef > 0:
            if v_lo is not None:
                lo_sum += coef * v_lo
            else:
                lo_sum = None
            if v_hi is not None:
                hi_sum += coef * v_hi
            else:
                hi_sum = None
        else:
            if v_hi is not None:
                lo_sum += coef * v_hi
            else:
                lo_sum = None
            if v_lo is not None:
                hi_sum += coef * v_lo
            else:
                hi_sum = None

    return lo_sum, hi_sum


def _compute_usable(alloc_size: int, platform: str) -> int:
    """计算分配器对齐后的可用大小."""
    try:
        from analysis.allocator_chunk_model import compute_effective_boundary
        return compute_effective_boundary(alloc_size, "malloc")
    except ImportError:
        if platform == "x86_64":
            remainder = alloc_size % 16
            if remainder == 0:
                return alloc_size
            return alloc_size + (16 - remainder)
        return alloc_size


__all__ = ['prove_with_invariants']
