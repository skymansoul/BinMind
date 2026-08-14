"""
LSP Layer 3 — 分配器语义对齐证明器: 处理分配器对齐余量导致的边界判定。
malloc(24)→usable=32，write_end落在alloc与usable之间时按padding访问判SAFE。
仅当write_end明确落在padding区判SAFE，超出usable_size判OVERFLOW，否则返回None。
"""
from typing import Optional

from core.cj_bvf_types import SymbolicExpr
from core.lsp_types import (
    LSPProofResult, LSPVerdict, LSPProofLayer,
)


def prove_with_allocator_alignment(
    alloc_expr: SymbolicExpr,
    write_expr: SymbolicExpr,
    offset_expr: Optional[SymbolicExpr],
    alloc_size_const: int,
    platform: str = "x86_64",
) -> Optional[LSPProofResult]:
    """Layer 3: 分配器语义对齐证明.

    当alloc和write均为常量, 且write_end > alloc但 <= usable时,
    证明访问落在对齐padding区, 判定SAFE.
    """
    if not alloc_expr.is_constant():
        return None

    alloc_val = int(alloc_expr.const)
    if alloc_val <= 0:
        return None

    offset_val = 0.0
    if offset_expr and offset_expr.is_constant():
        offset_val = offset_expr.const

    if write_expr.is_constant():
        write_end = write_expr.const + offset_val
    elif write_expr.is_tainted():
        return None
    else:
        return None

    usable = _compute_usable_size(alloc_val, platform)
    if usable <= 0:
        return None

    padding = usable - alloc_val

    if write_end <= alloc_val + 1e-9:
        return None

    if write_end <= usable + 1e-9:
        return LSPProofResult(
            verdict=LSPVerdict.PROVEN_SAFE,
            proven_layer=LSPProofLayer.ALLOCATOR_ALIGNMENT,
            reason=(
                f"allocator padding safe: write_end={write_end} "
                f"<= usable={usable}, alloc={alloc_val}, "
                f"padding={padding}B"),
            confidence_delta=-0.30,
            proof_chain=[
                f"Step 1: alloc={alloc_val}, usable={usable} "
                f"(padding={padding}B)",
                f"Step 2: write_end={write_end} "
                f"({write_expr.const} + offset {offset_val})",
                f"Step 3: {alloc_val} < {write_end} <= {usable} "
                f"→ falls in padding zone",
                f"Conclusion: access within usable boundary → SAFE",
            ],
        )

    if write_end > usable + 1e-9:
        return LSPProofResult(
            verdict=LSPVerdict.PROVEN_OVERFLOW,
            proven_layer=LSPProofLayer.ALLOCATOR_ALIGNMENT,
            reason=(
                f"allocator confirmed overflow: write_end={write_end} "
                f"> usable={usable}, alloc={alloc_val}"),
            confidence_delta=+0.10,
            proof_chain=[
                f"Step 1: alloc={alloc_val}, usable={usable}",
                f"Step 2: write_end={write_end}",
                f"Step 3: {write_end} > {usable} "
                f"→ exceeds usable boundary",
                f"Conclusion: OVERFLOW confirmed",
            ],
        )

    return None


def _compute_usable_size(alloc_size: int, platform: str) -> int:
    """计算分配器实际可用大小(含对齐padding)."""
    try:
        from analysis.allocator_chunk_model import compute_effective_boundary
        return compute_effective_boundary(alloc_size, "malloc")
    except ImportError:
        word_size = 16 if platform == "x86_64" else 8
        if alloc_size <= 0:
            return 0
        if platform == "x86_64":
            chunk = max(32, ((alloc_size + 16 + 15) // 16) * 16)
            return chunk - 16
        else:
            chunk = max(16, ((alloc_size + 8 + 7) // 8) * 8)
            return chunk - 8


__all__ = ['prove_with_allocator_alignment']
