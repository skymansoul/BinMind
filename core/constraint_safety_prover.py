"""
安全性证明器: 尝试证明堆写入在约束系统下安全: 对 copy 操作证明 copy_size <= effective_alloc_size, 对偏移写入证明 offset + store_size <= effective_alloc_size, 对循环写入证明 loop_bound * elem_size <= alloc_size。
方法: 构造"安全约束" write_end - effective_alloc_size <= 0 并加入系统, 对非安全相关变量做 Fourier-Motzkin 消元, 剩余常量约束矛盾则原系统蕴含安全, 判 PROVEN_SAFE; 无矛盾则返回 None。
保守性: 证明失败时返回 None, 不影响召回率 (候选保留)。
"""

from typing import Optional
from dataclasses import dataclass, field

from core.constraint_constraint_types import (
    ConstraintType, SolverVerdict, LinearConstraint,
    ConstraintSystem,
)
from core.constraint_fourier_motzkin import (
    fourier_motzkin_eliminate,
    check_feasibility,
)
from core.constraint_safety_helpers import (
    evaluate_constant_write_end as _evaluate_constant_write_end,
    compute_usable_size as _compute_usable_size,
    compute_write_end as _compute_write_end,
)


@dataclass
class ProofResult:
    """证明结果."""
    verdict: str = ""
    reason: str = ""
    confidence_delta: float = 0.0
    proof_chain: list[str] = field(default_factory=list)


def prove_write_safety(
    sys: ConstraintSystem,
    platform: str = "x86_64",
) -> Optional[ProofResult]:
    """尝试证明写入安全(不溢出).

    策略: 计算write_end和boundary的值/表达式,
    若能确定write_end <= boundary, 判 PROVEN_SAFE.

    对纯常量场景直接比较; 对含变量场景用假设+消元法.
    返回None表示无法证明安全(保守保留候选).
    """
    alloc_usable = _compute_usable_size(sys, platform)
    if alloc_usable <= 0:
        return None

    write_end_expr, write_end_desc = _compute_write_end(sys)
    if write_end_expr is None:
        return None

    if not write_end_expr:
        write_end_val = _evaluate_constant_write_end(sys)
        if write_end_val is not None:
            if write_end_val <= alloc_usable:
                return ProofResult(
                    verdict="PROVEN_SAFE",
                    reason=f"{write_end_desc} <= {alloc_usable} (usable_size)",
                    confidence_delta=-0.45,
                    proof_chain=[
                        f"Step 1: write_end = {write_end_val}",
                        f"Step 2: usable_size = {alloc_usable}",
                        f"Step 3: {write_end_val} <= {alloc_usable} → SAFE",
                    ],
                )
            return None

    overflow_constraint = LinearConstraint(
        coefficients=dict(write_end_expr),
        constant=float(-alloc_usable),
        operator=">",
        source=ConstraintType.ALIGNMENT,
        confidence=1.0,
        description=f"assumption: {write_end_desc} > {alloc_usable} (overflow)",
    )

    all_constraints = list(sys.constraints) + [overflow_constraint]

    non_target_vars = [
        v for v in sys.var_names
        if v not in write_end_expr
    ]

    if non_target_vars:
        all_constraints = fourier_motzkin_eliminate(
            all_constraints, non_target_vars)

    write_vars = list(write_end_expr.keys())
    if len(write_vars) > 1:
        all_constraints = fourier_motzkin_eliminate(
            all_constraints, write_vars[1:])

    feasible, reason = check_feasibility(all_constraints)

    if not feasible:
        proof_chain = [
            f"Step 1: assume overflow: {write_end_desc} > {alloc_usable}",
            f"Step 2: collect {len(sys.constraints)} constraints from IR",
            f"Step 3: FM-eliminate {len(non_target_vars)} non-target vars",
            f"Step 4: contradiction found → overflow impossible",
            f"Conclusion: write is SAFE (proven by constraint joining)",
        ]
        return ProofResult(
            verdict="PROVEN_SAFE",
            reason=f"constraint system proves {write_end_desc} <= {alloc_usable}",
            confidence_delta=-0.45,
            proof_chain=proof_chain,
        )

    return None


def prove_overflow(
    sys: ConstraintSystem,
    platform: str = "x86_64",
) -> Optional[ProofResult]:
    """尝试确认溢出(证明写入确实超出边界).

    策略: 计算write_end和boundary的值/表达式,
    若能确定write_end > boundary, 判 PROVEN_OVERFLOW.

    仅在约束非常充分时触发, 避免过度自信.
    """
    alloc_usable = _compute_usable_size(sys, platform)
    if alloc_usable <= 0:
        return None

    write_end_expr, write_end_desc = _compute_write_end(sys)
    if write_end_expr is None:
        return None

    if not write_end_expr:
        write_end_val = _evaluate_constant_write_end(sys)
        if write_end_val is not None and write_end_val > alloc_usable:
            return ProofResult(
                verdict="PROVEN_OVERFLOW",
                reason=f"{write_end_desc} = {write_end_val} > {alloc_usable} (usable_size)",
                confidence_delta=+0.20,
                proof_chain=[
                    f"Step 1: write_end = {write_end_val}",
                    f"Step 2: usable_size = {alloc_usable}",
                    f"Step 3: {write_end_val} > {alloc_usable} → OVERFLOW",
                ],
            )
        return None

    safety_constraint = LinearConstraint(
        coefficients=dict(write_end_expr),
        constant=float(-alloc_usable),
        operator="<=",
        source=ConstraintType.ALIGNMENT,
        confidence=1.0,
        description=f"assumption: {write_end_desc} <= {alloc_usable} (safe)",
    )

    all_constraints = list(sys.constraints) + [safety_constraint]

    non_target_vars = [
        v for v in sys.var_names
        if v not in write_end_expr
    ]

    if non_target_vars:
        all_constraints = fourier_motzkin_eliminate(
            all_constraints, non_target_vars)

    write_vars = list(write_end_expr.keys())
    if len(write_vars) > 1:
        all_constraints = fourier_motzkin_eliminate(
            all_constraints, write_vars[1:])

    feasible, reason = check_feasibility(all_constraints)

    if not feasible:
        return ProofResult(
            verdict="PROVEN_OVERFLOW",
            reason=f"constraint system confirms {write_end_desc} > {alloc_usable}",
            confidence_delta=+0.20,
            proof_chain=[
                f"Step 1: assume safe: {write_end_desc} <= {alloc_usable}",
                f"Step 2: collect {len(sys.constraints)} constraints",
                f"Step 3: contradiction → safe assumption is false",
                f"Conclusion: overflow CONFIRMED",
            ],
        )

    return None


__all__ = [
    'ProofResult',
    'prove_write_safety',
    'prove_overflow',
]
