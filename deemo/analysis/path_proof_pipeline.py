"""
路径敏感约束传播 管道集成 — 作为仿射关系边界验证维度6, 提供路径敏感约束传播证明.

提供 L1/L2/L3 三层证明 (守卫约束/仿射传递/分配器语义),
补充现有维度的路径敏感约束传播能力.

设计原则 (功能只增不减):
  - 仅 FILTER 可证明安全的候选项
  - 不确定时 fall through 到现有维度
  - 不影响 仿射边界验证 (Affine Bound Verification) 任一维度的现有逻辑
"""


from typing import Dict, List, Optional, Tuple

from analysis.affine_bound_dimensions import (
    GapsbvVerdict, DimensionResult, GapsbvReport, _resolve_macros,
)
from analysis.path_proof_pair_prover import PairProof, MIVRPairProver


def dim6_mivr_constraint_proof(pseudocode: str) -> DimensionResult:
    """维度6: 路径敏感约束传播证明 — 路径敏感守卫→写入约束传播. (权重 0.30)

    1. 只在then分支内传播约束 (真·路径敏感)
    2. 通过赋值链传递性解析变量关系
    3. 三层证明体系 (守卫/仿射/语义), 逐级降级

    保守性: 仅当 L1(硬证明) 或 L2(仿射证明) 或 L3(语义证明)
    任一返回 SAFE 时才判定 SAFE. 否则 UNCERTAIN.
    """
    prover = MIVRPairProver()
    proofs = prover.prove_from_source(pseudocode)

    if not proofs:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "UNCERTAIN", 0.0,
            "no alloc-write pairs found")

    safe_proofs = [p for p in proofs if p.verdict == "SAFE"]
    overflow_proofs = [p for p in proofs if p.verdict == "OVERFLOW"]
    uncertain_proofs = [p for p in proofs if p.verdict == "UNCERTAIN"]

    # 统计各层级
    l1_safe = [p for p in safe_proofs if p.proof_level == "L1"]
    l2_safe = [p for p in safe_proofs if p.proof_level == "L2"]
    l3_safe = [p for p in safe_proofs if p.proof_level == "L3"]

    if l1_safe:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "SAFE", 0.90,
            f"L1: {len(l1_safe)} pair(s) proved safe by guard constraint: "
            + "; ".join(p.proof_detail[:80] for p in l1_safe[:2]))
    elif l2_safe:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "SAFE", 0.80,
            f"L2: {len(l2_safe)} pair(s) proved safe by affine + constraint: "
            + "; ".join(p.proof_detail[:80] for p in l2_safe[:2]))
    elif l3_safe:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "SAFE", 0.70,
            f"L3: {len(l3_safe)} pair(s) proved safe by constant offset / slack: "
            + "; ".join(p.proof_detail[:80] for p in l3_safe[:2]))
    elif overflow_proofs:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "OVERFLOW", 0.85,
            f"{len(overflow_proofs)} pair(s) confirmed overflow: "
            + "; ".join(p.proof_detail[:80] for p in overflow_proofs[:2]))
    elif uncertain_proofs:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "UNCERTAIN", 0.30,
            f"{len(uncertain_proofs)} pair(s) uncertain: "
            + "; ".join(p.proof_detail[:80] for p in uncertain_proofs[:2]))
    else:
        return DimensionResult(
            "MIVR_ConstraintProof", 0.30, "UNCERTAIN", 0.0,
            "no conclusive proofs")


def detect_heap_overflow_mivr(pseudocode: str) -> Tuple[str, float, List[PairProof]]:
    """路径敏感约束传播 独立检测入口 — 返回 (verdict, confidence, proofs).

    可用于:
      - 独立检测 (替代 仿射边界验证 (Affine Bound Verification))
      - 与 仿射边界验证 (Affine Bound Verification) 结果对比
      - 消融研究

    Example:
        >>> code = '''
        ...     buf = malloc(64);
        ...     if (idx < 64) {
        ...         buf[idx] = value;
        ...     }
        ... '''
        >>> verdict, conf, proofs = detect_heap_overflow_mivr(code)
        >>> print(verdict)  # SAFE
    """
    prover = MIVRPairProver()
    proofs = prover.prove_from_source(pseudocode)
    safe = [p for p in proofs if p.verdict == "SAFE"]
    overflow = [p for p in proofs if p.verdict == "OVERFLOW"]

    if safe:
        max_conf = max(p.confidence for p in safe)
        return "SAFE", max_conf, proofs
    elif overflow:
        max_conf = max(p.confidence for p in overflow)
        return "OVERFLOW", max_conf, proofs
    else:
        return "UNCERTAIN", 0.0, proofs


def run_gapsbv_with_mivr(pseudocode: str) -> GapsbvReport:
    """仿射关系边界验证 + 路径敏感约束传播 联合检测 — 在现有5维度基础上添加维度6.

    与 detect_heap_overflow_gapsbv 接口兼容, 但额外运行 路径敏感约束传播 维度.
    """
    from analysis.gapsbv_pipeline import detect_heap_overflow_gapsbv

    # 运行原 仿射边界验证 (Affine Bound Verification) 5维度
    report = detect_heap_overflow_gapsbv(pseudocode)

    # 追加 路径敏感约束传播 (Path-Sensitive Constraint Propagation) 作为维度6
    dim6 = dim6_mivr_constraint_proof(pseudocode)

    # 若 路径敏感约束传播 (Path-Sensitive Constraint Propagation) 给出更强的判定, 考虑覆盖
    if dim6.verdict == "SAFE" and report.verdict != "SAFE":
        # 路径敏感约束传播 (Path-Sensitive Constraint Propagation) 证明安全而 仿射边界验证 (Affine Bound Verification) 未证明 → 安全覆盖
        report.verdict = "SAFE"
        report.confidence = max(report.confidence, dim6.confidence)
        report.active_filters.append("MIVR_ConstraintProof")

    # 添加 路径敏感约束传播 (Path-Sensitive Constraint Propagation) 维度结果
    report.dimensions.append(dim6)

    return report


__all__ = [
    'dim6_mivr_constraint_proof',
    'detect_heap_overflow_mivr',
    'run_gapsbv_with_mivr',
]
