"""
约束联结求解器 — 对约束系统做联合可行性判定: 常量代换简化 → 安全性证明 → 溢出确认 → FM 边界推理。
Fourier-Motzkin 消元从线性不等式组消去变量, 组合 a*x+..<=0 与 b*x+..>=0 (a>0, b<0), 消元后出现矛盾则系统不可行。
无法证明安全或溢出时返回 INCONCLUSIVE (保守保留); 不符号化内存地址, 不调用 SMT 求解器, 复杂度 O(n^3) (n 为约束数)。
"""

import math
from typing import Optional

from core.cj_constraint_types import (
    ConstraintType, SolverVerdict, LinearConstraint,
    ConstraintSystem, SolverResult,
)
from core.cj_fourier_motzkin import (
    fourier_motzkin_eliminate,
    check_feasibility,
    substitute_constant,
)
from core.cj_safety_prover import (
    prove_write_safety,
    prove_overflow,
    _compute_usable_size,
    _compute_write_end,
)


class ConstraintJoinSolver:
    """约束联结求解器.

    对单个(alloc, write)对的约束系统做联合判定.
    四步:
      Step 1: 常量代换 — 将已知常量代入约束系统
      Step 2: 安全性证明 — 尝试证明 write_end <= alloc_usable
      Step 3: 溢出确认 — 尝试证明 write_end > alloc_usable
      Step 4: FM边界推理 — 从残差约束推导变量边界, 补充判定
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform

    def solve(self, sys: ConstraintSystem) -> SolverResult:
        """对约束系统做联合判定."""
        result = SolverResult()
        result.constraints_collected = len(sys.constraints)

        simplified = self._simplify(sys)
        result.constraints_used = len(simplified.constraints)

        safety = prove_write_safety(simplified, self._platform)
        if safety is not None:
            result.verdict = SolverVerdict.PROVEN_SAFE
            result.reason = safety.reason
            result.confidence_delta = safety.confidence_delta
            result.proof_chain = safety.proof_chain
            return result

        overflow = prove_overflow(simplified, self._platform)
        if overflow is not None:
            result.verdict = SolverVerdict.PROVEN_OVERFLOW
            result.reason = overflow.reason
            result.confidence_delta = overflow.confidence_delta
            result.proof_chain = overflow.proof_chain
            return result

        fm_result = self._fm_boundary_refine(simplified)
        if fm_result is not None:
            result.verdict = fm_result[0]
            result.reason = fm_result[1]
            result.confidence_delta = -0.35 if fm_result[0] == SolverVerdict.PROVEN_SAFE else 0.15
            result.proof_chain = [f"FM boundary: {fm_result[1]}"]
            return result

        result.verdict = SolverVerdict.INCONCLUSIVE
        result.reason = (
            f"constraints insufficient: {len(simplified.constraints)} "
            f"constraints, {len(simplified.var_names)} vars, "
            f"cannot prove safe or overflow")
        return result

    def _simplify(self, sys: ConstraintSystem) -> ConstraintSystem:
        """常量代换 + 冗余约束删除."""
        simplified = ConstraintSystem(
            alloc_var=sys.alloc_var,
            alloc_size=sys.alloc_size,
            copy_var=sys.copy_var,
            copy_size=sys.copy_size,
            offset_var=sys.offset_var,
            offset_val=sys.offset_val,
            loop_var=sys.loop_var,
            loop_bound=sys.loop_bound,
            mnemonic=sys.mnemonic,
            store_size=sys.store_size,
        )

        bound_map: dict[str, float] = {}
        if sys.alloc_size > 0:
            bound_map[sys.alloc_var] = float(sys.alloc_size)
        if sys.copy_size > 0:
            bound_map[sys.copy_var] = float(sys.copy_size)
        if sys.offset_val > 0 and sys.offset_var:
            bound_map[sys.offset_var] = float(sys.offset_val)
        if sys.loop_bound > 0 and sys.loop_var:
            bound_map[sys.loop_var] = float(sys.loop_bound)

        for c in sys.constraints:
            if c.is_constant_only():
                if self._evaluate_constant_constraint(c):
                    continue
                else:
                    simplified.constraints = [c]
                    return simplified

            substituted = substitute_constant(c, bound_map)
            if substituted is not None:
                simplified.constraints.append(substituted)

        return simplified

    def _evaluate_constant_constraint(self, c: LinearConstraint) -> bool:
        """求值纯常量约束, 返回True=满足(可丢弃), False=矛盾(系统不可行)."""
        val = c.constant
        if c.operator == "<=":
            return val <= 0
        elif c.operator == "<":
            return val < 0
        elif c.operator == ">=":
            return val >= 0
        elif c.operator == ">":
            return val > 0
        elif c.operator == "==":
            return val == 0
        return True

    def _fm_boundary_refine(
        self,
        sys: ConstraintSystem,
    ) -> Optional[tuple[SolverVerdict, str]]:
        """FM边界推理: 从残差约束推导变量边界, 补充Step2/3无法判定的场景.

        当prove_safe和prove_overflow都返回None时, 尝试:
        1. 计算write_end的符号表达式
        2. 对非write_end变量做FM消元
        3. 从残差约束提取单变量边界
        4. 用边界评估write_end的[lo, hi]区间
        """
        alloc_usable = _compute_usable_size(sys, self._platform)
        if alloc_usable <= 0:
            return None

        write_end_expr, write_end_desc = _compute_write_end(sys)
        if write_end_expr is None:
            return None

        from core.cj_fm_boundary import fm_bound_refine
        return fm_bound_refine(sys, write_end_expr, alloc_usable)


def solve_candidate(
    candidate,
    ir_lines: list[str],
    decompiled_text: str = "",
    platform: str = "x86_64",
) -> tuple[SolverResult, ConstraintSystem]:
    """便捷接口: 对单个候选构建约束系统并求解.

    返回 (solver_result, constraint_system).
    求解顺序: 仿射关系证明 → 约束收集 → 区间域增强 → FM消元.
    """
    from core.cj_affine_bridge import try_affine_proof
    from core.cj_constraint_collector import collect_constraints
    from core.cj_interval_domain import interval_refine

    affine_result = try_affine_proof(candidate, ir_lines, platform)
    if affine_result is not None:
        sys_empty = ConstraintSystem(mnemonic=candidate.overflow_store.mnemonic)
        return affine_result, sys_empty

    sys = collect_constraints(candidate, ir_lines, decompiled_text)

    alloc_pc = candidate.alloc_site.pc
    write_pc = candidate.overflow_store.pc
    sys = interval_refine(
        sys, ir_lines, decompiled_text, alloc_pc, write_pc)

    solver = ConstraintJoinSolver(platform)
    result = solver.solve(sys)

    if result.verdict == SolverVerdict.INCONCLUSIVE:
        from core.cj_bvf_solver_bridge import try_bvf_proof
        bvf_result = try_bvf_proof(candidate, ir_lines, platform)
        if bvf_result is not None:
            return bvf_result, sys

        from core.cj_pcbvf_bridge import try_pcbvf_proof
        pcbvf_result = try_pcbvf_proof(candidate, ir_lines, platform)
        if pcbvf_result is not None:
            return pcbvf_result, sys

        from core.caawp_bridge import try_caawp_proof
        caawp_result = try_caawp_proof(candidate, ir_lines, platform)
        if caawp_result is not None:
            return caawp_result, sys

    if (result.verdict == SolverVerdict.PROVEN_SAFE
            and candidate.overflow_store.offset_is_dynamic):
        from core.cj_bvf_solver_bridge import try_bvf_proof
        bvf_result = try_bvf_proof(candidate, ir_lines, platform)
        if bvf_result is not None and \
                bvf_result.verdict == SolverVerdict.PROVEN_OVERFLOW:
            return bvf_result, sys

    return result, sys


def solve_candidate_path_sensitive(
    candidate,
    ir_lines: list[str],
    decompiled_text: str = "",
    platform: str = "x86_64",
):
    """路径敏感求解接口 — PS-CJ.

    当反编译文本可用时, 使用路径敏感约束联结求解器;
    回退到全局CJ当路径枚举失败.
    返回 (psj_result, path_systems).
    """
    from core.ps_cj_solver import PathSensitiveCJSolver
    from core.ps_cj_path_collector import collect_path_sensitive_constraints
    solver = PathSensitiveCJSolver(platform)
    path_systems = collect_path_sensitive_constraints(
        candidate, ir_lines, decompiled_text)
    result = solver.solve_path_sensitive(
        candidate, ir_lines, decompiled_text)
    return result, path_systems


__all__ = [
    'ConstraintJoinSolver', 'solve_candidate',
    'solve_candidate_path_sensitive',
]
