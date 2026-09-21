"""路径敏感约束联结求解器, 路径敏感约束求解核心求解模块: 每条CFG路径独立FM消元+安全性证明, 保守融合.
融合: 所有可行路径SAFE→过滤; 任一可行路径OVERFLOW→保留; 任意INCONCLUSIVE→保守保留; 全部不可行→回退全局约束求解.
路径来自简化CFG(正则+启发式), 有界枚举(max 128), 无路径间约束传播。理论: Reps-Horwitz-Sagiv 路径可达性。"""
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from core.constraint_constraint_types import (
    ConstraintType, SolverVerdict, LinearConstraint,
    ConstraintSystem, SolverResult,
)
from core.constraint_solver import ConstraintJoinSolver
from core.constraint_safety_prover import prove_write_safety, prove_overflow
from core.path_constraint_cfg_builder import CFGPath
from core.path_constraint_path_collector import collect_path_sensitive_constraints
from core.heap_overflow_detector import HeapOverflowCandidate


@dataclass
class PathSolverResult:
    """单条路径的求解结果。"""
    verdict: SolverVerdict = SolverVerdict.INCONCLUSIVE
    reason: str = ""
    path_feasible: bool = True
    path_description: str = ""
    constraints_count: int = 0
    proof_chain: List[str] = field(default_factory=list)


@dataclass
class PSJResult:
    """路径敏感求解器的整体结果。"""
    verdict: SolverVerdict = SolverVerdict.INCONCLUSIVE
    reason: str = ""
    paths_analyzed: int = 0
    paths_feasible: int = 0
    paths_safe: int = 0
    paths_overflow: int = 0
    paths_inconclusive: int = 0
    paths_infeasible: int = 0
    confidence_delta: float = 0.0
    proof_chain: List[str] = field(default_factory=list)
    fallback_global_cj: bool = False


class PathSensitiveCJSolver:
    """路径敏感约束联结求解器。

    接口与ConstraintJoinSolver.solve()兼容, 可作为替代。
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        self._global_solver = ConstraintJoinSolver(platform)

    def solve(
        self,
        sys: ConstraintSystem,
    ) -> SolverResult:
        """全局约束求解 (Constraint Solving) 回退接口 - 无路径信息时使用。"""
        return self._global_solver.solve(sys)

    def solve_path_sensitive(
        self,
        candidate: HeapOverflowCandidate,
        ir_lines: list[str],
        decompiled_text: str = "",
    ) -> PSJResult:
        """路径敏感求解: 枚举路径-逐路径约束求解 (Constraint Solving)-保守融合。"""
        path_systems = collect_path_sensitive_constraints(
            candidate, ir_lines, decompiled_text)

        if len(path_systems) <= 1:
            return self._fallback_global(
                candidate, ir_lines, decompiled_text)

        path_results: List[PathSolverResult] = []
        for path, psys in path_systems:
            pr = self._solve_single_path(path, psys)
            path_results.append(pr)

        return self._fuse_results(path_results)

    def _solve_single_path(
        self,
        path: CFGPath,
        psys: ConstraintSystem,
    ) -> PathSolverResult:
        """对单条路径的约束系统做约束求解 (Constraint Solving) 求解。"""
        if not path.is_feasible:
            return PathSolverResult(
                verdict=SolverVerdict.INCONCLUSIVE,
                reason="path infeasible (guard contradiction)",
                path_feasible=False,
                path_description=path.description,
                constraints_count=len(psys.constraints),
                proof_chain=["Path infeasible: guard constraints "
                             "contradict each other"],
            )

        simplified = self._global_solver._simplify(psys)

        safety = prove_write_safety(simplified, self._platform)
        if safety is not None:
            return PathSolverResult(
                verdict=SolverVerdict.PROVEN_SAFE,
                reason=safety.reason,
                path_description=path.description,
                constraints_count=len(simplified.constraints),
                proof_chain=safety.proof_chain,
            )

        overflow = prove_overflow(simplified, self._platform)
        if overflow is not None:
            return PathSolverResult(
                verdict=SolverVerdict.PROVEN_OVERFLOW,
                reason=overflow.reason,
                path_description=path.description,
                constraints_count=len(simplified.constraints),
                proof_chain=overflow.proof_chain,
            )

        fm_result = self._global_solver._fm_boundary_refine(simplified)
        if fm_result is not None:
            verdict, reason = fm_result
            return PathSolverResult(
                verdict=verdict,
                reason=reason,
                path_description=path.description,
                constraints_count=len(simplified.constraints),
                proof_chain=[f"FM boundary: {reason}"],
            )

        return PathSolverResult(
            verdict=SolverVerdict.INCONCLUSIVE,
            reason=f"insufficient constraints: "
                   f"{len(simplified.constraints)} constraints",
            path_description=path.description,
            constraints_count=len(simplified.constraints),
        )

    def _fuse_results(
        self,
        path_results: List[PathSolverResult],
    ) -> PSJResult:
        """保守融合所有路径的判定结果。

        融合规则:
          - 任一可行路径OVERFLOW - OVERFLOW (保留候选)
          - 所有可行路径SAFE - SAFE (过滤候选)
          - 否则 - INCONCLUSIVE (保守保留)
          - 全部不可行 - 回退全局约束求解 (Constraint Solving)
        """
        result = PSJResult()
        result.paths_analyzed = len(path_results)

        feasible = [r for r in path_results if r.path_feasible]
        infeasible = [r for r in path_results if not r.path_feasible]

        result.paths_feasible = len(feasible)
        result.paths_infeasible = len(infeasible)

        if not feasible:
            result.fallback_global_cj = True
            result.verdict = SolverVerdict.INCONCLUSIVE
            result.reason = "all paths infeasible, fallback to global CJ"
            return result

        for r in feasible:
            if r.verdict == SolverVerdict.PROVEN_SAFE:
                result.paths_safe += 1
            elif r.verdict == SolverVerdict.PROVEN_OVERFLOW:
                result.paths_overflow += 1
            else:
                result.paths_inconclusive += 1

        if result.paths_overflow > 0:
            result.verdict = SolverVerdict.PROVEN_OVERFLOW
            ovf_path = next(
                r for r in feasible
                if r.verdict == SolverVerdict.PROVEN_OVERFLOW)
            result.reason = (
                f"overflow on {result.paths_overflow}/{result.paths_feasible}"
                f" feasible paths: {ovf_path.reason}")
            result.confidence_delta = 0.20
            result.proof_chain = [
                f"PS-CJ: {result.paths_feasible} feasible paths, "
                f"{result.paths_overflow} prove overflow",
                f"Overflow path: {ovf_path.path_description}",
            ] + ovf_path.proof_chain
        elif result.paths_inconclusive == 0 and result.paths_safe > 0:
            result.verdict = SolverVerdict.PROVEN_SAFE
            result.reason = (
                f"all {result.paths_safe} feasible paths prove safe "
                f"({result.paths_infeasible} infeasible paths excluded)")
            result.confidence_delta = -0.45
            result.proof_chain = [
                f"PS-CJ: {result.paths_feasible} feasible paths, "
                f"all prove safe",
                f"Path breakdown: {result.paths_safe} safe, "
                f"{result.paths_infeasible} infeasible",
            ]
        else:
            result.verdict = SolverVerdict.INCONCLUSIVE
            result.reason = (
                f"{result.paths_inconclusive}/{result.paths_feasible} "
                f"paths inconclusive "
                f"({result.paths_safe} safe, "
                f"{result.paths_overflow} overflow, "
                f"{result.paths_infeasible} infeasible)")

        return result

    def _fallback_global(
        self,
        candidate: HeapOverflowCandidate,
        ir_lines: list[str],
        decompiled_text: str,
    ) -> PSJResult:
        """回退到全局约束求解 (Constraint Solving) 求解。"""
        from core.constraint_constraint_collector import collect_constraints
        sys = collect_constraints(candidate, ir_lines, decompiled_text)
        global_result = self._global_solver.solve(sys)

        return PSJResult(
            verdict=global_result.verdict,
            reason=global_result.reason,
            paths_analyzed=1,
            paths_feasible=1,
            paths_safe=(
                1 if global_result.verdict == SolverVerdict.PROVEN_SAFE
                else 0),
            paths_overflow=(
                1 if global_result.verdict == SolverVerdict.PROVEN_OVERFLOW
                else 0),
            paths_inconclusive=(
                1 if global_result.verdict == SolverVerdict.INCONCLUSIVE
                else 0),
            confidence_delta=global_result.confidence_delta,
            proof_chain=global_result.proof_chain,
            fallback_global_cj=True,
        )


def solve_candidate_path_sensitive(
    candidate: HeapOverflowCandidate,
    ir_lines: list[str],
    decompiled_text: str = "",
    platform: str = "x86_64",
) -> Tuple[PSJResult, List[Tuple[CFGPath, ConstraintSystem]]]:
    """便捷接口: 路径敏感求解单个候选。

    返回 (psj_result, path_systems)。
    """
    solver = PathSensitiveCJSolver(platform)
    path_systems = collect_path_sensitive_constraints(
        candidate, ir_lines, decompiled_text)
    result = solver.solve_path_sensitive(
        candidate, ir_lines, decompiled_text)
    return result, path_systems


__all__ = [
    'PathSolverResult', 'PSJResult',
    'PathSensitiveCJSolver',
    'solve_candidate_path_sensitive',
]
