"""路径约束收集验证 pipeline 集成模块 — 将路径约束收集验证求解器作为前置约束验证层接入格式串检测管线。
若路径约束收集验证判定 SAFE → 过滤候选; VULN/UNCERTAIN → 保留交 格式说明符约束系统 (Format Specifier Constraint System) 评分; 路径约束收集验证不替代 格式说明符约束系统 (Format Specifier Constraint System)。"""

from typing import Dict, List, Tuple

from core.path_constraint_constraint_types import FcpvCandidate, SafetyLabel
from core.path_constraint_safety_solver import FcpvSafetySolver


def run_fcpv(source: str) -> List[FcpvCandidate]:
    """运行路径约束收集验证求解器, 返回候选列表 (含安全标签)."""
    solver = FcpvSafetySolver()
    return solver.solve(source)


def fcpv_filter(source: str) -> Dict:
    """路径约束收集验证过滤入口: 返回结构化检测结果.

    返回:
        {
            "candidates": [...],  # 全部候选
            "vuln": [...],        # 路径约束收集验证判定 VULN
            "safe": [...],        # 路径约束收集验证判定 SAFE (过滤)
            "uncertain": [...],   # 路径约束收集验证判定 UNCERTAIN
            "has_vuln": bool,     # 是否存在 VULN
            "summary": str,
        }
    """
    candidates = run_fcpv(source)
    solver = FcpvSafetySolver()
    vuln, safe, uncertain = solver.filter_vuln(candidates)

    return {
        "candidates": candidates,
        "vuln": vuln,
        "safe": safe,
        "uncertain": uncertain,
        "has_vuln": len(vuln) > 0,
        "summary": f"路径约束收集验证: {len(vuln)} VULN, {len(safe)} SAFE, "
                   f"{len(uncertain)} UNCERTAIN (of {len(candidates)} candidates)",
    }


def fcpv_enhance_fscs(source: str) -> Tuple[List[FcpvCandidate], List]:
    """路径约束收集验证增强 格式说明符约束系统 (Format Specifier Constraint System): 返回路径约束收集验证结果 + 需 格式说明符约束系统 (Format Specifier Constraint System) 评分的候选.

    路径约束收集验证 SAFE 的候选无需 格式说明符约束系统 (Format Specifier Constraint System) 评分 (已过滤).
    路径约束收集验证 VULN/UNCERTAIN 的候选交 格式说明符约束系统 (Format Specifier Constraint System) 评分.
    """
    candidates = run_fcpv(source)
    solver = FcpvSafetySolver()
    vuln, safe, uncertain = solver.filter_vuln(candidates)
    need_fscs = vuln + uncertain
    return candidates, need_fscs


__all__ = ['run_fcpv', 'fcpv_filter', 'fcpv_enhance_fscs']
