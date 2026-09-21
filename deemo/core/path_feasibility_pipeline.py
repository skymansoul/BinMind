"""路径可行性检查管线集成 — 将路径条件感知过滤接入路径约束收集验证格式串检测管线。
路径约束收集验证求解后对VULN判定执行路径可行性检查过滤：路径约束收集验证回答taint可达性，
路径可行性检查回答sink调用是否在可达路径上（过滤路径不可达的误报）。"""
from typing import Any, Dict, List

from core.path_constraint_constraint_types import FcpvCandidate, SafetyLabel
from core.path_constraint_safety_solver import FcpvSafetySolver
from core.path_feasibility_verifier import filter_fmt_by_pcfc


def run_fcpv_pcfc(source: str) -> List[FcpvCandidate]:
    """路径约束收集验证 + 路径可行性检查联合格式串检测.

    先用路径约束收集验证判定, 再用路径可行性检查过滤路径不可达的VULN.
    """
    solver = FcpvSafetySolver()
    candidates = solver.solve(source)

    filtered, stats = filter_fmt_by_pcfc(source, candidates)
    return filtered


def fcpv_pcfc_filter(source: str) -> Dict[str, Any]:
    """路径约束收集验证+路径可行性检查过滤入口: 返回结构化检测结果.

    返回:
        {
            "candidates": [...],
            "vuln": [...],
            "safe": [...],
            "uncertain": [...],
            "has_vuln": bool,
            "summary": str,
        }
    """
    candidates = run_fcpv_pcfc(source)
    solver = FcpvSafetySolver()
    vuln, safe, uncertain = solver.filter_vuln(candidates)

    return {
        "candidates": candidates,
        "vuln": vuln,
        "safe": safe,
        "uncertain": uncertain,
        "has_vuln": len(vuln) > 0,
        "summary": (
            f"路径约束收集验证+路径可行性检查: {len(vuln)} VULN, {len(safe)} SAFE, "
            f"{len(uncertain)} UNCERTAIN "
            f"(of {len(candidates)} candidates)"),
    }


__all__ = ['run_fcpv_pcfc', 'fcpv_pcfc_filter']
