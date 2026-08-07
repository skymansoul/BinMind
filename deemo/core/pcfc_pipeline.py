"""
PCFC管线集成 — 将路径条件感知过滤接入FCPV格式串检测管线.

集成位置: FCPV求解之后, 对VULN判定执行PCFC过滤.
集成策略:
  1. FcpvSafetySolver.solve -> 获取VULN candidates
  2. PCFC提取sink路径条件 -> 过滤路径不可达的误报
  3. 返回过滤后的candidates

PCFC是FCPV的正交补充:
  FCPV回答: "格式串参数是否从外部输入可达?" (taint可达性)
  PCFC回答: "sink调用是否在可达路径上?" (路径可达性)
"""
from typing import Any, Dict, List

from core.fcpv_constraint_types import FcpvCandidate, SafetyLabel
from core.fcpv_safety_solver import FcpvSafetySolver
from core.pcfc_verifier import filter_fmt_by_pcfc


def run_fcpv_pcfc(source: str) -> List[FcpvCandidate]:
    """FCPV + PCFC联合格式串检测.

    先用FCPV判定, 再用PCFC过滤路径不可达的VULN.
    """
    solver = FcpvSafetySolver()
    candidates = solver.solve(source)

    filtered, stats = filter_fmt_by_pcfc(source, candidates)
    return filtered


def fcpv_pcfc_filter(source: str) -> Dict[str, Any]:
    """FCPV+PCFC过滤入口: 返回结构化检测结果.

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
            f"FCPV+PCFC: {len(vuln)} VULN, {len(safe)} SAFE, "
            f"{len(uncertain)} UNCERTAIN "
            f"(of {len(candidates)} candidates)"),
    }


__all__ = ['run_fcpv_pcfc', 'fcpv_pcfc_filter']
