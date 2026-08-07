"""
FCPV pipeline 集成模块 — 将 FCPV 求解器接入格式串检测管线.

集成位置: 在 FSCS 评分之前, 作为源码级约束验证层.
若 FCPV 判定 SAFE → 过滤候选, 无需 FSCS 评分.
若 FCPV 判定 VULN → 保留, FSCS 可补充评分.
若 FCPV 判定 UNCERTAIN → 保留, 交 FSCS 评分决定.

设计决策: FCPV 不替代 FSCS, 而是作为前置约束验证器.
FSCS 评分作为后处理精化 (补充 exploitability/impact 量化).
"""

from typing import Dict, List, Tuple

from core.fcpv_constraint_types import FcpvCandidate, SafetyLabel
from core.fcpv_safety_solver import FcpvSafetySolver


def run_fcpv(source: str) -> List[FcpvCandidate]:
    """运行 FCPV 求解器, 返回候选列表 (含安全标签)."""
    solver = FcpvSafetySolver()
    return solver.solve(source)


def fcpv_filter(source: str) -> Dict:
    """FCPV 过滤入口: 返回结构化检测结果.

    返回:
        {
            "candidates": [...],  # 全部候选
            "vuln": [...],        # FCPV 判定 VULN
            "safe": [...],        # FCPV 判定 SAFE (过滤)
            "uncertain": [...],   # FCPV 判定 UNCERTAIN
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
        "summary": f"FCPV: {len(vuln)} VULN, {len(safe)} SAFE, "
                   f"{len(uncertain)} UNCERTAIN (of {len(candidates)} candidates)",
    }


def fcpv_enhance_fscs(source: str) -> Tuple[List[FcpvCandidate], List]:
    """FCPV 增强 FSCS: 返回 FCPV 结果 + 需 FSCS 评分的候选.

    FCPV SAFE 的候选无需 FSCS 评分 (已过滤).
    FCPV VULN/UNCERTAIN 的候选交 FSCS 评分.
    """
    candidates = run_fcpv(source)
    solver = FcpvSafetySolver()
    vuln, safe, uncertain = solver.filter_vuln(candidates)
    need_fscs = vuln + uncertain
    return candidates, need_fscs


__all__ = ['run_fcpv', 'fcpv_filter', 'fcpv_enhance_fscs']
