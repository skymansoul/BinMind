"""
Function-level vulnerability risk ranking.

Ranks analyzed functions by multi-dimensional risk scoring to produce a
"Top-N functions for manual review" list. Addresses the gap where AI analysis
results flow into reports but lack targeted prioritization.

Scoring dimensions:
  1. Dangerous function density (0-30): count * severity weight of dangerous calls
  2. Input exposure (0-25): parameters sourced from read/recv/fgets etc.
  3. Protection gaps (0-20): missing mitigations (No Canary +10, No NX +10)
  4. LLM confidence (0-15): bonus when LLM flagged vulnerabilities
  5. Call graph position (0-10): criticality (directly called by main > deep call)

Total 0-100. Used for ranking, not absolute judgment — low-scoring functions
may still be vulnerable; high-scoring ones are the best starting points.

References:
  - Grieco et al., 2016, IEEE S&P, "Toward Large-Scale Vulnerability Discovery"
  - Lin et al., 2020, CCS, "Software Vulnerability Discovery via Learning
    Multi-Dimensional Hierarchical Code Feature"
"""


import logging
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# 危险函数的严重度权重——与 static_analysis.DANGEROUS_FUNCTIONS 的映射
_SEVERITY_WEIGHT = {
    "Critical": 10, "High": 7, "Medium": 4, "Low": 1,
}

# 来自外部输入的函数——其参数可能是攻击面
_INPUT_SOURCES = {
    "read", "recv", "recvfrom", "fgets", "gets", "scanf",
    "fread", "getline", "getchar", "argv", "argc",
}

# 直接由 main 调用的函数加分（调用图根节点直连）
_CALLGRAPH_ROOT_BONUS = 5


def rank_functions(
    decomp_results: List[Dict[str, Any]],
    dangerous_imports: Optional[List[Dict[str, Any]]] = None,
    checksec: Optional[Dict[str, Any]] = None,
    call_graph: Optional[Dict[str, List[str]]] = None,
    top_n: int = 10,
) -> List[Dict[str, Any]]:
    """
    对分析结果中的函数按风险评分排序。

    Args:
        decomp_results:   pipeline 的 decomp_analysis 输出——每个元素包含
                          function/function_name + analysis.vulnerabilities
        dangerous_imports: static_analysis.scan_imports() 的结果
        checksec:          detect_checksec() 的结果
        call_graph:        cfg_extractor.extract_cfg()["call_graph"] 的结果
        top_n:             返回 Top-N 个函数

    Returns:
        排序后的函数风险列表，每个元素包含函数名、总分、各维度得分和排序理由
    """
    # 构建危险函数名→严重度的快速查表
    danger_map: Dict[str, str] = {}
    if dangerous_imports:
        for imp in dangerous_imports:
            name = imp.get("function", "")
            if "." in name:
                name = name.rsplit(".", 1)[-1]
            danger_map[name] = imp.get("severity", "Medium")

    # 构建 main 可达的直接调用者集合
    main_callees: set = set()
    if call_graph and "main" in call_graph:
        main_callees = set(call_graph["main"])

    scored = []
    for result in decomp_results:
        # 兼容两种格式: {function, ...} 或 {function_name, analysis: {vulnerabilities}}
        fname = result.get("function_name") or result.get("function", "?")
        analysis = result.get("analysis", result)
        vulns = analysis.get("vulnerabilities", [])
        pseudo = analysis.get("pseudocode", result.get("pseudocode", ""))

        score_detail = _score_function(
            fname, vulns, pseudo, danger_map, checksec, main_callees,
        )
        total = sum(score_detail.values())

        if total > 0:
            scored.append({
                "function": fname,
                "total_score": total,
                "score_detail": score_detail,
                "vuln_count": len(vulns),
                "vuln_types": list({v.get("type", "?") for v in vulns}),
                "reason": _describe_score(score_detail),
            })

    # 按总分降序排序
    scored.sort(key=lambda s: -s["total_score"])

    _log.info("Risk ranking: top function = %s (score=%d)",
              scored[0]["function"] if scored else "none",
              scored[0]["total_score"] if scored else 0)

    return scored[:top_n]



def _score_function(
    fname: str,
    vulns: List[Dict[str, Any]],
    pseudocode: str,
    danger_map: Dict[str, str],
    checksec: Optional[Dict[str, Any]],
    main_callees: set,
) -> Dict[str, int]:
    """计算单个函数的五维风险得分。"""
    scores = {
        "dangerous_calls": 0,
        "input_exposure": 0,
        "protection_gaps": 0,
        "llm_confidence": 0,
        "callgraph_position": 0,
    }

    # 1. 危险函数密度
    for func_name, severity in danger_map.items():
        if func_name in pseudocode:
            weight = _SEVERITY_WEIGHT.get(severity, 2)
            scores["dangerous_calls"] = min(30, scores["dangerous_calls"] + weight)

    # system/popen/execve 是最高风险的调用，额外加分
    if "system" in pseudocode or "popen" in pseudocode or "execve" in pseudocode:
        scores["dangerous_calls"] = min(30, scores["dangerous_calls"] + 5)

    # 2. 输入暴露面
    for source in _INPUT_SOURCES:
        if source in pseudocode:
            scores["input_exposure"] = min(25, scores["input_exposure"] + 5)
            if scores["input_exposure"] >= 25:
                break

    # 3. 保护缺口
    if checksec:
        if not checksec.get("canary", True):
            scores["protection_gaps"] += 10
        if not checksec.get("nx", True):
            scores["protection_gaps"] += 5
        if not checksec.get("pie", True):
            scores["protection_gaps"] += 5
    scores["protection_gaps"] = min(20, scores["protection_gaps"])

    # 4. LLM 置信度
    if vulns:
        max_sev = max(
            (_SEVERITY_WEIGHT.get(v.get("severity", "Low"), 1) for v in vulns),
            default=1,
        )
        scores["llm_confidence"] = min(15, len(vulns) * 3 + max_sev // 2)

    # 5. 调用图位置
    if fname in main_callees:
        scores["callgraph_position"] = _CALLGRAPH_ROOT_BONUS
    if fname == "main":
        scores["callgraph_position"] = 3  # main 本身通常只是入口

    return scores


def _describe_score(detail: Dict[str, int]) -> str:
    """将得分分解为人类可读的理由文本。"""
    parts = []
    if detail["dangerous_calls"] >= 15:
        parts.append("high density of dangerous calls")
    elif detail["dangerous_calls"] >= 5:
        parts.append("contains exploitable imports")

    if detail["input_exposure"] >= 15:
        parts.append("direct external input")
    elif detail["input_exposure"] >= 5:
        parts.append("possible input surface")

    if detail["protection_gaps"] >= 10:
        parts.append("weak binary hardening")
    elif detail["protection_gaps"] >= 5:
        parts.append("partial hardening only")

    if detail["llm_confidence"] >= 8:
        parts.append("LLM-confirmed vulnerabilities")
    elif detail["llm_confidence"] >= 3:
        parts.append("LLM-flagged suspicious patterns")

    if detail["callgraph_position"] >= _CALLGRAPH_ROOT_BONUS:
        parts.append("directly reachable from main")

    return "; ".join(parts) if parts else "low risk — routine review"
