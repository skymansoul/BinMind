# mutation_predictor — 交互感知的加固措施优化
# 在给定实施预算约束下，选择最大化风险降幅的加固措施组合。
# 使用贪心边际效益（每单位成本的风险降幅）选择，天然近似次模优化。

import math
from typing import Dict, List, Tuple, Optional


_MUTATIONS = {
    "enable_canary":       {"cost": 2, "risk_reduction": 0.12, "category": "compile_time"},
    "enable_pie":          {"cost": 2, "risk_reduction": 0.08, "category": "compile_time"},
    "enable_full_relro":   {"cost": 1, "risk_reduction": 0.10, "category": "compile_time"},
    "enable_nx":           {"cost": 1, "risk_reduction": 0.10, "category": "compile_time"},
    "enable_fortify":      {"cost": 2, "risk_reduction": 0.05, "category": "compile_time"},
    "enable_cfg":          {"cost": 3, "risk_reduction": 0.08, "category": "compile_time"},
    "remove_dangerous_imports": {"cost": 5, "risk_reduction": 0.15, "category": "refactor"},
    "eliminate_rwx":       {"cost": 4, "risk_reduction": 0.18, "category": "refactor"},
    "add_guard_pages":     {"cost": 1, "risk_reduction": 0.06, "category": "compile_time"},
}

# 两两交互效应矩阵: (mut_a, mut_b) -> synergy_factor
# >0 正交互 (1+1>2)，<0 负交互 (冗余)
_INTERACTIONS = {
    ("enable_pie","enable_full_relro"): 0.25,
    ("enable_canary","enable_fortify"): 0.20,
    ("enable_nx","eliminate_rwx"): 0.15,
    ("enable_cfg","enable_pie"): 0.18,
    ("remove_dangerous_imports","enable_canary"): -0.05,
    ("add_guard_pages","enable_nx"): 0.10,
}


def _interaction_bonus(selected: List[str], candidate: str) -> float:
    bonus = 0.0
    for s in selected:
        key = (s, candidate)
        rev = (candidate, s)
        bonus += _INTERACTIONS.get(key, _INTERACTIONS.get(rev, 0.0))
    return bonus


def predict_mutations(
    binary_analysis: Dict,
    candidate_mutations: List[str] = None,
    budget: int = 10,
) -> Dict:
    """交互感知的加固措施优化。在 budget 约束下最大化风险降幅。"""
    cs = binary_analysis.get("checksec", {})
    exploit = binary_analysis.get("exploit_chain", binary_analysis.get("exploit", {}))

    # 过滤已启用的措施，计算各措施的实际边际效益
    available = []
    all_names = candidate_mutations or list(_MUTATIONS.keys())
    for name in all_names:
        mut = _MUTATIONS.get(name)
        if not mut: continue
        if _already_enabled(name, cs): continue
        reduction = mut["risk_reduction"]
        # exploitability 调制: 高 exploit 的二进制从加固中获益更多
        ei = exploit.get("exploitability_index", 30.0)
        if ei > 50:
            reduction *= 1.3
        elif ei < 15:
            reduction *= 0.7
        available.append({"name": name, "cost": mut["cost"],
                         "reduction": round(reduction, 4),
                         "category": mut["category"],
                         "marginal_benefit_per_cost": round(reduction / mut["cost"], 4)})

    if not available:
        return {"recommendations": [], "total_reduction": 0.0,
                "total_cost": 0, "budget": budget,
                "optimization_method": "greedy_marginal_benefit"}

    # 贪心选择: 每次选边际效益/成本比最高的措施
    # 选后重算交互效应
    selected = []
    remaining_budget = budget

    while remaining_budget > 0 and available:
        best_idx, best_score = -1, -1.0
        for i, item in enumerate(available):
            if item["cost"] > remaining_budget:
                continue
            bonus = _interaction_bonus([s["name"] for s in selected], item["name"])
            score = (item["reduction"] + bonus) / item["cost"]
            if score > best_score:
                best_score = score
                best_idx = i

        if best_idx < 0:
            break

        chosen = available.pop(best_idx)
        bonus = _interaction_bonus([s["name"] for s in selected], chosen["name"])
        chosen["interaction_bonus"] = round(bonus, 4)
        chosen["effective_reduction"] = round(chosen["reduction"] + bonus, 4)
        selected.append(chosen)
        remaining_budget -= chosen["cost"]

    total_reduction = sum(s["effective_reduction"] for s in selected)
    # submodular diminishing returns: 后期选择的实际效益衰减 10%
    if len(selected) > 3:
        for i in range(3, len(selected)):
            selected[i]["effective_reduction"] = round(selected[i]["effective_reduction"] * 0.90, 4)
        total_reduction = round(sum(s["effective_reduction"] for s in selected), 4)

    base_risk = exploit.get("exploitability_index", 30.0) / 100.0
    predicted_risk = round(max(0.0, base_risk - total_reduction), 4)

    return {"recommendations": selected,
            "total_risk_reduction": total_reduction,
            "total_cost": budget - remaining_budget,
            "budget": budget,
            "remaining_budget": remaining_budget,
            "current_risk": round(base_risk, 4),
            "predicted_risk": predicted_risk,
            "optimization_method": "greedy_marginal_benefit_with_interactions",
            "interaction_pairs_found": sum(1 for s in selected if s.get("interaction_bonus", 0) > 0.01)}


def _already_enabled(name: str, checksec: Dict) -> bool:
    checks = {"enable_canary": "canary", "enable_pie": "pie", "enable_nx": "nx",
              "enable_full_relro": "relro", "enable_fortify": "fortify",
              "enable_cfg": "cfg"}
    key = checks.get(name)
    if not key: return False
    val = checksec.get(key)
    if isinstance(val, bool): return val
    if isinstance(val, str): return "full" in val.lower() or val.lower() == "true"
    return False
