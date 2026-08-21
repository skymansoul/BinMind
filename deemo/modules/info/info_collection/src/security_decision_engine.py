# security_decision_engine — 贝叶斯决策框架
# 将分析信号转化为后验风险分布，在风险-置信度空间中为每个决策动作
# 计算期望效用，选择最大期望效用的动作。效用函数编码了假阳性/假阴性的
# 相对代价。

import math
from typing import Dict, List, Tuple, Optional


# 决策动作的效用函数参数
# 每个动作为 (risk_weight, false_positive_cost, false_negative_cost)
# risk_weight: 该动作对风险信号的敏感度（高→低风险时也倾向于选中）
# false_positive_cost: 误报代价（高→该动作的阈值更高）
# false_negative_cost: 漏报代价（高→该动作的阈值更低）
_ACTION_PARAMS = {
    "BLOCK":        (0.85, 0.30, 0.70),
    "QUARANTINE":   (0.65, 0.45, 0.55),
    "INVESTIGATE":  (0.45, 0.60, 0.40),
    "MONITOR":      (0.25, 0.75, 0.25),
    "ALLOW":        (0.10, 0.90, 0.10),
}


def _extract_risk_signals(analysis: Dict) -> Dict[str, float]:
    """从分析信号中提取归一化风险指标。每个指标缩放到 [0,1]。"""
    s = {}
    exploit = analysis.get("exploit", {})
    s["exploit"] = exploit.get("exploitability_index", 0.0) / 100.0

    ttp = analysis.get("ttp", {})
    s["ttp_completeness"] = ttp.get("kill_chain_completeness", 0.0)
    s["ttp_count"] = min(ttp.get("boosted_ttp_count", 0) / 10.0, 1.0)

    evasion = analysis.get("evasion", {})
    s["evasion"] = evasion.get("evasion_score", 0.0)

    reach = analysis.get("reachability", {})
    s["reachability"] = reach.get("risk_score", 0.0)

    cti = analysis.get("cti", {})
    s["cti_confidence"] = cti.get("attribution_confidence", 0.0)

    obf = analysis.get("obfuscation", {})
    top = obf.get("top_match", {}) if isinstance(obf, dict) else {}
    s["obfuscation"] = top.get("confidence", 0.0) if isinstance(top, dict) else 0.0

    cap = analysis.get("capability", {})
    role = cap.get("binary_role", "")
    s["malicious_role"] = 0.90 if role in ("RANSOMWARE","C2_IMPLANT","EVASIVE_TOOL") else (
        0.50 if role in ("TROJAN_APPLICATION","DATA_EXFILTRATOR") else 0.10)

    bypass = analysis.get("bypass_likelihood", {})
    s["bypass"] = bypass.get("overall_bypass_score", 0.0)

    return s


def _compute_posterior_risk(signals: Dict[str, float]) -> Tuple[float, float]:
    """使用对数几率加权融合计算后验风险均值和精度。
    每个信号视为独立的 log-odds 证据，融合为单一后验均值。
    """
    log_odds_sum = 0.0
    weight_sum = 0.0

    weights = {"exploit": 3.0, "ttp_completeness": 2.5, "ttp_count": 1.5,
               "evasion": 2.0, "reachability": 2.0, "cti_confidence": 3.0,
               "obfuscation": 1.5, "malicious_role": 3.5, "bypass": 2.0}

    for key, val in signals.items():
        w = weights.get(key, 1.0)
        if val > 0.01:
            odds = val / max(1.0 - val, 0.01)
            log_odds_sum += math.log(max(odds, 0.01)) * w
            weight_sum += w

    if weight_sum < 0.5:
        return (0.10, 0.5)

    mean_log_odds = log_odds_sum / weight_sum
    posterior_risk = 1.0 / (1.0 + math.exp(-mean_log_odds))

    # 精度: 与信号一致性相关（信号方差小→精度高）
    risk_vals = [v for v in signals.values() if v > 0.01]
    if len(risk_vals) >= 2:
        variance = sum((v - posterior_risk) ** 2 for v in risk_vals) / len(risk_vals)
        precision = 1.0 / max(variance, 0.001)
        precision = min(precision, 20.0) / 20.0
    else:
        precision = 0.3

    return (round(posterior_risk, 4), round(precision, 4))


def _expected_utility(action: str, risk: float, precision: float,
                      thresholds: Dict[str, float] = None) -> float:
    """计算给定动作在 (risk, precision) 下的期望效用。"""
    rw, fpc, fnc = _ACTION_PARAMS[action]
    t = thresholds or {}

    # 基础效用: 风险越高，越倾向干预动作
    # 各动作有各自的"舒适区"——风险在此范围内时效用最高
    comfort_zones = {"BLOCK": (0.70, 1.0), "QUARANTINE": (0.45, 0.85),
                     "INVESTIGATE": (0.25, 0.65), "MONITOR": (0.10, 0.45),
                     "ALLOW": (0.0, 0.20)}
    lo, hi = comfort_zones.get(action, (0.0, 1.0))
    comfort = 1.0 - abs(risk - (lo+hi)/2) / max((hi-lo)/2, 0.01)
    comfort = max(0.0, min(1.0, comfort))

    # 精度调制: 低精度时降低极端动作的效用
    precision_penalty = (1.0 - precision) * 0.5 if action in ("BLOCK","QUARANTINE") else 0.0

    # 误报代价调制
    fp_risk = (1.0 - risk) * fpc

    base = rw * comfort + (1.0 - rw) * (1.0 - fp_risk) - precision_penalty

    # 阈值覆盖
    min_conf = t.get(f"min_{action.lower()}", 0.0)
    if precision < min_conf:
        base -= 0.30

    return round(base, 4)


def decide(analysis_signals: Dict = None, unified_risk: Dict = None,
           thresholds: Dict = None) -> Dict:
    """贝叶斯决策引擎主入口。接口保持向后兼容。"""
    signals = analysis_signals or {}
    if unified_risk:
        signals.setdefault("unified_risk", unified_risk)

    risk_signals = _extract_risk_signals(signals)
    risk, precision = _compute_posterior_risk(risk_signals)

    actions = ["BLOCK", "QUARANTINE", "INVESTIGATE", "MONITOR", "ALLOW"]
    utilities = {}
    for action in actions:
        utilities[action] = _expected_utility(action, risk, precision, thresholds)

    best_action = max(utilities, key=utilities.get)
    best_utility = utilities[best_action]

    # 若最优效用过低（所有动作都不理想），退回 IGNORE
    if best_utility < 0.15:
        return {"decision": "IGNORE", "confidence": 0.0,
                "rule": "low_utility_fallback",
                "evidence": [], "audit_trail": utilities,
                "explanation": f"所有决策动作的期望效用均低于阈值 (max={best_utility:.3f})",
                "posterior_risk": risk, "posterior_precision": precision}

    evidence = []
    for key, val in sorted(risk_signals.items(), key=lambda x: x[1], reverse=True):
        if val > 0.15:
            evidence.append(f"{key}={val:.2f}")

    return {"decision": best_action,
            "confidence": round(best_utility, 4),
            "rule": "bayesian_maximum_expected_utility",
            "evidence": evidence[:5],
            "audit_trail": {a: round(u, 4) for a, u in utilities.items()},
            "explanation": f"选择 {best_action}（期望效用={best_utility:.3f}），后验风险={risk:.3f}，精度={precision:.3f}",
            "posterior_risk": risk,
            "posterior_precision": precision}


def decide_from_pipeline(
    posture_result: Dict = None, exploit_result: Dict = None,
    ttp_result: Dict = None, evasion_result: Dict = None,
    reachability_result: Dict = None, supply_chain_result: Dict = None,
    obfuscation_result: Dict = None, capability_result: Dict = None,
    cti_result: Dict = None, import_info: Dict = None,
    thresholds: Dict = None) -> Dict:
    return decide(analysis_signals={
        "posture": posture_result or {}, "exploit": exploit_result or {},
        "ttp": ttp_result or {}, "evasion": evasion_result or {},
        "reachability": reachability_result or {},
        "supply_chain": supply_chain_result or {},
        "obfuscation": obfuscation_result or {},
        "capability": capability_result or {}, "cti": cti_result or {},
        "import_info": import_info or {},
    }, thresholds=thresholds)
