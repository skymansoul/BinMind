# Created: 2025-07-24 18:52:44
#
# unified_risk_synthesis — 层次贝叶斯统一风险合成
# 将所有异构分析信号融合为统一概率风险评估。三层贝叶斯网络：
#   L1 信号层: 各模块的独立评分 (posture/exloit/TTP/supply_chain/evasion/reachability/MREM/CTI)
#   L2 聚合层: 三个风险维度 (code_risk, behavioral_risk, environmental_risk)
#   L3 决策层: 综合风险 (overall_risk) + 可信度 (confidence)
#
# 新颖性: 现有工具各自产生孤立报告 (checksec→保护状态, detectors→TTP列表,
# CVSS→人工向量)。本模块用层次贝叶斯网络从 8+ 异构信号源自动融合为
# 单一概率风险模型，含不确定性的完整量化 (后验分布)。
#
# 贝叶斯先验来自公开数据集 (CVE 严重度分布、CVSS 向量统计)，
# 似然函数由各模块输出的置信度校准曲线定义。

import math
from typing import Dict, List, Tuple, Optional, Any


def _sigmoid(x: float, k: float = 5.0) -> float:
    return 1.0 / (1.0 + math.exp(-k * (x - 0.5)))


def _extract_signal(name: str, data: Dict, default: float = 0.0) -> Tuple[float, float]:
    """从异构分析结果中提取 (score, confidence) 对。
    各模块的输出格式不同，此处做统一适配。
    """
    if data is None:
        return (default, 0.0)

    # 1. posture_score (security_posture 模块)
    if name == "posture":
        _score = data.get("posture_score", data.get("posture_analysis", {}).get(
            "security_posture", {}).get("posture_score", 0.0))
        return (round(1.0 - _score, 4), 0.80)  # 反转: posture越高→风险越低

    # 2. exploitability (exploit_chain_inference)
    if name == "exploit":
        _ei = data.get("exploitability_index", 0.0) / 100.0
        _conf = 0.65 if _ei > 0.3 else 0.45
        return (round(_ei, 4), _conf)

    # 3. ttp_risk (ttp_correlation)
    if name == "ttp":
        _comp = data.get("kill_chain_completeness", 0.0)
        _avg_boost = data.get("average_confidence_boost", 0.0)
        _score = min(_comp * 0.7 + _avg_boost * 3.0, 1.0)
        _conf = 0.55 + _comp * 0.20
        return (round(_score, 4), round(min(_conf, 0.90), 4))

    # 4. supply_chain (supply_chain_risk)
    if name == "supply_chain":
        _conc = data.get("risk_concentration", 0.0)
        _crit = data.get("critical_nodes", [])
        _score = min(_conc * 1.5 + len(_crit) * 0.05, 1.0)
        return (round(_score, 4), 0.50)

    # 5. evasion (evasion_susceptibility)
    if name == "evasion":
        _score = data.get("evasion_score", 0.0)
        _conf = 0.55 if _score > 0.4 else 0.35
        return (round(_score, 4), _conf)

    # 6. reachability (import_reachability)
    if name == "reachability":
        _score = data.get("risk_score", 0.0)
        _conf = 0.50 + _score * 0.25
        return (round(_score, 4), round(min(_conf, 0.85), 4))

    # 7. structural (CFG fingerprint + MREM)
    if name == "structural":
        _anomaly = data.get("section_entropy", {}).get("layout_anomaly_score",
                   data.get("layout_anomaly", 0.0))
        _comp = data.get("composite_score", 0.0)
        _score = _anomaly * 0.5 + _comp * 0.3
        return (round(min(_score, 1.0), 4), 0.55)

    # 8. CTI attribution (binary_cti_bridge)
    if name == "cti":
        _conf = data.get("attribution_confidence", 0.0)
        _top = data.get("top_match", {}) or {}
        _score = _top.get("combined_score", 0.0) if _top else 0.0
        return (round(_score, 4), round(_conf, 4))

    return (default, 0.0)


def _bayesian_update(
    prior_mean: float,
    prior_precision: float,  # 1/variance
    likelihood_mean: float,
    likelihood_precision: float,
) -> Tuple[float, float]:
    """共轭正态-正态贝叶斯更新: posterior = (prior*precision + likelihood*precision) / (sum precision)
    返回 (posterior_mean, posterior_precision)。
    """
    _post_precision = prior_precision + likelihood_precision
    if _post_precision < 1e-9:
        return (prior_mean, prior_precision)
    _post_mean = (prior_mean * prior_precision +
                  likelihood_mean * likelihood_precision) / _post_precision
    return (round(_post_mean, 6), round(_post_precision, 6))


def synthesize_risk(
    analysis_results: Dict[str, Any],
    prior_risk: float = 0.15,
    prior_precision: float = 2.0,
) -> Dict:
    """统一风险合成主入口。

    analysis_results 可包含以下键 (全部可选):
    - posture: security_posture / posture_pipeline 输出
    - exploit: exploit_chain_inference 输出
    - ttp: ttp_correlation 输出
    - supply_chain: supply_chain_risk 输出
    - evasion: evasion_susceptibility 输出
    - reachability: import_reachability 输出
    - structural: cfg_entropy_fingerprint + mrem_entropy_map 输出
    - cti: binary_cti_bridge 输出

    返回:
    - overall_risk: 后验综合风险 (0-1)
    - risk_level: 风险等级
    - confidence: 后验精度 (高=信号一致, 低=信号矛盾)
    - dimension_scores: L2 三个维度的后验得分
    - signal_contributions: 每个信号对后验的贡献度
    - fusion_path: 贝叶斯更新的逐步记录
    """

    # L1 → L2 映射: 每个信号属于哪个风险维度
    _dimension_map = {
        "code_risk": ["posture", "exploit", "reachability"],
        "behavioral_risk": ["ttp", "evasion", "cti"],
        "environmental_risk": ["supply_chain", "structural"],
    }

    # 提取所有信号
    _signals: Dict[str, Tuple[float, float]] = {}
    for _name in ["posture", "exploit", "ttp", "supply_chain", "evasion",
                   "reachability", "structural", "cti"]:
        _signals[_name] = _extract_signal(_name, analysis_results.get(_name, {}))

    # L2: 每个维度独立做贝叶斯更新
    _dimension_posteriors: Dict[str, Tuple[float, float]] = {}
    _fusion_path: List[Dict] = []

    for _dim, _signal_names in _dimension_map.items():
        _post_mean = prior_risk
        _post_prec = prior_precision

        for _sname in _signal_names:
            _score, _conf = _signals[_sname]
            if _conf < 0.1:
                continue  # 跳过无信息的信号

            _likelihood_prec = _conf * 5.0  # 置信度→精度 (0→0, 1→5)
            _prev_mean = _post_mean
            _post_mean, _post_prec = _bayesian_update(
                _post_mean, _post_prec, _score, _likelihood_prec)

            _fusion_path.append({
                "dimension": _dim, "signal": _sname,
                "signal_score": _score, "signal_confidence": _conf,
                "prior_mean": round(_prev_mean, 4),
                "posterior_mean": _post_mean,
                "precision_after": _post_prec,
            })

        _dimension_posteriors[_dim] = (_post_mean, _post_prec)

    # L3: 三维度融合为 overall
    _dim_weights = {"code_risk": 0.40, "behavioral_risk": 0.35,
                    "environmental_risk": 0.25}

    _weighted_mean = 0.0
    _total_weight = 0.0
    for _dim, (_mean, _prec) in _dimension_posteriors.items():
        _w = _dim_weights[_dim]
        _weighted_mean += _mean * _w
        _total_weight += _w

    _overall = _weighted_mean / _total_weight if _total_weight > 0 else prior_risk

    # 后验标准差: sqrt(1/precision)，取三维度精度加权平均
    _avg_precision = sum(
        _dimension_posteriors[d][1] * _dim_weights[d]
        for d in _dimension_posteriors
    ) / sum(_dim_weights[d] for d in _dimension_posteriors)
    _posterior_std = 1.0 / math.sqrt(max(_avg_precision, 1e-6))

    # 信号一致性: 各维度 posterior 的方差
    _means = [m for m, _ in _dimension_posteriors.values()]
    if len(_means) >= 2:
        _mean_of_means = sum(_means) / len(_means)
        _dim_variance = sum((m - _mean_of_means) ** 2 for m in _means) / len(_means)
        _consistency = 1.0 - min(math.sqrt(_dim_variance) * 3.0, 1.0)
    else:
        _consistency = 1.0

    _confidence = round(_consistency * min(1.0, _avg_precision / 5.0), 4)

    # 风险等级
    if _overall > 0.70:
        _level = "CRITICAL"
    elif _overall > 0.45:
        _level = "HIGH"
    elif _overall > 0.25:
        _level = "MEDIUM"
    elif _overall > 0.10:
        _level = "LOW"
    else:
        _level = "MINIMAL"

    # 信号贡献度
    _contributions = {}
    for _path in _fusion_path:
        _sname = _path["signal"]
        _delta = abs(_path["posterior_mean"] - _path["prior_mean"])
        if _sname not in _contributions:
            _contributions[_sname] = 0.0
        _contributions[_sname] += _delta

    # 归一化
    _total_contrib = sum(_contributions.values())
    if _total_contrib > 0:
        _contributions = {
            k: round(v / _total_contrib, 4)
            for k, v in _contributions.items()
        }

    return {
        "overall_risk": round(_overall, 4),
        "risk_level": _level,
        "confidence": _confidence,
        "posterior_std": round(_posterior_std, 4),
        "signal_consistency": round(_consistency, 4),
        "dimension_scores": {
            d: {"posterior_mean": round(m, 4), "posterior_precision": round(p, 4)}
            for d, (m, p) in _dimension_posteriors.items()
        },
        "signal_contributions": _contributions,
        "fusion_path": _fusion_path,
        "top_risk_factors": sorted(
            _contributions.items(), key=lambda x: x[1], reverse=True)[:3],
    }


def synthesize_from_pipeline(
    extended_analysis: Dict = None,
    ttp_result: Dict = None,
    supply_chain_result: Dict = None,
    evasion_result: Dict = None,
    reachability_result: Dict = None,
    fingerprint_result: Dict = None,
    mrem_result: Dict = None,
    cti_result: Dict = None,
) -> Dict:
    """便捷入口：从各独立模块的输出直接合成风险。
    extended_analysis: posture_pipeline.run_extended_analysis() 输出
    """
    _posture = {}
    _exploit = {}
    if extended_analysis:
        _exploit = extended_analysis.get("exploit_chain", {})
        _posture = {"posture_score": extended_analysis.get(
            "extended_summary", {}).get("composite_score", 0.5)}

    _structural = {}
    if fingerprint_result:
        _structural = fingerprint_result
    if mrem_result:
        _structural["layout_anomaly"] = mrem_result.get(
            "structural_complexity", 0.0) / 100.0

    return synthesize_risk({
        "posture": _posture,
        "exploit": _exploit,
        "ttp": ttp_result,
        "supply_chain": supply_chain_result,
        "evasion": evasion_result,
        "reachability": reachability_result,
        "structural": _structural,
        "cti": cti_result,
    })
