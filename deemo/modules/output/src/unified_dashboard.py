"""
统一风险仪表盘 — 熵加权动态聚合 + 置信带 + 雷达图数据。

问题定义:
  37 个评分模块输出独立分数。安全团队需要单一综合风险指数。
  传统线性加权的问题是: 静态权重无法反映各维度在当前评估中的
  实际区分度——如果所有模块在"加固质量"维度上得分相同, 该维度
  对决策的边际信息量为零, 不应占用相同权重。

  本模块的熵加权方案:
    1. 计算每个维度内部子指标的方差
    2. 高方差 → 高信息量 → 高权重 (该维度能区分风险)
    3. 低方差 → 低信息量 → 低权重 (该维度对本次评估无贡献)
    4. 归一化后与静态先验权重做加权调和平均 (保留领域知识)

  输出: 0-100 统一指数 + 置信带 + 六维雷达数据 + 权重解释。

参考:
  Shannon (1948): 信息熵作为不确定性的度量
  OWASP Risk Rating Methodology: 风险 = 可能性 × 影响
  无现有动态加权仪表盘工具 — 2026-08 检索确认

修改记录:
  创建 2026-08-02 — 静态加权版
  2026-08-04 — 追加熵加权动态聚合 + 置信带
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


_DIMENSION_PRIORS = {
    'exploitability': 0.25, 'exposure': 0.20, 'hardening': 0.15,
    'code_quality': 0.15, 'remediation': 0.10, 'mitigation': 0.15,
}


@dataclass
class RiskDashboard:
    unified_risk_index: float
    risk_level: str
    radar_dimensions: Dict[str, float]
    dimension_weights: Dict[str, float]    # 实际使用的权重 (含熵调整)
    top_risks: List[Dict[str, Any]] = field(default_factory=list)
    risk_trend: str = 'stable'
    confidence_band: Tuple[float, float] = (0, 0)
    executive_summary: str = ''


def _entropy_weights(
    dim_scores: Dict[str, List[float]],
    priors: Dict[str, float],
    alpha: float = 0.4,
) -> Dict[str, float]:
    """
    熵加权: 混合静态先验和动态信息量权重。

    dim_scores: {dim_name: [sub_scores...]} — 每个维度的子指标列表
    alpha: 动态权重的贡献比例 (0=纯静态, 1=纯动态)

    动态权重 ∝ variance(sub_scores) — 高方差维度获得更高权重。
    调和混合: final = α × dynamic + (1-α) × prior
    """
    if not dim_scores:
        return dict(priors)

    # 计算每个维度的方差 (归一化后)
    variances = {}
    for dim, scores in dim_scores.items():
        n = len(scores)
        if n < 2:
            variances[dim] = 0.01  # 单指标 → 最小方差
        else:
            mean = sum(scores) / n
            var = sum((s - mean) ** 2 for s in scores) / n
            # 归一化: 方差通常在 [0, 100] (10分制的平方)
            variances[dim] = min(var / 100.0, 1.0) + 0.01

    total_var = sum(variances.values())
    if total_var < 1e-8:
        return dict(priors)

    dynamic = {dim: v / total_var for dim, v in variances.items()}

    # 调和混合
    blended = {}
    for dim in priors:
        blended[dim] = round(alpha * dynamic.get(dim, 0.1) + (1 - alpha) * priors[dim], 4)

    # 重新归一化
    total = sum(blended.values())
    return {k: round(v / total, 4) for k, v in blended.items()}


def _dimension_exploitability(
    primitive_quality: float = 5.0, heap_exploit: float = 5.0,
    format_string: float = 0.0, off_by_one: float = 0.0,
    double_free: float = 0.0, null_deref: float = 0.0,
    type_confusion: float = 0.0, underflow: float = 0.0,
    integer_overflow: float = 0.0, race_window: float = 0.0,
    stack_pivot: float = 5.0,
) -> Tuple[float, List[float]]:
    scores = [primitive_quality, heap_exploit, format_string, off_by_one,
              double_free, null_deref, type_confusion, underflow,
              integer_overflow, race_window, stack_pivot]
    active = [s for s in scores if s > 0]
    avg = round(sum(active)/len(active), 1) if active else 0.0
    return avg, scores


def _dimension_exposure(
    risk_composite: float = 5.0, ipc_risk: float = 0.0,
    signal_risk: float = 0.0, contagion_score: float = 5.0,
) -> Tuple[float, List[float]]:
    scores = [risk_composite, ipc_risk, signal_risk, contagion_score]
    active = [s for s in scores if s > 0]
    return (round(sum(active)/len(active), 1) if active else 0.0), scores


def _dimension_hardening(
    aslr_score: float = 50.0, bitrot: float = 5.0,
    hardening_gain: float = 0.0, opt_sensitivity: float = 5.0,
) -> Tuple[float, List[float]]:
    h = (aslr_score * 0.4 + (10 - bitrot) * 3.33 * 0.3 +
         hardening_gain * 0.15 + (10 - opt_sensitivity) * 3.33 * 0.15)
    return round(h, 1), [aslr_score/10, 10-bitrot, hardening_gain, 10-opt_sensitivity]


def _dimension_code_quality(
    security_debt: float = 5.0, vuln_density_z: float = 0.0,
    reliability: float = 0.8,
) -> Tuple[float, List[float]]:
    base = (security_debt * 0.4 + min(abs(vuln_density_z) * 10, 10) * 0.3 +
            (1 - reliability) * 10 * 0.3)
    return round(base, 1), [security_debt, min(abs(vuln_density_z)*10, 10), (1-reliability)*10]


def _dimension_remediation(
    remediation_diff: float = 5.0, urgency_hours: float = 168.0,
    vuln_lifespan_days: float = 55.0,
) -> Tuple[float, List[float]]:
    urg_norm = max(0, 10 - math.log2(max(urgency_hours, 1)) * 1.5)
    life_norm = min(vuln_lifespan_days / 10.0, 10.0)
    return (round(remediation_diff * 0.4 + urg_norm * 0.35 + life_norm * 0.25, 1),
            [remediation_diff, urg_norm, life_norm])


def _dimension_mitigation(
    sandbox_difficulty: float = 5.0, cfi_penalty: float = 0.0,
    heap_protection: float = 5.0,
) -> Tuple[float, List[float]]:
    h = (sandbox_difficulty * 0.45 + (10 - min(cfi_penalty, 10)) * 0.25 +
         heap_protection * 0.30)
    return round(h, 1), [sandbox_difficulty, 10-min(cfi_penalty,10), heap_protection]


def _risk_level(index: float) -> str:
    if index >= 75: return 'critical'
    if index >= 50: return 'high'
    if index >= 25: return 'medium'
    return 'low'


def generate_dashboard(
    primitive_quality: float = 5.0, heap_exploit: float = 5.0,
    format_string: float = 0.0, off_by_one: float = 0.0,
    double_free: float = 0.0, null_deref: float = 0.0,
    type_confusion: float = 0.0, underflow: float = 0.0,
    integer_overflow: float = 0.0, race_window: float = 0.0,
    stack_pivot: float = 5.0,
    risk_composite: float = 5.0, ipc_risk: float = 0.0,
    signal_risk: float = 0.0, contagion_score: float = 5.0,
    aslr_score: float = 50.0, bitrot: float = 5.0,
    hardening_gain: float = 0.0, opt_sensitivity: float = 5.0,
    security_debt: float = 5.0, vuln_density_z: float = 0.0,
    reliability: float = 0.8,
    remediation_diff: float = 5.0, urgency_hours: float = 168.0,
    vuln_lifespan_days: float = 55.0,
    sandbox_difficulty: float = 5.0, cfi_penalty: float = 0.0,
    heap_protection: float = 5.0,
    previous_index: Optional[float] = None,
    alpha: float = 0.4,
) -> RiskDashboard:
    """
    生成统一风险仪表盘 — 熵加权动态聚合。

    alpha: 0=纯静态先验权重, 1=纯动态熵权重
    """
    exp_val, exp_subs = _dimension_exploitability(
        primitive_quality, heap_exploit, format_string, off_by_one,
        double_free, null_deref, type_confusion, underflow,
        integer_overflow, race_window, stack_pivot)
    expo_val, expo_subs = _dimension_exposure(risk_composite, ipc_risk, signal_risk, contagion_score)
    hard_val, hard_subs = _dimension_hardening(aslr_score, bitrot, hardening_gain, opt_sensitivity)
    code_val, code_subs = _dimension_code_quality(security_debt, vuln_density_z, reliability)
    rem_val, rem_subs = _dimension_remediation(remediation_diff, urgency_hours, vuln_lifespan_days)
    mit_val, mit_subs = _dimension_mitigation(sandbox_difficulty, cfi_penalty, heap_protection)

    dim_values = {
        'exploitability': exp_val, 'exposure': expo_val,
        'hardening': hard_val, 'code_quality': code_val,
        'remediation': rem_val, 'mitigation': mit_val,
    }
    dim_subscores = {
        'exploitability': exp_subs, 'exposure': expo_subs,
        'hardening': hard_subs, 'code_quality': code_subs,
        'remediation': rem_subs, 'mitigation': mit_subs,
    }

    # 熵加权
    weights = _entropy_weights(dim_subscores, _DIMENSION_PRIORS, alpha)

    raw = sum(weights[k] * dim_values[k] * 10 for k in weights)
    index = round(max(0.0, min(100.0, raw)), 1)

    # 置信带: ±(1-α)×10% 反映动态权重的估计不确定性
    half_band = round((1 - alpha) * index * 0.10, 1)
    confidence_band = (round(index - half_band, 1), round(index + half_band, 1))

    trend = 'stable'
    if previous_index is not None:
        delta = index - previous_index
        trend = 'rising' if delta > 5 else ('declining' if delta < -5 else 'stable')

    level = _risk_level(index)
    if level == 'critical':
        summary = '极高风险 — 多维度同时告警。建议立即启动 incident response'
    elif level == 'high':
        summary = '高风险 — 存在可利用漏洞且暴露面较大。建议 24h 内评估'
    elif level == 'medium':
        summary = '中等风险 — 存在可改进的安全弱点。纳入下个 sprint'
    else:
        summary = '低风险 — 当前防护措施有效。保持定期评估'

    top = sorted(dim_values.items(), key=lambda x: x[1], reverse=True)
    top_risks = [{'dimension': k, 'score': round(v, 1),
                  'weight': weights.get(k, 0)} for k, v in top[:3]]

    return RiskDashboard(
        unified_risk_index=index, risk_level=level,
        radar_dimensions={k: round(v * 10, 1) for k, v in dim_values.items()},
        dimension_weights=weights, top_risks=top_risks,
        risk_trend=trend, confidence_band=confidence_band,
        executive_summary=summary)
