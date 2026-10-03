"""
漏洞寿命估计 — 经验生存曲线 + Cox 因子模型的混合方法。

问题定义:
  安全团队需要回答: "这个漏洞预计多久会被修复?"
  现有工具: EPSS 预测利用概率, CVSS temporal 是评分快照——都不预测修复时间。

  本模块提供双路径寿命估计:
    1. 经验路径: 若有所史 CVE 修复数据 → Kaplan-Meier 生存曲线
    2. 因子路径: Cox 比例风险启发式——六因子乘法模型
    3. 混合路径: 用经验曲线校准因子模型的基线

Kaplan-Meier 生存函数:
  S(t) = Π_{t_i ≤ t} (1 - d_i/n_i)
  d_i = 在时间 t_i 被修复的数量, n_i = 在 t_i 时刻仍"存活"的数量
  中位寿命 = S(t) 首次穿越 0.5 的时间

  Kaplan & Meier: 非参数生存估计
  Cox: 比例风险回归模型
  NVD CVE 生命周期分析: 中位修复时间 ~55 天基线

修改记录:
  创建 2025-04-17 — 六因子乘法模型
  2025-04-17 — 追加 Kaplan-Meier 经验生存曲线 + 混合估计
"""

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

_BASELINE_LIFESPAN_DAYS = 55.0

@dataclass
class SurvivalCurve:
    """Kaplan-Meier 生存曲线。"""
    time_points: List[float]           # 排序后的时间点 (天)
    survival_probs: List[float]        # S(t) 在每个时间点的值
    median_days: float                 # 中位生存时间
    percentile_25: float               # 25% 被修复的天数
    percentile_75: float               # 75% 被修复的天数
    total_events: int                  # 总事件数 (已修复)
    total_censored: int                # 截尾数 (尚未修复)

def fit_survival(
    events: List[Tuple[float, bool]],
    min_events: int = 10,
) -> Optional[SurvivalCurve]:
    """
    从 (时间, 是否已修复) 构建 Kaplan-Meier 生存曲线。

    events: [(days_elapsed, was_fixed), ...]
      was_fixed=True → 事件 (修复), was_fixed=False → 截尾 (仍未修复)
    min_events: 需要至少这么多个已修复事件才返回有效曲线

    返回 None 如果数据不足。
    """
    fixed = [e for e in events if e[1]]
    if len(fixed) < min_events:
        return None

    # 排序时间点
    sorted_events = sorted(events, key=lambda e: e[0])
    time_points: List[float] = []
    surv_probs: List[float] = []
    n_at_risk = len(events)
    surv = 1.0
    total_fixed = 0
    total_censored = 0
    prev_t = -1.0

    for t, was_fixed in sorted_events:
        if t > prev_t and prev_t >= 0:
            time_points.append(prev_t)
            surv_probs.append(round(surv, 4))
        if was_fixed:
            d = 1
            # 聚合同一时间点的多个事件
            j = sorted_events.index((t, was_fixed))
            while j + 1 < len(sorted_events) and sorted_events[j+1][0] == t and sorted_events[j+1][1]:
                d += 1
                j += 1
            surv *= (1.0 - d / n_at_risk) if n_at_risk > 0 else 1.0
            total_fixed += 1
        else:
            total_censored += 1
        n_at_risk -= 1
        prev_t = t

    if prev_t >= 0:
        time_points.append(prev_t)
        surv_probs.append(round(surv, 4))

    if not time_points:
        return None

    # 中位和百分位
    median = _find_percentile(time_points, surv_probs, 0.50)
    p25 = _find_percentile(time_points, surv_probs, 0.75)
    p75 = _find_percentile(time_points, surv_probs, 0.25)

    return SurvivalCurve(
        time_points=time_points, survival_probs=surv_probs,
        median_days=median, percentile_25=p25, percentile_75=p75,
        total_events=total_fixed, total_censored=total_censored)

def _find_percentile(times: List[float], probs: List[float],
                     target: float) -> float:
    """S(t) 首次 ≤ target 的 t。线性插值。"""
    for i, (t, s) in enumerate(zip(times, probs)):
        if s <= target:
            if i == 0: return t
            prev_s = probs[i-1]
            prev_t = times[i-1]
            if prev_s == s: return t
            frac = (prev_s - target) / (prev_s - s) if prev_s != s else 0
            return round(prev_t + frac * (t - prev_t), 1)
    return times[-1] if times else _BASELINE_LIFESPAN_DAYS

# 因子模型的六个因子 (保留原有逻辑)

def _activity_factor(commits_per_month: float) -> float:
    if commits_per_month <= 0: return 2.0
    if commits_per_month < 5: return 1.8
    if commits_per_month > 50: return 0.6
    return round(1.8 - (commits_per_month - 5) * (1.2 / 45), 2)

def _complexity_factor(cc: int) -> float:
    if cc <= 5: return 0.8
    if cc >= 30: return 1.6
    return round(0.8 + (cc - 5) * (0.8 / 25), 2)

def _severity_factor(cvss: float) -> float:
    if cvss >= 9.0: return 0.5
    if cvss <= 3.0: return 1.5
    return round(1.5 - (cvss - 3.0) * (1.0 / 6.0), 2)

def _exploit_public_factor(poc: bool, kev: bool = False) -> float:
    if kev: return 0.3
    if poc: return 0.4
    return 1.0

def _maintainer_factor(mt: str) -> float:
    return {'enterprise': 0.7, 'community': 1.3, 'individual': 1.6}.get(mt, 1.0)

def _ecosystem_factor(is_lib: bool, deps: int = 0) -> float:
    if is_lib:
        if deps >= 50: return 1.8
        if deps >= 10: return 1.5
        return 1.2
    return 0.9

@dataclass
class LifespanEstimate:
    vuln_identifier: str
    expected_days: float
    baseline_days: float
    factors: Dict[str, float] = field(default_factory=dict)
    confidence_interval: Tuple[float, float] = (0, 0)
    risk_of_prolonged: str = ''
    estimation_method: str = 'cox_factors'

    def __post_init__(self):
        if self.expected_days >= 180: self.risk_of_prolonged = 'critical_delay'
        elif self.expected_days >= 90: self.risk_of_prolonged = 'significant_delay'
        elif self.expected_days >= 30: self.risk_of_prolonged = 'moderate'
        else: self.risk_of_prolonged = 'expected_timely'

def estimate_lifespan(
    identifier: str = '', commits_per_month: float = 10.0,
    cyclomatic_complexity: int = 10, cvss_score: float = 5.0,
    poc_published: bool = False, kev_listed: bool = False,
    maintainer_type: str = 'unknown', is_shared_library: bool = False,
    dependents: int = 0,
    survival_curve: Optional[SurvivalCurve] = None,
) -> LifespanEstimate:
    """
    估计漏洞修复时间。双路径:
      - survival_curve 提供时: 从经验曲线取中位寿命
      - 否则: Cox 因子乘法模型

    混合模式: 用经验曲线的中位替换基线 (55天), 因子仍做乘法修正。
    """
    baseline = _BASELINE_LIFESPAN_DAYS
    method = 'cox_factors'

    if survival_curve is not None:
        baseline = survival_curve.median_days
        method = 'kaplan_meier'
        # 用因子做微调 (混合模式)
        factors = {
            'survival_median': 1.0,
            'activity': _activity_factor(commits_per_month),
            'complexity': _complexity_factor(cyclomatic_complexity),
        }
        product = factors['activity'] * factors['complexity']
        expected = round(baseline * product, 1)
        ci_low = round(survival_curve.percentile_25 * product, 1)
        ci_high = round(survival_curve.percentile_75 * product, 1)
    else:
        factors = {
            'activity': _activity_factor(commits_per_month),
            'complexity': _complexity_factor(cyclomatic_complexity),
            'severity': _severity_factor(cvss_score),
            'exploit_public': _exploit_public_factor(poc_published, kev_listed),
            'maintainer': _maintainer_factor(maintainer_type),
            'ecosystem': _ecosystem_factor(is_shared_library, dependents),
        }
        product = 1.0
        for v in factors.values(): product *= v
        expected = round(baseline * product, 1)
        ci_low = round(expected * 0.6, 1)
        ci_high = round(expected * 1.4, 1)

    return LifespanEstimate(
        vuln_identifier=identifier or 'unknown',
        expected_days=expected, baseline_days=baseline,
        factors={k: round(v, 2) for k, v in factors.items()},
        confidence_interval=(ci_low, ci_high),
        estimation_method=method)

def batch_estimate(
    vulnerabilities: List[Dict[str, Any]],
    survival_curve: Optional[SurvivalCurve] = None,
) -> List[LifespanEstimate]:
    results = []
    for v in vulnerabilities:
        est = estimate_lifespan(
            identifier=v.get('identifier', v.get('function_name', '')),
            commits_per_month=v.get('commits_per_month', 10.0),
            cyclomatic_complexity=v.get('cyclomatic_complexity', 10),
            cvss_score=v.get('cvss_score', 5.0),
            poc_published=v.get('poc_published', False),
            kev_listed=v.get('kev_listed', False),
            maintainer_type=v.get('maintainer_type', 'unknown'),
            is_shared_library=v.get('is_shared_library', False),
            dependents=v.get('dependents', 0),
            survival_curve=survival_curve)
        results.append(est)
    results.sort(key=lambda e: e.expected_days)
    return results

def lifespan_summary(estimates: List[LifespanEstimate]) -> Dict[str, Any]:
    if not estimates:
        return {'count': 0, 'mean_days': 0, 'max_days': 0,
                'fastest': None, 'slowest': None}
    days = [e.expected_days for e in estimates]
    at_risk = sum(1 for e in estimates if e.risk_of_prolonged in
                  ('critical_delay', 'significant_delay'))
    return {
        'count': len(estimates), 'mean_days': round(sum(days)/len(days), 1),
        'min_days': min(days), 'max_days': max(days),
        'fastest': estimates[0].vuln_identifier,
        'slowest': estimates[-1].vuln_identifier,
        'at_risk_count': at_risk,
        'estimation_method': estimates[0].estimation_method if estimates else 'none',
    }
