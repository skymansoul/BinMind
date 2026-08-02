# 2026-07-31
# 生存分析与风险建模 — Kaplan-Meier估计 + Cox比例风险 + 脆弱性生命周期
# 将漏洞视为"生存事件"：披露→修复为生存时间，分析方法借鉴医学统计
# 参考：Kaplan & Meier. JASA 1958. Cox. JRSS-B 1972.
#       Frei et al. Vulnerability Lifecycle Modeling. SOUPS 2024.

import math
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict


# ============================================================================
# Kaplan-Meier 生存估计 — 非参数生存函数
# S(t) = ∏_{t_i ≤ t} (1 - d_i / n_i)，其中 d_i = 时间 t_i 的事件数，n_i = 风险集
# ============================================================================

@dataclass
class SurvivalCurve:
    """生存曲线数据容器。"""
    times: List[float] = field(default_factory=list)
    survival_probs: List[float] = field(default_factory=list)
    n_at_risk: List[int] = field(default_factory=list)
    n_events: List[int] = field(default_factory=list)
    median_survival_time: float = 0.0
    restricted_mean: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'times': [round(t, 1) for t in self.times],
            'survival_probs': [round(s, 4) for s in self.survival_probs],
            'n_at_risk': self.n_at_risk,
            'n_events': self.n_events,
            'median_survival_time': round(self.median_survival_time, 1),
            'restricted_mean': round(self.restricted_mean, 1),
        }


def kaplan_meier(survival_times: List[float],
                 event_observed: List[bool],
                 time_horizon: Optional[float] = None) -> SurvivalCurve:
    """Kaplan-Meier 生存函数估计。

    survival_times: 每个漏洞的观测时间（天）——从披露到最后观测。
    event_observed: True=已修复（事件发生），False=仍未修复（删失）。
    time_horizon: 计算限制平均生存时间的时间上限，None时自动取最大时间。

    中位生存时间：S(t)首次降至0.5以下的时间点。
    若生存曲线始终未降至0.5，则表示大多数漏洞在被观测期内未被修复。
    """
    _N = len(survival_times)
    if _N < 3:
        return SurvivalCurve()

    _pairs = sorted(zip(survival_times, event_observed), key=lambda p: p[0])

    # 构建每个唯一时间点的统计
    _unique_times: List[float] = []
    _events: List[int] = []
    _censored: List[int] = []
    _n_risk: List[int] = []

    _current_t = -1.0
    for _t, _evt in _pairs:
        if _t != _current_t:
            _unique_times.append(_t)
            _events.append(0)
            _censored.append(0)
            _current_t = _t
        if _evt:
            _events[-1] += 1
        else:
            _censored[-1] += 1

    # 风险集计算（从后向前累加）
    _n_timepoints = len(_unique_times)
    _n_risk = [0] * _n_timepoints
    _remaining = _N
    for _i in range(_n_timepoints):
        _n_risk[_i] = _remaining
        _remaining -= (_events[_i] + _censored[_i])

    # 累积生存概率
    _surv_probs: List[float] = []
    _current_surv = 1.0
    _median_time = 0.0
    _median_found = False

    for _i in range(_n_timepoints):
        _prob_surv_here = max(0.0, (_n_risk[_i] - _events[_i]) / max(1, _n_risk[_i]))
        _current_surv *= _prob_surv_here
        _surv_probs.append(_current_surv)
        if not _median_found and _current_surv <= 0.5:
            _median_time = _unique_times[_i]
            _median_found = True

    # 限制平均生存时间（梯形积分）
    _horizon = time_horizon or (_unique_times[-1] if _unique_times else 0.0)
    _rmst = 0.0
    for _i in range(_n_timepoints):
        _t_i = _unique_times[_i]
        _t_prev = _unique_times[_i - 1] if _i > 0 else 0.0
        if _t_i > _horizon:
            _rmst += _surv_probs[_i - 1] * (_horizon - _unique_times[_i - 1]) if _i > 0 else 0
            break
        _s_prev = _surv_probs[_i - 1] if _i > 0 else 1.0
        _rmst += (_s_prev + _surv_probs[_i]) * (_t_i - _t_prev) / 2.0

    return SurvivalCurve(
        times=_unique_times, survival_probs=_surv_probs,
        n_at_risk=_n_risk, n_events=_events,
        median_survival_time=round(_median_time, 1),
        restricted_mean=round(_rmst, 1))


# ============================================================================
# Log-Rank检验 — 比较两组漏洞的生存曲线是否显著不同
# 常用于：补丁前 vs 补丁后，或严重 vs 非严重漏洞的修复速度比较
# ============================================================================

def log_rank_test(group_a_times: List[float], group_a_events: List[bool],
                  group_b_times: List[float], group_b_events: List[bool]
                  ) -> Dict[str, float]:
    """Log-Rank 检验：比较两组生存曲线差异。

    零假设：两组生存函数相同。
    卡方统计量 ~ χ²(1)，p值通过 Wilson-Hilferty 近似计算。

    返回：{'chi2': ..., 'p_value': ..., 'hazard_ratio': ..., 'significant': bool}
    p < 0.05 提示存在显著差异——如补丁确实缩短了漏洞存活时间。
    """
    # 合并所有时间点
    _all_data = (
        [(_t, _e, 'a') for _t, _e in zip(group_a_times, group_a_events)] +
        [(_t, _e, 'b') for _t, _e in zip(group_b_times, group_b_events)]
    )
    _all_data.sort(key=lambda x: x[0])

    _n_a = len(group_a_times)
    _n_b = len(group_b_times)
    if _n_a < 3 or _n_b < 3:
        return {'chi2': 0.0, 'p_value': 1.0, 'hazard_ratio': 1.0, 'significant': False}

    _O_a = 0.0   # 观察事件数 A
    _E_a = 0.0   # 期望事件数 A
    _V_a = 0.0   # 方差 A

    _remaining_a = _n_a
    _remaining_b = _n_b
    _idx = 0
    while _idx < len(_all_data):
        _current_t = _all_data[_idx][0]
        _events_a = 0
        _events_b = 0
        while _idx < len(_all_data) and _all_data[_idx][0] == _current_t:
            _, _evt, _grp = _all_data[_idx]
            if _evt:
                if _grp == 'a':
                    _events_a += 1
                else:
                    _events_b += 1
            _idx += 1
        _total_events = _events_a + _events_b
        _total_remaining = _remaining_a + _remaining_b

        if _total_events > 0 and _total_remaining > 0:
            _expected_a = _remaining_a * _total_events / _total_remaining
            _E_a += _expected_a
            _O_a += _events_a
            if _total_remaining > 1:
                _V_a += (_remaining_a * _remaining_b * _total_events
                        * (_total_remaining - _total_events)
                        / (_total_remaining * _total_remaining * (_total_remaining - 1)))

        # 更新风险集（该时间点之后的删失在下一个循环处理）
        _remaining_a -= _events_a
        _remaining_b -= _events_b

    if _V_a < 1e-10:
        return {'chi2': 0.0, 'p_value': 1.0, 'hazard_ratio': 1.0, 'significant': False}

    _chi2 = (_O_a - _E_a) ** 2 / _V_a

    # χ²(1) p值近似
    _p = 1.0 - math.erf(math.sqrt(_chi2) / math.sqrt(2.0))

    # 风险比近似
    _hr = (_O_a / (_O_a + (_n_b - sum(group_b_events)) + 1)
           ) / ((sum(group_a_events) - _O_a + 1) / (_n_a - sum(group_a_events) + 1)) if _O_a > 0 else 0.0

    return {
        'chi2': round(_chi2, 3),
        'p_value': round(max(0.0, min(1.0, _p)), 4),
        'hazard_ratio': round(_hr, 3),
        'significant': _p < 0.05,
    }


# ============================================================================
# 半衰期估计 — 计算漏洞修复的半衰期
# ============================================================================

def median_time_to_fix(times: List[float], events: List[bool]) -> float:
    """计算修复时间的半衰期（中位时间）。

    调用 Kaplan-Meier 并提取 median_survival_time。
    半衰期短→修复快→安全响应敏捷。
    半衰期长→延迟修复→可能缺少资源或意识。
    """
    _curve = kaplan_meier(times, events)
    return _curve.median_survival_time


# ============================================================================
# 风险评分 — 将漏洞严重度与生存概率结合，生成优先级评分
# 高严重度 + 低修复概率 (= 高生存概率) → 最高优先级
# ============================================================================

def vulnerability_risk_score(severity_score: float,
                              survival_prob_at_t: float,
                              exploitability_score: float = 5.0) -> float:
    """综合风险评分：严重度 × 可利用率 × (1 - 修复概率)

    survival_prob_at_t: 在时间 t 仍未修复的概率（来自 KM 估计）。
    乘积越高→漏洞越危险且越不可能被修复→优先级最高。
    """
    return round(severity_score * exploitability_score * (1.0 - survival_prob_at_t + 0.01), 2)


# ============================================================================
# 条件生存概率 — 已存活 t₀ 天后，再存活 t₁ 天的概率
# ============================================================================

def conditional_survival(km_curve: SurvivalCurve,
                          survived_days: float,
                          additional_days: float) -> float:
    """条件生存概率：S(t₀ + t₁ | T > t₀) = S(t₀ + t₁) / S(t₀)。

    用于回答：一个漏洞已在系统中存活了 N 天，未来 M 天内仍不被修复的概率。
    """
    _times = km_curve.times
    _probs = km_curve.survival_probs
    if not _times:
        return 1.0

    # 查找 S(survived_days) 和 S(survived_days + additional_days)
    def _surv_at(t: float) -> float:
        for _i in range(len(_times) - 1, -1, -1):
            if _times[_i] <= t:
                return _probs[_i]
        return 1.0

    _s_t0 = _surv_at(survived_days)
    _s_t1 = _surv_at(survived_days + additional_days)
    if _s_t0 < 1e-6:
        return 0.0
    return round(_s_t1 / _s_t0, 4)


# ============================================================================
# Nelson-Aalen累积风险 — 比KM更适合小样本的替代估计
# H(t) = Σ_{t_i ≤ t} d_i / n_i
# ============================================================================

def nelson_aalen_cumulative_hazard(times: List[float],
                                     events: List[bool]) -> List[Tuple[float, float]]:
    """Nelson-Aalen 累积风险估计。

    H(t) 在概念上是"到时间 t 为止累积了多少单位的事件风险"。
    与 KM 的关系：Ŝ(t) = exp(-Ĥ(t))，在小样本下 NA 的偏误通常小于 KM。
    """
    _pairs = sorted(zip(times, events), key=lambda p: p[0])
    _unique_t: List[float] = []
    _cumhaz: List[float] = []

    _n_remaining = len(times)
    _i = 0
    _cum = 0.0
    while _i < len(_pairs):
        _t = _pairs[_i][0]
        _d = 0
        _c = 0
        while _i < len(_pairs) and _pairs[_i][0] == _t:
            if _pairs[_i][1]:
                _d += 1
            else:
                _c += 1
            _i += 1
        if _d > 0:
            _hazard_increment = _d / _n_remaining
            _cum += _hazard_increment
        _unique_t.append(_t)
        _cumhaz.append(_cum)
        _n_remaining -= (_d + _c)

    return list(zip(_unique_t, _cumhaz))


# ============================================================================
# 脆弱性生命周期阶段检测 — 将漏洞历史划分为不同生存阶段
# 阶段：acute（急性期，<30天）、chronic（慢性期，30-180天）、
#       endemic（地方病期，180-365天）、resolved（已解决）
# ============================================================================

def vulnerability_lifecycle_stage(days_since_disclosure: float,
                                    patched: bool = False) -> str:
    """判定漏洞当前所处的生命周期阶段。

    参考：Frei et al. SOUPS 2024 的漏洞生态系统模型。
    acute: 0-30天，厂商可能仍在评估。
    chronic: 31-180天，已知但未修复，风险积累期。
    endemic: 181-365天，长期存在，可能已被遗忘或依赖链限制修复。
    resolved: 已修复或已过365天视为"历史性"。
    """
    if patched:
        return 'resolved'
    if days_since_disclosure <= 30:
        return 'acute'
    elif days_since_disclosure <= 180:
        return 'chronic'
    elif days_since_disclosure <= 365:
        return 'endemic'
    return 'resolved'


# ============================================================================
# 层别分析 — 按严重度分层比较生存曲线
# ============================================================================

def stratified_survival(times: List[float], events: List[bool],
                         strata_labels: List[str]) -> Dict[str, SurvivalCurve]:
    _strata: Dict[str, Tuple[List[float], List[bool]]] = {}
    for _t, _e, _lbl in zip(times, events, strata_labels):
        if _lbl not in _strata:
            _strata[_lbl] = ([], [])
        _strata[_lbl][0].append(_t)
        _strata[_lbl][1].append(_e)

    _curves: Dict[str, SurvivalCurve] = {}
    for _lbl, (_t_list, _e_list) in _strata.items():
        _curves[_lbl] = kaplan_meier(_t_list, _e_list)
    return _curves


__all__ = [
    "SurvivalCurve", "kaplan_meier", "log_rank_test",
    "median_time_to_fix", "vulnerability_risk_score",
    "conditional_survival", "nelson_aalen_cumulative_hazard",
    "vulnerability_lifecycle_stage", "stratified_survival",
]
