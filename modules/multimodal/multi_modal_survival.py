# 漏洞生存分析：Kaplan-Meier估计 + 对数秩检验 + 脆弱性生命周期阶段划分
# 将漏洞视为生存事件，披露→修复间隔作为生存时间，工具链源自医学统计
# 基础文献：Kaplan & Meier. JASA 1958. Cox. JRSS-B 1972.
#          Frei et al. Vulnerability Lifecycle Modeling. SOUPS 2024.

import math
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field
from collections import defaultdict


# Kaplan-Meier 生存函数：非参数估计
# S(t) = ∏_{t_i ≤ t} (1 - d_i / n_i)，d_i = t_i 时刻事件数，n_i = 该时刻风险集

@dataclass
class SurvivalCurve:
    """生存曲线完整输出：时间点序列、生存概率、风险集、事件计数与摘要统计量。"""
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
    """估计漏洞修复时间的生存函数。

    survival_times: 每个漏洞自披露起的观测天数。
    event_observed: True=已修复（事件发生），False=观测截止时未修复（右删失）。
    time_horizon: 限制平均生存时间（RMST）的截断上限，None时用最大观测时间。

    中位生存时间定义为 S(t) 首次 ≤ 0.5 的时刻。
    若曲线全程高于 0.5，则多数漏洞在观测窗口内未完成修复。
    """
    _N = len(survival_times)
    if _N < 3:
        return SurvivalCurve()

    _pairs = sorted(zip(survival_times, event_observed), key=lambda p: p[0])

    # 逐时间点聚合：同一时刻的多个事件合并统计
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

    # 反向累加确定各时刻的风险集规模
    _n_timepoints = len(_unique_times)
    _n_risk = [0] * _n_timepoints
    _remaining = _N
    for _i in range(_n_timepoints):
        _n_risk[_i] = _remaining
        _remaining -= (_events[_i] + _censored[_i])

    # 累积乘积计算生存概率
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

    # 梯形积分计算限制平均生存时间（RMST）
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


# 对数秩检验 — 比较两组漏洞生存曲线是否存在显著差异
# 典型用途：补丁发布前后、严重/非严重漏洞的修复速度对比

def log_rank_test(group_a_times: List[float], group_a_events: List[bool],
                  group_b_times: List[float], group_b_events: List[bool]
                  ) -> Dict[str, float]:
    """对数秩检验：判断两组的生存函数是否同分布。

    零假设 H0：两组生存曲线无差异。
    检验统计量服从 χ²(1)，p 值通过标准正态近似得出。

    返回字典字段：chi2、p_value、hazard_ratio、significant。
    p < 0.05 表明两组修复速度存在统计意义差异。
    """
    # 统一时间轴，标记组别
    _all_data = (
        [(_t, _e, 'a') for _t, _e in zip(group_a_times, group_a_events)] +
        [(_t, _e, 'b') for _t, _e in zip(group_b_times, group_b_events)]
    )
    _all_data.sort(key=lambda x: x[0])

    _n_a = len(group_a_times)
    _n_b = len(group_b_times)
    if _n_a < 3 or _n_b < 3:
        return {'chi2': 0.0, 'p_value': 1.0, 'hazard_ratio': 1.0, 'significant': False}

    _O_a = 0.0   # A组观测事件数
    _E_a = 0.0   # A组期望事件数（H0下）
    _V_a = 0.0   # A组方差

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

        # 更新风险集规模
        _remaining_a -= _events_a
        _remaining_b -= _events_b

    if _V_a < 1e-10:
        return {'chi2': 0.0, 'p_value': 1.0, 'hazard_ratio': 1.0, 'significant': False}

    _chi2 = (_O_a - _E_a) ** 2 / _V_a

    # 标准正态近似计算 χ²(1) 的双尾 p 值
    _p = 1.0 - math.erf(math.sqrt(_chi2) / math.sqrt(2.0))

    # 风险比：A组相对B组的事件发生率比值估计
    _hr = (_O_a / (_O_a + (_n_b - sum(group_b_events)) + 1)
           ) / ((sum(group_a_events) - _O_a + 1) / (_n_a - sum(group_a_events) + 1)) if _O_a > 0 else 0.0

    return {
        'chi2': round(_chi2, 3),
        'p_value': round(max(0.0, min(1.0, _p)), 4),
        'hazard_ratio': round(_hr, 3),
        'significant': _p < 0.05,
    }


# 半衰期估计 — 漏洞修复的中位时间

def median_time_to_fix(times: List[float], events: List[bool]) -> float:
    """漏洞修复半衰期：KM估计的中位生存时间。

    调用 kaplan_meier 并提取 median_survival_time 字段。
    半衰期短反映安全团队响应速度快；半衰期长提示资源不足或感知滞后。
    """
    _curve = kaplan_meier(times, events)
    return _curve.median_survival_time


# 综合风险评分 — 严重度 × 可利用性 × (1 - 修复概率)
# 高严重度且低修复概率的漏洞获得最高优先处理等级

def vulnerability_risk_score(severity_score: float,
                              survival_prob_at_t: float,
                              exploitability_score: float = 5.0) -> float:
    """漏洞优先级评分：严重度 × 可利用度 × 仍存续概率。

    survival_prob_at_t: KM曲线在该时刻的生存概率（未修复概率估计）。
    分值越高，漏洞危害越大且修复前景越不确定，应优先处置。
    """
    return round(severity_score * exploitability_score * (1.0 - survival_prob_at_t + 0.01), 2)


# 条件生存概率 — 已存续 t₀ 天后，继续存续 t₁ 天的概率

def conditional_survival(km_curve: SurvivalCurve,
                          survived_days: float,
                          additional_days: float) -> float:
    """条件生存概率：S(t₀ + t₁ | T > t₀) = S(t₀ + t₁) / S(t₀)。

    用途：已知某漏洞已未被修复持续 N 天，估计未来 M 天内仍不被修复的几率。
    """
    _times = km_curve.times
    _probs = km_curve.survival_probs
    if not _times:
        return 1.0

    # 从已有KM曲线中插值 S(t) 的值
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


# Nelson-Aalen 累积风险 — 小样本下优于 KM 的替代估计量
# H(t) = Σ_{t_i ≤ t} d_i / n_i

def nelson_aalen_cumulative_hazard(times: List[float],
                                     events: List[bool]) -> List[Tuple[float, float]]:
    """Nelson-Aalen 累积风险函数估计。

    H(t) 物理含义：截至时间 t 的事件风险累积总量。
    与 KM 的关系：Ŝ_NA(t) = exp(-Ĥ(t))。在小样本条件中 NA 估计偏误更小。
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


# 脆弱性生命周期阶段检测 — 四阶段划分
# acute (<30天)、chronic (30-180天)、endemic (180-365天)、resolved (已修复/超365天)

def vulnerability_lifecycle_stage(days_since_disclosure: float,
                                    patched: bool = False) -> str:
    """判定漏洞当前所处的生命周期阶段。

    阶段划分依据 Frei et al. SOUPS 2024 的漏洞生态模型：
    acute (0-30天): 厂商评估期，尚未制定修复方案。
    chronic (31-180天): 已知未修复，风险窗口持续积累。
    endemic (181-365天): 长期驻留，可能因依赖链锁定而推迟修复。
    resolved: 已完成修复或超过365天视为归档。
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


# 分层生存分析 — 按标签（严重度/类型）分别估计各子群的生存曲线

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
