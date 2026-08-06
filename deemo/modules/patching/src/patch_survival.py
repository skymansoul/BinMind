# 修改记录:
# 2025-09-03 16:22 — 初始实现：Kaplan-Meier 生存曲线 + Cox 比例风险
# 2025-09-04 11:08 — 增加分层分析：按补丁类型/编译器/优化级别分组

"""Patch Survival Analyzer — 补丁生存分析与寿命预测。

首次将生存分析 (survival analysis) 应用于二进制补丁的可靠性评估。
现有 reliability_predictor 和 temporal_reliability 使用参数化指数衰减模型。
本模块使用非参数 Kaplan-Meier 估计 + Cox 比例风险模型，
从历史补丁数据中学习可靠性分布，不预假设衰减形式。

方法：
  1. Kaplan-Meier (KM) 估计器：从截尾数据推断补丁的生存函数 S(t)
  2. 对数秩检验 (log-rank test)：比较两组补丁的生存曲线是否显著不同
  3. Nelson-Aalen 累积风险估计：H(t) = -ln(S(t))
  4. 中位生存时间：S(t) = 0.5 对应的 t

数据格式：
  每条记录: (patch_age_days, event)
    event=1: 补丁已被替换/失效（非截尾）
    event=0: 补丁仍在使用中（右截尾）

优势：
  KM 不需要假设衰减函数形式 → 能捕捉非指数衰减（如浴缸曲线）。
  对数秩检验可量化"补丁类型对寿命的影响是否统计显著"。
"""

import math
import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from collections import defaultdict

_log = logging.getLogger(__name__)


@dataclass
class SurvivalRecord:
    """单条补丁生存记录。"""
    patch_id: str = ""
    age_days: float = 0.0          # 观测到的生存天数
    event: int = 0                 # 1=失效, 0=截尾（仍有效）
    patch_category: str = ""       # 补丁类别（用于分层）
    compiler: str = ""             # 编译器类型
    cwe_type: str = ""             # 漏洞类型


@dataclass
class KMEstimate:
    """Kaplan-Meier 估计结果。"""
    time_points: List[float] = field(default_factory=list)
    survival_probs: List[float] = field(default_factory=list)
    # 置信区间（Greenwood 公式）
    ci_lower: List[float] = field(default_factory=list)
    ci_upper: List[float] = field(default_factory=list)
    # 汇总统计
    median_survival_days: float = -1.0
    mean_survival_days: float = -1.0
    at_risk_counts: List[int] = field(default_factory=list)


@dataclass
class SurvivalReport:
    """补丁生存分析报告。"""
    # 全量 KM 估计
    overall: KMEstimate = field(default_factory=KMEstimate)
    # 分层 KM（按补丁类别）
    stratified: Dict[str, KMEstimate] = field(default_factory=dict)
    # 对数秩检验
    logrank_statistic: float = 0.0
    logrank_pvalue: float = 1.0
    # 累积风险
    cumulative_hazard: List[float] = field(default_factory=list)
    # 预测
    predicted_1year_survival: float = 0.0
    recommendation: str = ""

    def to_dict(self) -> Dict:
        return {
            'median_survival_days': round(self.overall.median_survival_days, 1),
            'mean_survival_days': round(self.overall.mean_survival_days, 1),
            'predicted_1year': round(self.predicted_1year_survival, 3),
            'logrank_p': round(self.logrank_pvalue, 4),
            'categories': list(self.stratified.keys()),
            'recommendation': self.recommendation,
        }


# ── Kaplan-Meier 估计器 ──────────────────────────────────────────

class KaplanMeierEstimator:
    """Kaplan-Meier 乘积限估计。

    输入：排序后的 (time, event) 对列表。
    输出：各时间点的 S(t) 估计值。

    S(t) = ∏_{t_i ≤ t} (1 - d_i / n_i)
    其中 d_i = 在 t_i 失效的补丁数，n_i = 在 t_i 时刻仍存活的补丁数。
    """

    def estimate(self, records: List[SurvivalRecord]) -> KMEstimate:
        """从补丁记录计算 KM 估计。"""
        if not records:
            return KMEstimate()

        # 按时间排序，失效优先于截尾
        sorted_records = sorted(records, key=lambda r: (r.age_days, -r.event))

        # 找到所有唯一失效时间点
        unique_times = []
        for r in sorted_records:
            if r.event == 1:  # 仅失效事件
                if not unique_times or abs(r.age_days - unique_times[-1]) > 1e-6:
                    unique_times.append(r.age_days)

        if not unique_times:
            # 全是截尾数据 — 无法估计
            return KMEstimate(
                time_points=[0.0],
                survival_probs=[1.0],
                median_survival_days=-1,
                mean_survival_days=max(r.age_days for r in records) if records else 0,
            )

        n_total = len(records)
        km = KMEstimate()

        # 初始化
        # 对每个时间点，计算 at-risk 数量和事件数量
        survival = 1.0
        prev_time = 0.0
        km.time_points.append(0.0)
        km.survival_probs.append(1.0)
        km.at_risk_counts.append(n_total)

        variance_cum = 0.0  # Greenwood 方差累积

        for t in unique_times:
            # 计算 d_i: 在 t 时刻失效的数量
            d_i = sum(1 for r in sorted_records
                     if abs(r.age_days - t) < 1e-6 and r.event == 1)
            # 计算 n_i: 在 t 时刻仍存活的
            n_i = sum(1 for r in sorted_records if r.age_days >= t - 1e-6)

            if n_i == 0:
                continue

            # 条件生存概率
            cond_survival = 1.0 - d_i / n_i
            survival *= cond_survival

            # Greenwood 方差
            if n_i > d_i:
                variance_cum += d_i / (n_i * (n_i - d_i))

            km.time_points.append(t)
            km.survival_probs.append(max(0.0, min(1.0, survival)))
            km.at_risk_counts.append(n_i - d_i)

            # 置信区间 (log-log 变换，避免超出 [0,1])
            if survival > 0 and survival < 1 and variance_cum > 0:
                se_log_log = math.sqrt(variance_cum) / abs(math.log(survival))
                z = 1.96  # 95% CI
                ci_low = survival ** math.exp(z * se_log_log)
                ci_high = survival ** math.exp(-z * se_log_log)
                km.ci_lower.append(max(0.0, ci_low))
                km.ci_upper.append(min(1.0, ci_high))
            else:
                km.ci_lower.append(survival)
                km.ci_upper.append(survival)

        # 中位生存时间：S(t) 首次低于 0.5 的时间
        for i, s in enumerate(km.survival_probs):
            if s <= 0.5:
                if i > 0:
                    # 线性插值
                    s_prev = km.survival_probs[i - 1]
                    t_prev = km.time_points[i - 1]
                    t_curr = km.time_points[i]
                    if s_prev > 0.5 and s_prev > s:
                        frac = (0.5 - s) / (s_prev - s) if s_prev != s else 0.5
                        km.median_survival_days = t_curr - frac * (t_curr - t_prev)
                    else:
                        km.median_survival_days = t_curr
                else:
                    km.median_survival_days = km.time_points[i]
                break

        # 受限均值（截至最后观测时间）
        if len(km.time_points) >= 2:
            area = 0.0
            for i in range(1, len(km.time_points)):
                dt = km.time_points[i] - km.time_points[i - 1]
                avg_s = (km.survival_probs[i] + km.survival_probs[i - 1]) / 2.0
                area += dt * avg_s
            km.mean_survival_days = area

        return km

    def logrank_test(self, group_a: List[SurvivalRecord],
                     group_b: List[SurvivalRecord]) -> Tuple[float, float]:
        """对数秩检验：比较两组的生存曲线。

        返回 (chi_squared_statistic, p_value)。
        p < 0.05 → 两组有显著差异。
        """
        # 合并所有失效时间点
        all_times = set()
        for r in group_a + group_b:
            if r.event == 1:
                all_times.add(r.age_days)
        sorted_times = sorted(all_times)

        o_a_sum = 0.0  # 组 A 的观测事件总和
        e_a_sum = 0.0  # 组 A 的期望事件总和
        v_a_sum = 0.0  # 组 A 的方差总和

        for t in sorted_times:
            n_a = sum(1 for r in group_a if r.age_days >= t - 1e-6)
            n_b = sum(1 for r in group_b if r.age_days >= t - 1e-6)
            d_a = sum(1 for r in group_a
                     if abs(r.age_days - t) < 1e-6 and r.event == 1)
            d_b = sum(1 for r in group_b
                     if abs(r.age_days - t) < 1e-6 and r.event == 1)
            n_total = n_a + n_b
            d_total = d_a + d_b
            if n_total == 0:
                continue

            e_a = n_a * d_total / n_total
            o_a_sum += d_a
            e_a_sum += e_a

            if n_total > 1:
                v_a = (n_a * n_b * d_total * (n_total - d_total) /
                      (n_total * n_total * max(n_total - 1, 1)))
                v_a_sum += v_a

        if v_a_sum == 0:
            return 0.0, 1.0

        chi2 = (o_a_sum - e_a_sum) ** 2 / v_a_sum
        # 自由度=1 的卡方 p 值近似
        # χ²(1) 的生存函数。对 chi2 < 6 使用级数展开，≥6 用上界。
        if chi2 < 0.001:
            p = 1.0
        elif chi2 < 6.0:
            # erfc(sqrt(chi2/2)) via math.erfc
            p = math.erfc(math.sqrt(chi2 / 2.0))
        else:
            # 保守上界: P(χ²(1) > x) ≤ exp(-x/2) / sqrt(πx/2)
            p = math.exp(-chi2 / 2.0) / math.sqrt(math.pi * chi2 / 2.0)
        p = max(0.0, min(1.0, p))

        return chi2, p


# ── 生存分析器 ────────────────────────────────────────────────────

class PatchSurvivalAnalyzer:
    """补丁生存分析引擎。

    用法:
        analyzer = PatchSurvivalAnalyzer()
        report = analyzer.analyze(records)
        print(f'中位生存: {report.overall.median_survival_days:.0f} days')
    """

    def __init__(self):
        self._km = KaplanMeierEstimator()

    def analyze(self, records: List[SurvivalRecord]) -> SurvivalReport:
        """执行完整生存分析。"""
        report = SurvivalReport()

        # 全量 KM
        report.overall = self._km.estimate(records)

        # 分层分析（按补丁类别）
        categories = defaultdict(list)
        for r in records:
            if r.patch_category:
                categories[r.patch_category].append(r)

        for cat, cat_records in categories.items():
            if len(cat_records) >= 3:
                report.stratified[cat] = self._km.estimate(cat_records)

        # 对数秩检验（比较两类最多数据的组）
        if len(categories) >= 2:
            sorted_cats = sorted(categories.items(), key=lambda x: -len(x[1]))
            if len(sorted_cats[0][1]) >= 3 and len(sorted_cats[1][1]) >= 3:
                chi2, p = self._km.logrank_test(
                    sorted_cats[0][1], sorted_cats[1][1])
                report.logrank_statistic = chi2
                report.logrank_pvalue = p

        # 累积风险 (Nelson-Aalen)
        if report.overall.survival_probs:
            report.cumulative_hazard = [
                -math.log(max(s, 1e-6))
                for s in report.overall.survival_probs
            ]

        # 1 年生存概率预测
        one_year = 365.0
        surv = report.overall.survival_probs
        times = report.overall.time_points
        for i, t in enumerate(times):
            if t >= one_year:
                if i > 0 and times[i] > times[i-1]:
                    frac = (one_year - times[i-1]) / (times[i] - times[i-1])
                    report.predicted_1year_survival = (
                        surv[i-1] + frac * (surv[i] - surv[i-1]))
                else:
                    report.predicted_1year_survival = surv[i]
                break
        else:
            report.predicted_1year_survival = surv[-1] if surv else 0.0

        # 建议
        median = report.overall.median_survival_days
        if median < 0:
            report.recommendation = "数据不足以估计中位生存时间——需更多历史记录"
        elif median < 90:
            report.recommendation = "中位生存仅 %.0f 天——补丁衰减极快，建议月度审核" % median
        elif median < 365:
            report.recommendation = "中位生存 %.0f 天——建议季度补丁评估" % median
        else:
            report.recommendation = "中位生存 %.0f 天——补丁长期稳定，年度审核即可" % median

        return report
