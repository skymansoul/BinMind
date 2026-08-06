"""
鞅校准检验 -- 用鞅差分检验统计验证传播模型置信度的校准质量。

问题：
  PropagationGraph的贝叶斯更新机制对边置信度做逐次更新。
  若更新是良好校准的，则预测误差序列应构成鞅差序列(martingale difference):
    E[error_{t+1} | past_errors] = 0
  若偏离此性质，说明模型存在系统性偏差——要么过度自信(低估不确定性)，
  要么过度保守(高估不确定性)。

方案：
  三种互补的鞅性质检验:
  1. Ljung-Box Q检验: errors是否序列自相关（鞅差序列应无自相关）
  2. Lo-MacKinlay方差比检验: Var(k步和)/(k * Var(1步)) 是否≈1
  3. Kolmogorov-Smirnov检验: 标准化errors是否服从标准正态

  复合校准评分 = 三检验p值的调和平均——任意一项不通过即拉低总分。

与已有工作的区分：
  鞅检验广泛用于金融市场的有效性检验(弱式有效市场假说)和
  概率预测的校准评估。从未应用于漏洞传播图贝叶斯更新的校准验证。
  本模块填补了传播模型的形式化统计校准评估空白。

ref: Lo & MacKinlay (1988) "Stock Market Prices do not Follow Random Walks".
ref: Dawid (1984) "Statistical Theory: The Prequential Approach" -- 概率预测校准。
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class CalibrationReport:
    """传播模型校准检验报告。"""
    ljung_box_stat: float
    ljung_box_pvalue: float
    variance_ratio: float         # k步方差比 (应≈1)
    variance_ratio_z: float       # VR检验的Z统计量
    variance_ratio_pvalue: float
    ks_stat: float
    ks_pvalue: float
    composite_score: float        # 0-1, 越高校准越好
    is_calibrated: bool           # 综合判定
    n_observations: int


class MartingaleCalibrationTester:
    """鞅校准检验器 -- 传播模型置信度更新的统计验证。

    用法::

        graph = PropagationGraph()
        # ... 经过多轮贝叶斯更新 ...
        tester = MartingaleCalibrationTester()
        report = tester.test(graph, error_history)
        print(f"Calibrated: {report.is_calibrated}, score={report.composite_score:.3f}")
    """

    def __init__(self, lags_vr: int = 4, significance: float = 0.05,
                 ljung_box_lags: int = 5):
        self._k = lags_vr               # 方差比检验的步数
        self._alpha = significance      # 显著性水平
        self._lb_lags = ljung_box_lags  # Ljung-Box滞后阶数

    def test(self, graph: PropagationGraph,
             error_history: Optional[List[float]] = None
             ) -> CalibrationReport:
        """执行全部鞅校准检验。

        error_history: 预测误差序列(observed - predicted confidence)。
                       若为None，从图的边置信度更新历史自动提取。
        """
        errors = error_history or self._extract_errors(graph)
        n = len(errors)

        if n < self._lb_lags + 2:
            return CalibrationReport(0, 1, 1, 0, 1, 0, 1, 1.0, True, n)

        # 1. Ljung-Box Q检验
        lb_stat, lb_pval = self._ljung_box_test(errors)

        # 2. Lo-MacKinlay方差比检验
        vr, vr_z, vr_pval = self._variance_ratio_test(errors)

        # 3. KS正态性检验
        ks_stat, ks_pval = self._ks_normality_test(errors)

        # 复合校准评分: 三p值的调和平均
        pvals = [max(lb_pval, 1e-9), max(vr_pval, 1e-9), max(ks_pval, 1e-9)]
        composite = 3.0 / sum(1.0 / p for p in pvals)

        calibrated = (
            lb_pval > self._alpha and
            abs(vr - 1.0) < 0.15 and  # VR在[0.85, 1.15]内
            ks_pval > self._alpha / 2  # KS较宽松（正态性对传播数据要求高）
        )

        return CalibrationReport(
            ljung_box_stat=round(lb_stat, 4),
            ljung_box_pvalue=round(lb_pval, 4),
            variance_ratio=round(vr, 4),
            variance_ratio_z=round(vr_z, 4),
            variance_ratio_pvalue=round(vr_pval, 4),
            ks_stat=round(ks_stat, 4),
            ks_pvalue=round(ks_pval, 4),
            composite_score=round(composite, 4),
            is_calibrated=calibrated,
            n_observations=n,
        )

    def _extract_errors(self, graph: PropagationGraph) -> List[float]:
        """从传播图的边置信度更新中提取预测误差序列。

        误差 = 新观测置信度 - 先验期望置信度
        （贝叶斯更新前的prior与更新后的posterior之差）
        """
        errors: List[float] = []
        for (src, tgt), edge in graph._edges.items():
            if edge.evidence_count > 0:
                # 预测误差代理: (贝叶斯更新后 - 更新前) = 创新量
                prior = edge.prior_confidence
                posterior = edge.posterior_confidence
                errors.append(posterior - prior)
        return errors

    def _ljung_box_test(self, errors: List[float]
                         ) -> Tuple[float, float]:
        """Ljung-Box Q检验 -- H0: errors无序列自相关。

        Q = n*(n+2) * sum_{j=1..h} r_j^2 / (n-j)
        r_j = 滞后j的自相关系数。
        Q ~ χ²(h) 在大样本下（若H0成立）。
        """
        n = len(errors)
        mean_e = sum(errors) / n
        var_e = sum((e - mean_e)**2 for e in errors) / n

        if var_e < 1e-12:
            return 0.0, 1.0

        Q = 0.0
        max_lag = min(self._lb_lags, n - 2)
        for lag in range(1, max_lag + 1):
            cov = sum((errors[i] - mean_e) * (errors[i - lag] - mean_e)
                     for i in range(lag, n)) / n
            r = cov / var_e
            Q += (r ** 2) / (n - lag)

        Q *= n * (n + 2)
        # χ² p-value 近似: Wilson-Hilferty
        pval = self._chi2_survival(Q, max_lag)
        return Q, pval

    def _variance_ratio_test(self, errors: List[float]
                              ) -> Tuple[float, float, float]:
        """Lo-MacKinlay方差比检验。

        VR(k) = Var(k步和) / (k * Var(1步))
        鞅序列下VR(k)≈1。VR(k)<1 → 均值回复(过度保守)。
        VR(k)>1 → 趋势跟踪(过度自信)。
        """
        n = len(errors)
        k = min(self._k, n // 2)
        if k < 2:
            return 1.0, 0.0, 1.0

        mean_e = sum(errors) / n

        # 1步方差
        var1 = sum((e - mean_e)**2 for e in errors) / (n - 1)

        # k步和
        k_sums = []
        for i in range(n - k + 1):
            k_sums.append(sum(errors[i:i+k]))
        mean_ks = sum(k_sums) / len(k_sums)
        var_k = sum((s - mean_ks)**2 for s in k_sums) / (len(k_sums) - 1)

        vr = var_k / (k * var1) if var1 > 1e-12 else 1.0

        # Z统计量 (Lo-MacKinlay 同方差假设)
        # Z = (VR-1) / sqrt(2*(2k-1)*(k-1) / (3k*n))
        se = math.sqrt(2.0 * (2*k - 1) * (k - 1) / (3.0 * k * n))
        z_val = (vr - 1.0) / max(se, 1e-9)
        pval = 2.0 * (1.0 - self._normal_cdf(abs(z_val)))

        return vr, z_val, pval

    def _ks_normality_test(self, errors: List[float]
                            ) -> Tuple[float, float]:
        """KS检验 -- H0: 标准化errors服从标准正态。

        标准化: (e - mean) / std
        """
        n = len(errors)
        mean_e = sum(errors) / n
        var_e = sum((e - mean_e)**2 for e in errors) / max(n - 1, 1)
        std_e = math.sqrt(max(var_e, 1e-12))

        standardized = sorted([(e - mean_e) / std_e for e in errors])

        # 经验CDF vs 正态CDF的最大绝对差
        d_max = 0.0
        for i, x in enumerate(standardized):
            ecdf = (i + 1) / n
            ncdf = self._normal_cdf(x)
            d_max = max(d_max, abs(ecdf - ncdf))

        # KS统计量近似p值 (Kolmogorov分布)
        # p ≈ 2 * sum_{j=1}^{∞} (-1)^{j-1} * exp(-2*j^2 * (sqrt(n)*d)^2)
        lam = (math.sqrt(n) + 0.12 + 0.11 / math.sqrt(n)) * d_max
        pval = self._ks_survival(lam)

        return d_max, pval

    # ---- 统计辅助函数 ----

    @staticmethod
    def _normal_cdf(x: float) -> float:
        """标准正态CDF。"""
        if x < -8.0:
            return 0.0
        if x > 8.0:
            return 1.0
        t = 1.0 / (1.0 + 0.2316419 * abs(x))
        poly = ((((1.330274429 * t - 1.821255978) * t
                  + 1.781477937) * t - 0.356563782) * t
                + 0.319381530) * t
        phi = poly * math.exp(-x * x / 2.0) / math.sqrt(2.0 * math.pi)
        return 1.0 - phi if x >= 0 else phi

    @staticmethod
    def _chi2_survival(x: float, df: int) -> float:
        """χ²分布的尾部概率近似。"""
        if x <= 0:
            return 1.0
        # Wilson-Hilferty变换: (x/df)^(1/3) ≈ N(1-2/(9df), 2/(9df))
        z = ((x / df) ** (1.0/3.0) - 1.0 + 2.0/(9.0*df)) / math.sqrt(2.0/(9.0*df))
        return 1.0 - MartingaleCalibrationTester._normal_cdf(z)

    @staticmethod
    def _ks_survival(lam: float) -> float:
        """Kolmogorov分布的尾部概率。"""
        if lam < 0.01:
            return 1.0
        if lam > 5.0:
            return 0.0
        s = 0.0
        for j in range(1, 6):
            sign = 1 if j % 2 == 1 else -1
            s += sign * 2.0 * math.exp(-2.0 * j * j * lam * lam)
        return min(1.0, max(0.0, s))
