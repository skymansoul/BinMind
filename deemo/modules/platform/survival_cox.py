"""
Cox比例风险模型 — 半参数生存回归的独立实现。

与 propagation_survival.py 解耦：KaplanMeierEstimator 做非参数估计，
CoxPHModel 做半参数回归。分开放置允许独立测试和替换。

技术选型：
  全参数模型（Weibull, Log-normal）要求对基准风险分布做强假设，
  在漏洞利用场景下不成立——不同平台层的利用时间分布差异显著。
  半参数 Cox 模型不需要假设基准风险形式，仅估计协变量效应。

Breslow 偏似然：仅利用事件发生的排序信息，忽略事件间精确时间间隔。
这对 CVE 数据尤其合适——多数 CVE 只有"公开日期"和"首次野外利用日期"
两个时间点，缺乏精确的事件间隔。

SGD 而非 BFGS：样本量 <1000 时 BFGS 收敛更快，但需要 Hessian 近似矩阵
的存储和求逆。SGD 的额外优势在于可增量更新——新 CVE 加入时不需全量重算。
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence, Tuple

from .propagation_survival import SurvivalEvent


class CoxPHModel:
    """Cox 比例风险模型 — 半参数生存回归。

    h(t|x) = h₀(t) * exp(Σᵢ βᵢ · xᵢ)
    其中 h₀(t) 为基准风险（非参数估计），βᵢ 为协变量系数。

    本实现使用 Breslow 偏似然法估算 β。梯度下降优化，非闭式解。
    设计选择：
      - 样本量小（<1000）时 BFGS 精度高但收敛慢
      - 此处采用随机梯度下降 + 学习率退火，保证工程可用
    """

    def __init__(self, learning_rate: float = 0.01, max_iter: int = 200):
        self._lr = learning_rate
        self._max_iter = max_iter
        self._coefficients: Dict[str, float] = {}
        self._baseline_cumhaz: List[Tuple[float, float]] = []
        self._fitted = False

    def fit(self, events: Sequence[SurvivalEvent],
            covariate_names: Optional[List[str]] = None) -> Dict[str, float]:
        """拟合 Cox PH 模型 — 返回 {协变量名: 系数}。

        协变量名从第一条事件的 covariates dict 自动提取。
        """
        if not events:
            return {}

        if covariate_names is None:
            covariate_names = list(events[0].covariates.keys())

        # 事件索引：按发现→利用时间排序
        indexed: List[Tuple[float, bool, Dict[str, float]]] = []
        for ev in events:
            t = ev.event_time - ev.discovery_time if ev.event_time else ev.observation_end - ev.discovery_time
            indexed.append((max(t, 0.01), ev.event_time is not None, {
                k: ev.covariates.get(k, 0.0) for k in covariate_names
            }))
        indexed.sort(key=lambda x: x[0])

        n_vars = len(covariate_names)
        betas = [0.0] * n_vars

        # SGD 优化 Breslow 偏似然
        for iteration in range(self._max_iter):
            lr = self._lr / (1.0 + 0.001 * iteration)
            grad = [0.0] * n_vars
            n_events = 0

            for i, (ti, is_event, covs_i) in enumerate(indexed):
                if not is_event:
                    continue
                n_events += 1

                risk_denom = 0.0
                risk_weighted: List[float] = [0.0] * n_vars
                for j, (tj, _, covs_j) in enumerate(indexed):
                    if tj >= ti:
                        eta_j = sum(betas[k] * covs_j[name] for k, name in enumerate(covariate_names))
                        w = math.exp(eta_j)
                        risk_denom += w
                        for k in range(n_vars):
                            risk_weighted[k] += w * covs_j[covariate_names[k]]

                if risk_denom < 1e-10:
                    continue

                for k in range(n_vars):
                    grad[k] += covs_i[covariate_names[k]] - risk_weighted[k] / risk_denom

            if n_events == 0:
                break

            max_grad = max(abs(g) for g in grad)
            for k in range(n_vars):
                betas[k] += lr * grad[k]

            if max_grad < 1e-4:
                break

        self._coefficients = {name: betas[k] for k, name in enumerate(covariate_names)}
        self._fitted = True
        self._estimate_baseline(indexed, covariate_names, betas)

        return dict(self._coefficients)

    def predict_hazard_ratio(self, covariates: Dict[str, float]) -> float:
        """给定协变量，返回相对于基准风险的风险比率 exp(Σ β·x)。"""
        if not self._fitted:
            return 1.0
        log_hr = sum(self._coefficients.get(k, 0.0) * v for k, v in covariates.items())
        return math.exp(log_hr)

    def predict_survival(self, covariates: Dict[str, float],
                         times: List[float]) -> List[float]:
        """预测在给定协变量下的生存概率序列 S(t|x)。"""
        hr = self.predict_hazard_ratio(covariates)
        surv = []
        for t in times:
            cumhaz = self._baseline_cumhaz_at(t)
            surv.append(math.exp(-cumhaz * hr))
        return surv

    def _estimate_baseline(self, indexed: List[Tuple[float, bool, Dict[str, float]]],
                           names: List[str], betas: List[float]) -> None:
        """Breslow 估计器 — 累积基准风险 H₀(t)。"""
        cumhaz = 0.0
        self._baseline_cumhaz = [(0.0, 0.0)]

        for ti, is_event, covs_i in indexed:
            if not is_event:
                continue
            risk_sum = 0.0
            for tj, _, covs_j in indexed:
                if tj >= ti:
                    eta = sum(betas[k] * covs_j[name] for k, name in enumerate(names))
                    risk_sum += math.exp(eta)
            if risk_sum > 1e-10:
                cumhaz += 1.0 / risk_sum
            self._baseline_cumhaz.append((ti, cumhaz))

    def _baseline_cumhaz_at(self, t: float) -> float:
        """基准累积风险在时间 t 的插值。"""
        if not self._baseline_cumhaz:
            return 0.0
        lo, hi = 0, len(self._baseline_cumhaz) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self._baseline_cumhaz[mid][0] <= t:
                lo = mid
            else:
                hi = mid - 1
        return self._baseline_cumhaz[lo][1]
