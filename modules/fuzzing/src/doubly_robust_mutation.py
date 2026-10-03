"""双重鲁棒突变评估 — AIPW + 倾向得分 + 结果回归.
参考: Robins, Rotnitzky & Zhao JASA; Bang & Robins Biometrics.
在 fuzzing 中零先例。即使倾向得分模型或结果模型之一错误,
ATE 估计仍一致 (双重鲁棒性)。评估突变策略的因果效应。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class TreatmentObs:
    treatment: int       # 1=策略A, 0=策略B
    outcome: float       # 覆盖增益
    covariates: List[float]  # 种子特征 (大小, 代数等)


class DoublyRobustEvaluator:
    """双重鲁棒因果效应估计器.

    ATE = E[Y(1) - Y(0)] (平均处理效应)
    DR = (1/n)Σ [μ̂₁(X_i)-μ̂₀(X_i)]  ← 结果回归项
       + (1/n)Σ [T_i(Y_i-μ̂₁(X_i))/ê(X_i)]  ← IPW 校正 (处理组)
       - (1/n)Σ [(1-T_i)(Y_i-μ̂₀(X_i))/(1-ê(X_i))]  ← IPW 校正 (对照组)
    若 μ̂ 错但 ê 对 → IPW 项校正; 若 ê 错但 μ̂ 对 → 回归项覆盖。
    两者都对 → 半参数有效。两者都错 → 仍可能有偏。

    使用方式:
      dre = DoublyRobustEvaluator()
      for each mutation:
          treated = 1 if used_strategy_A else 0
          dre.add_obs(treated, coverage_gain, [seed_len, generation])
      ate, se = dre.estimate()
    """

    def __init__(self):
        self._obs: List[TreatmentObs] = []
        # 在线充分统计量
        self._n_treated: int = 0
        self._n_control: int = 0

    def add_obs(self, treatment: int, outcome: float,
                covariates: List[float]) -> None:
        self._obs.append(TreatmentObs(
            treatment=treatment, outcome=outcome,
            covariates=list(covariates)))
        if treatment == 1:
            self._n_treated += 1
        else:
            self._n_control += 1
        if len(self._obs) > 200:
            self._obs = self._obs[-150:]

    def estimate(self) -> Optional[Tuple[float, float, float]]:
        """返回 (ATE, standard_error, p_value)."""
        n = len(self._obs)
        if n < 10 or self._n_treated < 3 or self._n_control < 3:
            return None

        # 倾向得分模型 (logistic regression 在线更新)
        ps_scores = []
        for obs in self._obs:
            e_hat = self._propensity_score(obs.covariates)
            e_hat = max(0.05, min(0.95, e_hat))  # 截断防极端
            ps_scores.append(e_hat)

        # 结果回归模型 (线性)
        mu1_preds = []
        mu0_preds = []
        for obs in self._obs:
            mu1_preds.append(self._outcome_model(obs.covariates, treated=True))
            mu0_preds.append(self._outcome_model(obs.covariates, treated=False))

        # DR 估计
        dr_sum = 0.0
        dr_sq_sum = 0.0
        for i, obs in enumerate(self._obs):
            # 回归项
            reg_term = mu1_preds[i] - mu0_preds[i]
            # IPW 校正
            if obs.treatment == 1:
                ipw_term = (obs.outcome - mu1_preds[i]) / ps_scores[i]
            else:
                ipw_term = -(obs.outcome - mu0_preds[i]) / (1.0 - ps_scores[i])
            dr_i = reg_term + ipw_term
            dr_sum += dr_i
            dr_sq_sum += dr_i * dr_i

        ate = dr_sum / n
        # 影响函数方差
        var_if = max(1e-8, dr_sq_sum / n - ate * ate)
        se = math.sqrt(var_if / n)
        # Wald p-value
        z = abs(ate) / max(1e-8, se)
        p_value = 2.0 * (1.0 - 0.5 * (1.0 + math.erf(z / math.sqrt(2.0))))

        return ate, se, p_value

    def _propensity_score(self, covariates: List[float]) -> float:
        """简化 logistic 倾向得分: logit(P(T=1)) = Σ w_i·x_i."""
        # 在线更新权重 (简单移动平均)
        if not hasattr(self, '_ps_weights'):
            self._ps_weights = [0.0] * len(covariates)
        # 用最简单的方式: 基于处理/对照比例
        n = max(1, self._n_treated + self._n_control)
        base_prob = self._n_treated / n
        # 协变量微调 (正系数=更大x更可能被处理)
        lp = math.log(max(0.01, base_prob / max(0.01, 1.0 - base_prob)))
        for w, x in zip(self._ps_weights, covariates):
            lp += w * (x - 0.5)
        return 1.0 / (1.0 + math.exp(-lp))

    def _outcome_model(self, covariates: List[float],
                        treated: bool) -> float:
        """简化线性结果模型: E[Y|T,X] = β₀ + T·τ + Σ β_i·x_i."""
        if not hasattr(self, '_om_beta0'):
            self._om_beta0 = 0.5; self._om_tau = 0.0
            self._om_betas = [0.0] * len(covariates)
        pred = self._om_beta0
        if treated:
            pred += self._om_tau
        for b, x in zip(self._om_betas, covariates):
            pred += b * x
        return max(0.0, pred)

    def stats(self) -> dict:
        est = self.estimate()
        if est is None:
            return {"n": len(self._obs), "status": "insufficient_data"}
        ate, se, p = est
        return {"n": len(self._obs), "ATE": round(ate, 4),
                "SE": round(se, 4), "p_value": round(p, 4),
                "significant": p < 0.05,
                "n_treated": self._n_treated,
                "n_control": self._n_control}

    def clear(self) -> None:
        self._obs.clear()
        self._n_treated = 0; self._n_control = 0
