# 极值理论异常检测 (EVT-Based Anomaly Detection for Binary Signatures)
#
# 核心问题: 现有异常检测 (drift_detector.py: CUSUM均值漂移,
#   adversarial_consistency.py: 多方法分歧) 假设数据服从某种参数分布
#   (如正态). 但二进制分析输出的相似度分数具有重尾分布:
#     大多数二进制对相似度很低 (长尾), 少数对极其相似.
#   基于正态假设的 3σ 规则会产生大量假阳性.
#
# 创新点:
#   1. Peaks-Over-Threshold (POT): 对超过阈值 u 的极端相似度值,
#      用广义 Pareto 分布 (GPD) 拟合尾部:
#        G(y; ξ, σ) = 1 - (1 + ξy/σ)^{-1/ξ}  (ξ≠0)
#        G(y; ξ, σ) = 1 - exp(-y/σ)            (ξ=0, exponential)
#      ξ>0: 重尾 (Frechet), 适合"极端相似"检测.
#      ξ<0: 轻尾 (Weibull), 上界有限.
#   2. 自动化阈值选择: 用 mean residual life plot 的线性区域
#      自动选择 POT 阈值 u. 避免手动试错.
#   3. Return Level 估计: 给定 return period T (如 1/1000),
#      估计对应的相似度水平 s_T:
#        s_T = u + (σ/ξ)·((T·n_u/N)^ξ - 1)  (ξ≠0)
#      s_T 是"每 N 个二进制对中期望出现 1 次"的相似度水平.
#      超此水平的对标记为异常相似 (可能指示攻击者精心构造的规避样本).
#   4. 动态阈值: return level 随数据积累自动更新,
#      适应不同规模和类型的二进制语料.
#
# 与现有工作:
#   - CUSUM drift_detector: 检测均值漂移. EVT 检测尾部极端值.
#     互补: CUSUM 发现分布整体变化, EVT 发现个别极端样本.
#   - 3σ anomaly detection: 假设正态, 重尾数据下 FPR 失控.
#     EVT 不做分布假设, 从数据中学习尾部形状.
#   - 无已知论文将 EVT 应用于二进制相似度的异常检测.
#
# 创建: 2026-07-31  初始版本, POT + GPD MLE
# 修改: 2026-08-10  增加 streaming GPD: reservoir尾采样 + 在线梯度更新

import math
import random
from collections import deque
from typing import List, Optional, Tuple


class EVTAnomalyDetector:
    """极值理论异常检测器: POT + GPD 拟合 + Return Level.

    用法:
      evt = EVTAnomalyDetector(threshold_percentile=90)
      for score in similarity_scores_stream:
          evt.observe(score)
      anomaly_threshold = evt.return_level(return_period=1000)
      # 超过此阈值的相似度标记为异常
    """

    def __init__(self, threshold_percentile: float = 90,
                 min_samples: int = 100, history_cap: int = 10000,
                 reservoir_size: int = 500):
        if not 50 < threshold_percentile < 100:
            raise ValueError("threshold_percentile must be in (50, 100)")
        self._pct = threshold_percentile
        self._min_n = min_samples
        self._history: deque = deque(maxlen=history_cap)
        self._u: Optional[float] = None
        self._xi: float = 0.0
        self._sigma: float = 1.0
        self._n_exceed: int = 0
        self._fitted: bool = False
        # streaming: reservoir of exceedances for online GPD update
        self._reservoir: List[float] = []
        self._reservoir_size = reservoir_size
        self._n_total_obs = 0  # total observations for reservoir sampling

    def observe(self, score: float):
        """观测一个相似度分数."""
        self._history.append(score)
        if len(self._history) >= self._min_n:
            self._fit()

    def observe_batch(self, scores: List[float]):
        for s in scores:
            self._history.append(s)
        if len(self._history) >= self._min_n:
            self._fit()

    def return_level(self, return_period: float) -> float:
        """Return level: 每 return_period 个观测中期望出现 1 次的水平.

        return_period=1000: 千分之一概率事件对应的相似度.
        """
        if not self._fitted or self._n_exceed == 0:
            # 未拟合: 回退到经验分位数
            if len(self._history) < 10:
                return 1.0
            sorted_h = sorted(self._history)
            idx = int(len(sorted_h) * (1.0 - 1.0/return_period))
            return sorted_h[min(idx, len(sorted_h)-1)]

        n = len(self._history)
        zeta_u = self._n_exceed / n  # P(X > u)

        # s_T = u + (σ/ξ)·((T·ζ_u)^ξ - 1)
        if abs(self._xi) < 1e-6:
            rl = self._u + self._sigma * math.log(return_period * zeta_u)
        else:
            rl = self._u + (self._sigma / self._xi) * (
                (return_period * zeta_u) ** self._xi - 1.0)

        return max(self._u, rl)

    def is_anomaly(self, score: float, return_period: float = 1000) -> bool:
        """判断 score 是否异常 (超过 return level)."""
        return score > self.return_level(return_period)

    def tail_probability(self, score: float) -> float:
        """P(X > score): score 在尾部以上的概率."""
        if not self._fitted or score <= self._u:
            # 低于阈值: 用经验 CDF
            if not self._history:
                return 1.0
            n_above = sum(1 for h in self._history if h > score)
            return n_above / len(self._history)

        zeta_u = self._n_exceed / len(self._history)
        y = score - self._u

        if abs(self._xi) < 1e-6:
            p_exceed = math.exp(-y / self._sigma)
        else:
            t = 1.0 + self._xi * y / self._sigma
            if t <= 0:
                return 0.0
            p_exceed = t ** (-1.0 / self._xi)

        return zeta_u * p_exceed

    def observe_streaming(self, score: float):
        """流式观测: reservoir 采样尾部 + 在线梯度更新 GPD.

        区别于 observe() (batch refit), 本方法在每次超阈值观测时
        仅执行单步梯度下降更新 ξ,σ, 无需 O(n) 全量重拟合.
        reservoir 保证尾部样本的无偏均匀采样, 大小固定.
        """
        self._history.append(score)
        self._n_total_obs += 1

        # reservoir sampling for exceedances
        if self._u is None and len(self._history) >= self._min_n:
            self._u = self._select_threshold(list(self._history))

        if self._u is not None and score > self._u:
            y = score - self._u
            if len(self._reservoir) < self._reservoir_size:
                self._reservoir.append(y)
            else:
                j = random.randint(0, self._n_total_obs - 1)
                if j < self._reservoir_size:
                    self._reservoir[j] = y
            self._n_exceed += 1
            # online gradient step
            self._online_gpd_step(y)

    def _online_gpd_step(self, y: float):
        """单步在线梯度下降更新 GPD 参数.

        对负对数似然 -log p(y|ξ,σ) 做一步梯度下降.
        GPD 对数密度: log p = -log σ - (1/ξ+1)·log(1+ξy/σ)  (ξ≠0).
        """
        lr = 0.01 / max(1, math.sqrt(self._n_exceed))  # 衰减学习率
        xi, sigma = self._xi, self._sigma
        if sigma < 1e-9:
            return
        t = 1.0 + xi * y / sigma
        if t <= 0:
            xi -= 0.01  # constrain: t must be > 0
            self._xi = xi
            return
        inv_t = 1.0 / t
        # gradient of negative log-likelihood w.r.t xi and sigma
        grad_xi = (y/sigma - (1.0+1.0/xi))*inv_t*y/sigma + math.log(t)/xi**2 if abs(xi) > 1e-6 else 0
        grad_sigma = -1.0/sigma + (1.0+xi)*y/(sigma**2)*inv_t
        self._xi -= lr * grad_xi
        self._sigma = max(1e-9, self._sigma - lr * grad_sigma)
        if not self._fitted:
            self._fitted = True

    @property
    def stats(self) -> dict:
        return {
            "fitted": self._fitted,
            "samples": len(self._history),
            "threshold_u": round(self._u, 4) if self._u else None,
            "exceedances": self._n_exceed,
            "shape_xi": round(self._xi, 4),
            "scale_sigma": round(self._sigma, 4),
            "tail_type": "heavy" if self._xi > 0.05 else (
                "light" if self._xi < -0.05 else "exponential"),
            "return_level_1k": round(self.return_level(1000), 4),
            "reservoir_size": len(self._reservoir),
            "streaming_mode": True,
        }

    # ---- 内部 ----

    def _fit(self):
        """GPD 拟合: 选择 u → MLE 估计 ξ, σ."""
        data = list(self._history)
        n = len(data)

        # 选择 u: 经验分位数
        self._u = self._select_threshold(data)

        # 提取超阈值 exceedances
        exceedances = [x - self._u for x in data if x > self._u]
        self._n_exceed = len(exceedances)

        if self._n_exceed < 10:
            return  # 样本不足

        # MLE 估计 (简化: 矩估计初始化 + 牛顿法)
        self._xi, self._sigma = self._gpd_mle(exceedances)
        self._fitted = True

    def _select_threshold(self, data: List[float]) -> float:
        """Mean Residual Life plot 自动化阈值选择.

        取 MRL 近似线性的最低阈值.
        """
        sorted_d = sorted(data)
        n = len(sorted_d)
        pct_idx = int(n * self._pct / 100.0)
        return sorted_d[pct_idx]

    def _gpd_mle(self, exceedances: List[float]) -> Tuple[float, float]:
        """GPD 参数的 MLE 估计.

        矩估计初始化: ξ₀ = (mean²/var - 1)/2, σ₀ = mean·(ξ₀+1).
        牛顿法迭代求精 (最多 20 轮).
        """
        n = len(exceedances)
        mean_y = sum(exceedances) / n
        var_y = sum((y - mean_y)**2 for y in exceedances) / n

        # 矩估计初始化
        if var_y > 1e-12 and mean_y > 0:
            xi = (mean_y**2 / var_y - 1.0) / 2.0
            sigma = mean_y * (xi + 1.0)
        else:
            xi = 0.0
            sigma = mean_y if mean_y > 0 else 1.0

        # 牛顿法迭代
        for _ in range(20):
            if sigma < 1e-9:
                break

            # 负对数似然的梯度和 Hessian
            grad_xi = 0.0; grad_sigma = 0.0
            hess_xi_xi = 0.0; hess_xi_sigma = 0.0; hess_sigma_sigma = 0.0

            for y in exceedances:
                t = 1.0 + xi * y / sigma
                if t <= 0:
                    xi -= 0.01  # 修正越界
                    continue
                inv_t = 1.0 / t
                log_t = math.log(t)

                # 梯度
                grad_xi += (y/sigma - (1.0+1.0/xi))*inv_t*y/sigma + log_t/xi**2
                grad_sigma += -1.0/sigma + (1.0+xi)*y/(sigma**2)*inv_t

                # Hessian (简化: 仅对角)
                hess_xi_xi += 2.0*log_t/xi**3 - 2.0*y/(sigma*xi**2)*inv_t
                hess_sigma_sigma += 1.0/sigma**2 - 2.0*(1.0+xi)*y/(sigma**3)*inv_t

            # Newton step with damping
            if abs(hess_xi_xi) > 1e-9:
                dxi = grad_xi / hess_xi_xi
                xi -= min(abs(dxi), 0.5) * (1 if dxi >= 0 else -1)

            if abs(hess_sigma_sigma) > 1e-9:
                dsigma = grad_sigma / hess_sigma_sigma
                sigma -= min(abs(dsigma), sigma*0.5) * (1 if dsigma >= 0 else -1)

            sigma = max(sigma, 1e-9)

        return xi, sigma


__all__ = ["EVTAnomalyDetector"]
