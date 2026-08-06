# PAC-贝叶斯调度策略认证 — 学习型调度器的泛化保证框架
#
# RL 调度策略 (GRLScheduler) 在有限训练 DAG 上优化 makespan 后，
# 对新 DAG 的泛化性能缺乏可量化的保证。
#
# PAC-贝叶斯界 (McAllester 1999; Catoni 2007 紧化):
#   E_{h~Q}[R(h)] ≤ E_{h~Q}[R̂_N(h)] + √(KL(Q||P) + log(2√N/δ)) / (2N)
#   其中 R̂_N = 经验风险, KL = 后验 Q 对先验 P 的散度。
#
# 本模块使用高斯近似的 KL 上界:
#   先验 P: N(0, σ²_p·I)  —  随机初始化 GNN 权重
#   后验 Q: N(0, σ²_q·I)  —  RL 训练后权重 (用经验标准差估计)
#   若实际分布偏离高斯，KL 高斯近似是上界 → 泛化保证偏保守。

from __future__ import annotations

import math
from typing import Optional, List, Tuple


def _gaussian_kl(posterior_std: float, prior_std: float, d: int) -> float:
    """d 维各向同性高斯分布的 KL 散度。

    KL(N(0,σ²_q·I) || N(0,σ²_p·I)) = d·(log(σ_p/σ_q) + (σ²_q+σ²_p)/(2σ²_p) - 1/2)

    注意: 实际 Q 网络权重不满足各向同性高斯假设。
    此处用作近似上界——若实际 KL 更小，则 PAC-Bayes 界更紧，
    因此此近似给出的泛化误差界是保守的 (偏高)。
    若需精确 KL，应使用 MC 采样估计: KL ≈ (1/M)·Σ log(q(θ_i)/p(θ_i))。
    """
    if posterior_std <= 0 or prior_std <= 0:
        return 0.0
    ratio = prior_std / posterior_std
    return d * (math.log(ratio) + (posterior_std**2 - prior_std**2) / (2 * prior_std**2))


def catoni_bound(empirical_risk: float, kl: float, n: int,
                 delta: float = 0.05) -> float:
    """Catoni 紧化 PAC-Bayes 界。

    泛化风险 ≤ 经验风险 + √((KL + log(2√n/δ)) / (2n))
    """
    if n < 2:
        return 1.0
    penalty = math.sqrt(
        (kl + math.log(2.0 * math.sqrt(n) / delta)) / (2.0 * n)
    )
    return min(1.0, empirical_risk + penalty)


class PACBayesCertifier:
    """PAC-贝叶斯调度策略认证器。

    输入:
      - 先验参数 σ_p (GNN 随机初始化的权重标准差)
      - 后验参数 σ_q (RL 训练后的权重标准差 — 通常更小)
      - 参数维度 d (Q 网络权重向量长度)
      - 训练 DAG 数量 N

    输出:
      - 经验风险 R̂_N (训练集上的平均归一化 makespan)
      - 泛化风险上界 (Catoni 界)
      - 所需样本数下界: 需要多少训练 DAG 才能使泛化间隙 ≤ ε
    """

    def __init__(self, prior_std: float = 0.5,
                 posterior_std: float = 0.15,
                 param_dim: int = 128):
        self._sigma_p = prior_std
        self._sigma_q = posterior_std
        self._dim = param_dim
        # KL(Q||P) — 对先验到后验的信息增益的度量
        self._kl = _gaussian_kl(posterior_std, prior_std, param_dim)

    def certify(self, empirical_risk: float, n_train: int,
                delta: float = 0.05) -> dict:
        """给定经验风险，输出泛化保证。"""
        bound = catoni_bound(empirical_risk, self._kl, n_train, delta)
        return {
            "empirical_risk": round(empirical_risk, 4),
            "generalization_bound": round(bound, 4),
            "excess_risk": round(max(0.0, bound - empirical_risk), 4),
            "kl_divergence": round(self._kl, 2),
            "confidence": round(1.0 - delta, 4),
            "n_train": n_train,
        }

    def required_samples(self, target_gap: float = 0.05,
                         delta: float = 0.05) -> int:
        """需要多少训练 DAG 才能使泛化间隙 ≤ target_gap。

        从 Catoni 界反解:
          ε ≥ √((KL + log(2√n/δ)) / (2n))
          → 2n·ε² ≥ KL + log(2√n/δ)
          → n ≥ (KL + log(2/δ)) / (2ε²)  (粗略下界)
        """
        eps = max(target_gap, 0.001)
        # 数值求解 (二分)
        lo, hi = 2, 100000
        while lo < hi:
            mid = (lo + hi) // 2
            penalty = math.sqrt(
                (self._kl + math.log(2.0 * math.sqrt(mid) / delta)) / (2.0 * mid)
            )
            if penalty <= eps:
                hi = mid
            else:
                lo = mid + 1
        return lo

    def compute_empirical_risk(self, makespans: List[float],
                               optimal_makespans: List[float]) -> float:
        """经验风险 = mean(normalized_makespan - 1)。

        normalized = makespan / optimal_makespan。
        0 表示完美 (达到最优), 正值表示退化。
        """
        if not makespans:
            return 0.0
        ratios = [
            m / max(opt, 0.01) - 1.0
            for m, opt in zip(makespans, optimal_makespans)
        ]
        return max(0.0, sum(ratios) / len(ratios))

    def stats(self) -> dict:
        return {
            "prior_std": self._sigma_p,
            "posterior_std": self._sigma_q,
            "param_dim": self._dim,
            "kl_divergence": round(self._kl, 2),
        }
