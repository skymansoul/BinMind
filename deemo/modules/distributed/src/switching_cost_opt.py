# 切换代价感知的在线优化 — 调度参数整定的稳定性约束
#
# OCOWeightOptimizer (oco_scheduler.py) 每轮根据梯度更新权重，但忽略
# 一个重要成本: 参数切换本身有代价——频繁改变 (w_exec, w_carbon, w_mig)
# 导致调度计划震荡、任务迁移。
#
# 切换代价在线优化 (Online Optimization with Switching Costs):
#   min Σ f_t(θ_t) + λ·Σ ||θ_t - θ_{t-1}||₁
#   第一项: 累积损失
#   第二项: 总切换代价 (L1 距离 × 惩罚系数 λ)
#
# FairOBD (arXiv:2512.11131) 在同一框架下处理公平性、切换代价和
# 打击代价。本模块将切换代价引入调度参数整定——公平性和打击代价
# 在 NashFairScheduler 和 OTAssigner 中已处理。
#
# 算法: Online Balanced Descent (OBD) 的变体。
#   每轮: θ_t = argmin_θ { f_{t-1}(θ) + λ·||θ - θ_{t-1}||₁ + (1/η)·KL(θ||θ_{t-1}) }
#   KL 正则化是 online mirror descent 的标准形式 (Bregman 散度)。
#   L1 切换代价产生稀疏切换——多数轮 θ 保持不变。

from __future__ import annotations

import math
import threading
from typing import List


def _soft_threshold(x: float, lam: float) -> float:
    """软阈值算子 — L1 近端算子的核心。"""
    if x > lam:
        return x - lam
    if x < -lam:
        return x + lam
    return 0.0


class SwitchingCostOptimizer:
    """切换代价感知的在线权重优化器。

    对 K 维权重的连续在线优化，每步有 L1 切换惩罚。
    λ 控制稀疏性: λ=0 → 等价于标准 OGD；λ 大 → 很少切换。
    """

    def __init__(self, n_weights: int = 3, lr: float = 0.05,
                 lambda_switch: float = 0.02):
        self._K = n_weights
        self._lr = lr
        self._lam = lambda_switch
        self._weights = [1.0 / n_weights] * n_weights
        self._t: int = 0
        self._switch_count: int = 0
        self._lock = threading.Lock()

    @property
    def weights(self) -> List[float]:
        return list(self._weights)

    def step(self, gradient: List[float]) -> List[float]:
        """一次 OBD 更新 — 返回新权重。

        gradient[i] = ∂loss/∂w_i。

        算法:
          1. 镜像下降: w̃ = w - lr·g
          2. 近端: w' = prox_{λ·||·-w_old||₁}(w̃)
             = w_old + soft_threshold(w̃ - w_old, λ)
          3. 投影到单纯形
        """
        with self._lock:
            self._t += 1
            old = list(self._weights)

            # 1. 梯度下降 (KL 正则化等价于指数梯度在 simplex 上)
            # 此处用线性近似: w̃ = w - lr·g
            w_tilde = [
                old[i] - self._lr * gradient[i]
                for i in range(self._K)
            ]

            # 2. L1 近端: 软阈值
            w_prox = [
                old[i] + _soft_threshold(w_tilde[i] - old[i], self._lam)
                for i in range(self._K)
            ]

            # 3. 投影到单纯形
            self._weights = self._project_simplex(w_prox)

            # 追踪切换
            l1_change = sum(
                abs(self._weights[i] - old[i]) for i in range(self._K)
            )
            if l1_change > 0.001:
                self._switch_count += 1

        return list(self._weights)

    def _project_simplex(self, v: List[float]) -> List[float]:
        n = len(v)
        u = sorted(v, reverse=True)
        rho = 0
        cum = 0.0
        for j in range(n):
            cum += u[j]
            if u[j] - (cum - 1.0) / (j + 1) > 0:
                rho = j + 1
        theta = (sum(u[:rho]) - 1.0) / max(rho, 1)
        return [max(0.0, vi - theta) for vi in v]

    @property
    def switch_count(self) -> int:
        return self._switch_count

    def stats(self) -> dict:
        return {
            "weights": [round(w, 4) for w in self._weights],
            "iterations": self._t,
            "switch_count": self._switch_count,
            "switch_ratio": round(
                self._switch_count / max(1, self._t), 4
            ),
            "lambda_switch": self._lam,
        }
