# 在线凸优化调度 — 动态遗憾界 + 投影梯度下降的参数自整定
#
# OTAssigner 和 GRLScheduler 的代价函数有多组权重 (执行/碳/迁移)。
# 固定权重在环境变化时次优——需要在线自适应。
#
# 在线凸优化 (OCO) 框架:
#   每轮 t:
#     1. 选择参数 θ_t ∈ Θ (凸可行集)
#     2. 环境揭示损失函数 f_t(θ) (凸, 可能对抗性)
#     3. 承担损失 f_t(θ_t)，用梯度更新
#   目标: 最小化遗憾 R_T = Σf_t(θ_t) - min_θ Σf_t(θ)
#   动态遗憾: R_T^dyn = Σf_t(θ_t) - Σmin_θ f_t(θ)
#
# OGD (Online Gradient Descent) 的静态遗憾界:
#   R_T ≤ O(√T) (若 f_t 强凸 → O(log T))
# 动态遗憾含路径长度 P_T = Σ||θ_{t+1}* - θ_t*||
#
# 本模块: OGD + 投影到单纯形 (权重和为 1 且 ≥ 0)。
# 用于在线调节 OTAssigner 的 (w_exec, w_carbon, w_migration) 权重。

from __future__ import annotations

import math
import threading
from typing import List, Tuple


def _project_simplex(v: List[float]) -> List[float]:
    """投影到概率单纯形: {x | x_i ≥ 0, Σx_i = 1}。

    O(d log d) 算法 (Duchi et al. 2008)。
    """
    n = len(v)
    u = sorted(v, reverse=True)
    rho = 0
    cum = 0.0
    for j in range(n):
        cum += u[j]
        if u[j] - (cum - 1.0) / (j + 1) > 0:
            rho = j + 1
    theta = (sum(u[:rho]) - 1.0) / rho if rho > 0 else 0.0
    return [max(0.0, vi - theta) for vi in v]


class OCOWeightOptimizer:
    """OCO 权重优化器 — OGD with simplex projection。

    在线优化 K 维权重的凸组合。
    学习率 η_t = η_0 / √t (递减, 满足 OGD 标准条件)。
    """

    def __init__(self, n_weights: int = 3, eta0: float = 0.5):
        self._K = n_weights
        self._eta0 = eta0
        self._weights = [1.0 / n_weights] * n_weights
        self._t: int = 0
        self._cum_grad: List[float] = [0.0] * n_weights
        self._lock = threading.Lock()

    @property
    def weights(self) -> List[float]:
        return list(self._weights)

    def step(self, gradient: List[float]):
        """一次 OGD 更新。

        gradient[i] = ∂loss/∂w_i — 应归一化到合理范围 [-1, 1]。
        """
        with self._lock:
            self._t += 1
            eta = self._eta0 / math.sqrt(max(1, self._t))

            # 梯度下降
            new_w = [
                self._weights[i] - eta * gradient[i]
                for i in range(self._K)
            ]
            # 投影到单纯形
            self._weights = _project_simplex(new_w)
            # 累积梯度 (用于诊断)
            for i in range(self._K):
                self._cum_grad[i] += abs(gradient[i])

    def regret_bound(self) -> float:
        """静态遗憾上界: O(√T) 的常数因子。

        ‖θ‖₂ ≤ 1 (单纯形上), ‖g‖₂ ≤ √K → R_T ≤ √(2T)/η0 + η0·K·√T
        """
        T = max(1, self._t)
        return math.sqrt(2.0 * T) / self._eta0 + self._eta0 * self._K * math.sqrt(T)

    def stats(self) -> dict:
        return {
            "weights": [round(w, 4) for w in self._weights],
            "iterations": self._t,
            "eta_current": round(
                self._eta0 / math.sqrt(max(1, self._t)), 4
            ),
            "regret_bound": round(self.regret_bound(), 3),
        }


class OCOSchedulingAdapter:
    """OCO 调度适配器 — 在线调节调度代价函数的权重。

    与 OTAssigner 协同: 每轮 OT 分配后，观测实际 makespan
    和碳消耗，计算各权重的梯度，更新 OCO。
    梯度: ∂loss/∂w_i ≈ (loss(w+ε·e_i) - loss(w-ε·e_i)) / 2ε
    简化为单侧差分以节省一次 OT 求解:
      ∂loss/∂w_exec ≈ -makespan_improvement / baseline
      ∂loss/∂w_carbon ≈ -carbon_reduction / baseline
      ∂loss/∂w_migration ≈ -migration_cost / baseline
    """

    def __init__(self, n_weights: int = 3, eta0: float = 0.3):
        self._oco = OCOWeightOptimizer(n_weights, eta0)
        self._baseline_makespan: float = 1.0
        self._baseline_carbon: float = 1.0
        self._baseline_migration: float = 1.0

    def observe(self, makespan: float, carbon: float, migration: float,
                baseline_makespan: float = 1.0,
                baseline_carbon: float = 1.0,
                baseline_migration: float = 1.0):
        """观测本轮调度结果 → 计算梯度 → 更新 OCO 权重。

        损失 = makespan/baseline + carbon/baseline + migration/baseline
        梯度 ∝ 各分量对损失的贡献比例。
        """
        self._baseline_makespan = max(baseline_makespan, 0.01)
        self._baseline_carbon = max(baseline_carbon, 0.01)
        self._baseline_migration = max(baseline_migration, 0.01)

        # 归一化损失分量
        l_exec = makespan / self._baseline_makespan
        l_carbon = carbon / self._baseline_carbon
        l_mig = migration / self._baseline_migration
        total = l_exec + l_carbon + l_mig
        if total <= 0:
            return

        # 梯度 = 损失分量 / 总损失 (鼓励降低贡献最大的分量)
        grad = [
            l_exec / total,
            l_carbon / total,
            l_mig / total,
        ]
        self._oco.step(grad)

    @property
    def weights(self) -> List[float]:
        return self._oco.weights

    def stats(self) -> dict:
        return self._oco.stats()
