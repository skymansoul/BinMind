# 遗憾最优检查点 — Follow-the-Regularized-Leader 的自适应间隔整定
#
# adaptive_checkpoint.py 用 EWA (Exponential Weight Average) 在线学习
# 检查间隔。EWA 的遗憾界 O(√T) 仅在专家数 K 固定时成立——
# 但候选间隔集是连续参数 (15s~480s)，离散化粒度直接影响遗憾。
#
# 本模块用 Follow-the-Regularized-Leader (FTRL) 直接在线优化
# 连续检查间隔 T ∈ [T_min, T_max]:
#   T_{t+1} = argmin_{T} Σ_{s=1}^t ℓ_s(T) + R(T)
#   其中 ℓ_s(T) = (检查点开销 + 回滚代价) 在间隔 T 下的估计
#   R(T) = (λ/2)·(T - T_0)² 是 L2 正则化 (向默认值收缩)
#
# FTRL 的优势:
#   1. 连续参数空间 → 不受离散化粒度限制
#   2. L2 正则化 → 向先验 T_0 收缩，避免冷启动极端值
#   3. 遗憾界 O(log T) (若 ℓ_t 强凸) 或 O(√T) (一般凸)
#   4. 闭式更新: T = clamp(T_0 - (1/λ)·Σgrad_t, T_min, T_max)
#
# 与 AdaptiveCheckpointController 的关系:
#   该模块做离散候选 + EWA 选择。本模块做连续优化 + FTRL。
#   两者互补: EWA 适合多模态环境 (多个局部最优间隔)，FTRL 适合
#   单模态且需要细粒度调节的场景。

from __future__ import annotations

import math
import time
import threading
from collections import deque
from typing import Optional


class FTRLCheckpointController:
    """FTRL 驱动的连续检查间隔控制器。

    在线优化 T ∈ [T_min, T_max] 使总代价 (检查开销 + 回滚代价) 最小。

    代价估计:
      ℓ_t(T) = α/T + β·T
      其中 α = 检查点写入成本比例, β = 故障率 × 回滚代价比例
      对 T 求导: ∂ℓ/∂T = -α/T² + β
    """

    def __init__(self, T_min: float = 10.0, T_max: float = 600.0,
                 T_default: float = 120.0, reg_strength: float = 0.005,
                 lr: float = 0.1):
        self._T_min = T_min
        self._T_max = T_max
        self._T_cur = T_default
        self._T0 = T_default
        self._lam = reg_strength   # L2 正则化强度
        self._lr = lr

        # 累积梯度 (用于 FTRL 闭式解)
        self._cum_grad: float = 0.0
        self._t: int = 0

        # 观测统计
        self._last_checkpoint: float = time.monotonic()
        self._recent_checkpoint_costs: deque = deque(maxlen=20)
        self._recent_rollback_costs: deque = deque(maxlen=20)
        self._lock = threading.Lock()

    def should_checkpoint(self) -> bool:
        now = time.monotonic()
        return (now - self._last_checkpoint) >= self._T_cur

    def record_checkpoint(self, cost_ms: float):
        """记录检查点写入成本。"""
        with self._lock:
            self._last_checkpoint = time.monotonic()
            self._recent_checkpoint_costs.append(cost_ms)

    def record_rollback(self, lost_computation_ms: float):
        """记录回滚代价 (丢失的计算时间)。"""
        with self._lock:
            self._recent_rollback_costs.append(lost_computation_ms)

    def update_interval(self):
        """基于观测代价更新 FTRL 的连续间隔参数。

        梯度估计:
          α_hat = mean(checkpoint_costs)
          β_hat = mean(rollback_costs) / current_interval
          ∂ℓ/∂T ≈ -α_hat/T² + β_hat
        """
        with self._lock:
            self._t += 1
            if not self._recent_checkpoint_costs:
                return

            alpha = (sum(self._recent_checkpoint_costs) /
                     len(self._recent_checkpoint_costs))
            beta = 0.0
            if self._recent_rollback_costs:
                avg_rb = (sum(self._recent_rollback_costs) /
                          len(self._recent_rollback_costs))
                beta = avg_rb / max(self._T_cur, 1.0)

            # 梯度
            grad = -alpha / max(self._T_cur * self._T_cur, 0.01) + beta
            grad = max(-1.0, min(1.0, grad))  # 裁剪防炸

            # 累积梯度 (FTRL 状态)
            self._cum_grad += grad

            # FTRL 闭式解: T* = clamp(T0 - cum_grad / (λ·t + ε), T_min, T_max)
            denom = self._lam * self._t + 0.001
            T_opt = self._T0 - self._cum_grad / denom
            self._T_cur = max(self._T_min, min(self._T_max, T_opt))

    @property
    def current_interval(self) -> float:
        return self._T_cur

    @property
    def time_since_last_checkpoint(self) -> float:
        return time.monotonic() - self._last_checkpoint

    def stats(self) -> dict:
        with self._lock:
            return {
                "current_interval": round(self._T_cur, 1),
                "T_min": self._T_min, "T_max": self._T_max,
                "cumulative_gradient": round(self._cum_grad, 4),
                "iterations": self._t,
                "reg_strength": self._lam,
            }
