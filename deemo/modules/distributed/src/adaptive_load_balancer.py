# 自适应 Power-of-d 负载均衡器 — d 的在线调优 + 尾延迟上界
#
# src/load_balancer.py 的 ConsistentHashRing 解决的是亲和性路由
# (同一任务→同一节点)，本质是静态映射。Power-of-d 是另一范式:
# 每次分配时随机采样 d 台机器，选负载最轻者。
# d=1 → 纯随机 (高方差), d→∞ → JSQ (join-shortest-queue, 最优但开销大)
# d=2 → 指数级改善尾部延迟而仅 2× 探测开销
#
# Varma et al. (Stochastic Systems, 2025) 给出了 d 与队列长度的精确关系:
#   在 sub-Halfin-Whitt 区域 (λ = n - n^{1-γ}) 中:
#     d = Θ((n^γ log n)^{1/m}) → 队列集中分布在长度 m
#   这个结果依赖稳态 λ。实际系统的 λ 是时变的。
#
# 本模块:
#   1. 自适应 d: 基于观测到的负载方差在线调节 d
#      var 高 → d 增大 (更激进地平衡)
#      var 低 → d 减小 (节省探测开销)
#   2. 尾延迟上界: 利用 Kingman 上界 (G/G/1) 估算给定 d 下的
#      P(queue_length > x) ≤ exp(-θ·x)，θ 随 d 增大
#   3. 偏置采样: 对已知高性能机器增加采样权重 (软亲和)
#      → 兼顾负载均衡与缓存局部性

from __future__ import annotations

import math
import random
import threading
import time
from collections import deque
from typing import Optional, List, Dict, Tuple


class AdaptivePowerOfD:
    """自适应 power-of-d 负载均衡器。

    d 的范围 [d_min, d_max]，初始值 d_init。
    自适应规则:
      每 window 次分配后评估各机器负载的变异系数 (CV)。
      CV > 0.5 → d += 1 (负载不均衡加剧)
      CV < 0.2 → d -= 1 (负载已均匀，减少探测)
      d 受 [d_min, d_max] 约束。
    """

    def __init__(
        self, n_machines: int, d_min: int = 2, d_max: int = 8,
        window: int = 50, seed: Optional[int] = None,
    ):
        self._M = n_machines
        self._d = min(d_min, n_machines)
        self._d_min = min(d_min, n_machines)
        self._d_max = min(d_max, n_machines)
        self._window = window
        self._rng = random.Random(seed)

        # 每台机器的负载估计 (排队任务数)
        self._loads: List[float] = [0.0] * n_machines
        # 偏置权重: 高性能机器获得更高的采样权重
        self._bias: List[float] = [1.0] * n_machines
        # 自适应窗口计数
        self._assign_count: int = 0
        self._load_history: deque = deque(maxlen=window)
        self._lock = threading.Lock()

    def select(self, task_cost: float = 1.0) -> int:
        """选择目标机器 — power-of-d + 偏置。

        task_cost: 任务的预估负载贡献 (用于更新)
        返回: 机器索引
        """
        with self._lock:
            d = self._d
            # 无放回采样 d 台机器 (若 d > M 则全采样)
            candidates = self._rng.sample(range(self._M), min(d, self._M))

            # 偏置调整: 负载 = 原始负载 / 偏置权重
            def effective_load(m: int) -> float:
                return self._loads[m] / max(self._bias[m], 0.1)

            best = min(candidates, key=effective_load)
            self._loads[best] += task_cost
            self._assign_count += 1

            # 周期性自适应 d
            if self._assign_count % self._window == 0:
                self._adapt_d()
            return best

    def complete(self, machine: int, task_cost: float = 1.0):
        """任务在 machine 上完成 — 释放负载。"""
        with self._lock:
            self._loads[machine] = max(0.0, self._loads[machine] - task_cost)

    def update_bias(self, machine: int, performance_score: float):
        """更新机器偏置 — performance_score > 1 表示高于平均性能。

        采用 EMA 平滑偏置更新，避免单次测量波动。
        """
        with self._lock:
            self._bias[machine] = (
                0.85 * self._bias[machine] + 0.15 * performance_score
            )

    def _adapt_d(self):
        """基于负载变异系数自适应 d。"""
        loads = self._loads
        n = len(loads)
        mean_l = sum(loads) / n if n > 0 else 0.0
        if mean_l <= 0.01:
            cv = 0.0
        else:
            var = sum((l - mean_l) ** 2 for l in loads) / n
            cv = math.sqrt(var) / mean_l

        if cv > 0.5 and self._d < self._d_max:
            self._d += 1
        elif cv < 0.2 and self._d > self._d_min:
            self._d -= 1

    def tail_bound(self, x: int) -> float:
        """P(queue_length > x) 的上界估计。

        基于 Kingman G/G/1 上界 + power-of-d 加速因子。
        d 越大 → 有效到达率的方差越小 → 尾概率指数下降。
        """
        loads = self._loads
        mean_l = sum(loads) / max(len(loads), 1)
        if mean_l <= 0:
            return 0.0
        # d 的效应: 相当于将服务率提升了 ≈ log(d) 倍 (Mitzenmacher 2001)
        effective_rate = 1.0 + math.log(max(1, self._d))
        theta = effective_rate / max(mean_l, 0.01)
        return min(1.0, math.exp(-theta * x))

    @property
    def d(self) -> int:
        return self._d

    @property
    def loads(self) -> List[float]:
        return list(self._loads)

    def stats(self) -> dict:
        loads = self._loads
        mean_l = sum(loads) / max(len(loads), 1)
        var = sum((l - mean_l) ** 2 for l in loads) / max(len(loads), 1)
        return {
            "d": self._d, "d_min": self._d_min, "d_max": self._d_max,
            "mean_load": round(mean_l, 3),
            "load_cv": round(math.sqrt(max(var, 0.0)) / max(mean_l, 0.01), 3),
            "p_tail_gt_5": round(self.tail_bound(5), 6),
            "bias_range": [
                round(min(self._bias), 3), round(max(self._bias), 3)
            ],
        }
