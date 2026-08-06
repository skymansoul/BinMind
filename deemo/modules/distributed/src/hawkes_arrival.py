# 霍克斯自激到达模型 — 任务批处理与重试风暴的预测性资源预留
#
# 安全分析任务到达并非泊松: 一次批量提交 (如 CI 触发全量扫描)
# 产生一阵自激 (self-exciting) 的任务爆发。传统泊松模型低估了
# 突发性——低估方差 → 资源预留不足 → 队列积压。
#
# 霍克斯过程 (Hawkes 1971):
#   λ(t) = μ + Σ_{t_i < t} α·exp(-β·(t - t_i))
#   μ:   基础到达率 (外部触发)
#   α:   自激强度 (每次到达对后续到达率的提升)
#   β:   衰减速率 (自激效应消退的速度)
#   强度积分 Λ = μ·T + (α/β)·N(T) — α/β 是分支比 (每个事件平均
#   触发的子事件数)。α/β < 1 → 过程稳定；α/β ≥ 1 → 爆发性增长。
#
# 本模块在线估计霍克斯参数 (μ, α, β)，用于:
#   1. 短期: 预测未来 T 秒内的期望到达数 → 预留 worker
#   2. 中期: 检测自激爆发 → 触发前馈扩容 (与 PIDAutoscaler 联动)
#   3. 诊断: 分支比 α/β → 系统是否处于自激正反馈中
#
# 与 Li & Pang (2024) 的状态依赖霍克斯队列的区别:
#   该文做理论分析 (FLLN/FCLT)。本模块做在线参数估计 + 调度集成。

from __future__ import annotations

import math
import time
from collections import deque
from typing import Optional, List, Tuple


class HawkesArrivalModel:
    """霍克斯自激到达模型 — 在线参数估计 + 短期预测。

    用指数核 Hawkes(μ, α, β) 的最大似然在线近似。
    每新事件到达时增量更新参数。
    """

    def __init__(self, mu_init: float = 0.1, alpha_init: float = 0.05,
                 beta_init: float = 0.5, lr: float = 0.02,
                 window: int = 200):
        self._mu = mu_init
        self._alpha = alpha_init
        self._beta = beta_init
        self._lr = lr
        self._event_times: deque = deque(maxlen=window)
        self._last_update: float = time.monotonic()

    def record_arrival(self, timestamp: Optional[float] = None):
        """记录一次任务到达事件。触发增量参数更新。"""
        ts = timestamp or time.monotonic()
        self._event_times.append(ts)

        if len(self._event_times) < 10:
            return

        # 增量梯度: 最大化对数似然的随机梯度
        # ∂logL/∂μ ≈ 1/μ - T      (T = 观测窗口长度)
        # ∂logL/∂α ≈ Σ exp(-β·(t-t_i)) / λ(t_i) - Σ (1-exp(-β·Δt))/β
        # ∂logL/∂β ≈ α·Σ (t-t_i)·exp(-β·(t-t_i)) / λ(t_i) - α·Σ ...
        times = list(self._event_times)
        n = len(times)
        T = times[-1] - times[0] if n > 1 else 1.0

        # 简化: 用分支比 α/β 和平均间隔的矩估计
        # 分支比 ≈ (事件数/时长 - μ) / (事件数/时长) = 1 - μ/λ_avg
        lambda_avg = n / max(T, 0.01)
        br_new = max(0.0, min(0.95, 1.0 - self._mu / max(lambda_avg, 0.001)))

        # α 的估计: α ≈ br · β
        # β 的估计: 自相关衰减——间隔越短 → β 越大
        if n >= 3:
            intervals = [times[i] - times[i-1] for i in range(1, n)]
            med_interval = sorted(intervals)[len(intervals)//2]
            beta_new = 1.0 / max(med_interval, 0.001)
        else:
            beta_new = self._beta

        alpha_new = br_new * beta_new
        # μ 的估计: 基础到达率 = 总到达率 - 自激部分
        mu_new = max(0.001, lambda_avg - alpha_new * n / (beta_new * T))

        # EMA 更新 (稳定化)
        self._mu    = 0.9 * self._mu    + 0.1 * mu_new
        self._alpha = 0.9 * self._alpha + 0.1 * alpha_new
        self._beta  = 0.9 * self._beta  + 0.1 * beta_new
        self._last_update = ts

    def intensity(self, t: Optional[float] = None) -> float:
        """当前瞬时强度 λ(t)。"""
        now = t or time.monotonic()
        times = list(self._event_times)
        excitation = sum(
            self._alpha * math.exp(-self._beta * (now - ti))
            for ti in times if ti < now
        )
        return self._mu + excitation

    def expected_arrivals(self, horizon_s: float) -> float:
        """未来 horizon_s 秒内的期望到达数。

        E[N(t, t+Δt)] = μ·Δt + (α/β)·Σ[1-exp(-β·(t+Δt-t_i))]_{t_i ≤ t+Δt}
        简化: 用当前强度 λ(t) 的近似积分。
        """
        now = time.monotonic()
        # 霍克斯强度积分: ∫_0^Δ λ(t+s) ds
        # λ(t+s) = μ + Σ α·exp(-β·(t+s-t_i))
        # 积分: μ·Δ + Σ (α/β)·exp(-β·(t-t_i))·(1-exp(-β·Δ))
        integral = self._mu * horizon_s
        for ti in self._event_times:
            if ti < now:
                lag = now - ti
                integral += (self._alpha / self._beta) * math.exp(
                    -self._beta * lag
                ) * (1.0 - math.exp(-self._beta * horizon_s))
        return integral

    @property
    def branching_ratio(self) -> float:
        """分支比 α/β — > 0.8 表示接近超临界 (爆发)。"""
        return self._alpha / max(self._beta, 0.001)

    @property
    def is_bursting(self) -> bool:
        """当前是否处于自激爆发中 — 分支比 > 0.7 且强度 > 2μ。"""
        return (self.branching_ratio > 0.7 and
                self.intensity() > 2.0 * self._mu)

    def stats(self) -> dict:
        return {
            "mu": round(self._mu, 4),
            "alpha": round(self._alpha, 4),
            "beta": round(self._beta, 4),
            "intensity": round(self.intensity(), 4),
            "branching_ratio": round(self.branching_ratio, 4),
            "is_bursting": self.is_bursting,
            "events_tracked": len(self._event_times),
            "expected_next_60s": round(self.expected_arrivals(60.0), 2),
        }
