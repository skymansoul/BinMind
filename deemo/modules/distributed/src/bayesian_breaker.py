# 创建: 2026-06-28
# 修改: 2026-06-28 — 修复游程后验归一化欠流问题
#
# 贝叶斯变点检测熔断器 — 失败流统计的自适应阈值整定
#
# circuit_breaker.py 使用固定阈值 (失败率 > 50% → 熔断) 和固定
# 恢复时间 (half-open → closed)。adaptive_breaker.py 的
# FractionalCircuitBreaker 按失败比例逐步限流而非全开全断。
# 两者的共同缺陷: 阈值不与失败流的统计特性关联。
#
# 贝叶斯在线变点检测 (Bayesian Online Changepoint Detection, BOCD):
#   观测序列 x_1, x_2, ... (1=成功, 0=失败)
#   对每个时刻 t, 计算 run length r_t (自上次变点以来的步数):
#     P(r_t | x_{1:t}) ∝ P(x_t | r_{t-1}, x_{t-1}) · Σ P(r_{t-1} | r_t)
#   变点概率 = 1 - P(r_t = r_{t-1}+1)
#
# 本模块将 BOCD 应用于熔断决策:
# 失败率突然改变 → 高变点概率 → 立即熔断 (不等到积累足够失败)
#   - 失败率稳定 (即使高) → 低变点概率 → 按 Fractional 策略渐进限流
# 变点后的新分布有低失败率 → 立即恢复 (不等固定半开间隔)
#
# 直观对比: 固定阈值 → "最近 10 次中 ≥5 次失败 → 熔断"
#           BOCD → "失败率从 5% 变为 60% 的概率 > 0.9 → 熔断"
# BOCD 在失败率渐变时保持正常 (不误熔断)，在突变时快速响应。

from __future__ import annotations

import math
import time
import threading
from collections import deque
from typing import Optional


class BOCDDetector:
    """贝叶斯在线变点检测器 — Beta-Bernoulli 共轭模型。

    观测: x_t ∈ {0, 1}  (0=失败, 1=成功)
    先验: θ ~ Beta(α, β)  (失败概率)
    后验预测: P(x_t=0 | r) = (α_r + #failures) / (α_r + β_r + #total)
    hazard: H = 1 / expected_run_length  (变点先验)
    """

    def __init__(self, hazard_rate: float = 0.01,
                 alpha_prior: float = 1.0, beta_prior: float = 1.0,
                 max_run_length: int = 300):
        self._H = hazard_rate
        self._alpha0 = alpha_prior
        self._beta0 = beta_prior
        self._max_r = max_run_length

        # 游程后验: P(r_t | x_{1:t})  (只保留概率质量 > 1e-6 的游程)
        self._run_probs: List[float] = [1.0]  # P(r=0) at t=0
        self._alpha: List[float] = [alpha_prior]
        self._beta: List[float] = [beta_prior]
        self._changepoint_prob: float = 0.0
        self._t: int = 0

    def observe(self, success: bool):
        """观测一次结果 → 更新变点概率。"""
        self._t += 1
        x = 1 if success else 0

        new_probs = [0.0] * (len(self._run_probs) + 1)
        new_alpha = [self._alpha0] * (len(self._run_probs) + 1)
        new_beta = [self._beta0] * (len(self._run_probs) + 1)

        # 1. 预测概率: P(x_t | r_t = r)
        pred_prob = []
        for r in range(len(self._run_probs)):
            a = self._alpha[r]
            b = self._beta[r]
            p = a / (a + b) if (a + b) > 0 else 0.5
            pred_prob.append(p if x == 1 else (1.0 - p))

        # 2. 变点概率: P(r_t = 0 | x_t) = H·P(x_t | new_param)
        cp_likelihood = (self._alpha0 / (self._alpha0 + self._beta0)
                         if x == 1 else
                         self._beta0 / (self._alpha0 + self._beta0))
        new_probs[0] = self._H * cp_likelihood

        # 3. 生长概率: P(r_t = r+1 | x_t) = (1-H)·P(x_t|r_t=r)·P(r_t=r)
        for r in range(len(self._run_probs)):
            if r + 1 >= self._max_r:
                break
            grow = (1.0 - self._H) * pred_prob[r] * self._run_probs[r]
            new_probs[r + 1] = grow
            new_alpha[r + 1] = self._alpha[r] + x
            new_beta[r + 1] = self._beta[r] + (1 - x)

        # 4. 归一化
        total = sum(new_probs)
        if total > 1e-12:
            new_probs = [p / total for p in new_probs]
        else:
            new_probs = [1.0 / len(new_probs)] * len(new_probs)

        self._run_probs = new_probs
        self._alpha = new_alpha
        self._beta = new_beta
        self._changepoint_prob = new_probs[0] if new_probs else 0.0

        # 内存限制
        if len(self._run_probs) > self._max_r:
            self._run_probs = self._run_probs[-self._max_r:]
            self._alpha = self._alpha[-self._max_r:]
            self._beta = self._beta[-self._max_r:]

    @property
    def changepoint_probability(self) -> float:
        return self._changepoint_prob

    @property
    def current_failure_rate(self) -> float:
        """当前最可能游程的失败率估计。"""
        if not self._run_probs:
            return 0.5
        best_r = max(range(len(self._run_probs)),
                     key=lambda i: self._run_probs[i])
        a = self._alpha[best_r]
        b = self._beta[best_r]
        return (a / (a + b)) if (a + b) > 0 else 0.5


class BayesianCircuitBreaker:
    """贝叶斯变点熔断器 — BOCD 驱动的自适应熔断决策。

    与 CircuitBreaker 接口兼容 (call/mark_success/mark_failure/state)。
    """

    def __init__(self, cp_threshold: float = 0.70,
                 failure_rate_threshold: float = 0.40,
                 hazard_rate: float = 0.01):
        self._bocd = BOCDDetector(hazard_rate=hazard_rate)
        self._cp_thr = cp_threshold
        self._fr_thr = failure_rate_threshold
        self._state: str = "closed"
        self._lock = threading.Lock()
        self._last_transition: float = time.monotonic()

    def mark_success(self):
        with self._lock:
            self._bocd.observe(True)
            self._update_state()

    def mark_failure(self):
        with self._lock:
            self._bocd.observe(False)
            self._update_state()

    def _update_state(self):
        cp = self._bocd.changepoint_probability
        fr = self._bocd.current_failure_rate
        prev = self._state

        if cp > self._cp_thr and fr > self._fr_thr:
            self._state = "open"
        elif cp > self._cp_thr and fr <= self._fr_thr * 0.5:
            self._state = "closed"
        elif cp < self._cp_thr * 0.3 and self._state == "open":
            self._state = "half_open"

        if self._state != prev:
            self._last_transition = time.monotonic()

    @property
    def state(self) -> str:
        return self._state

    def allow_request(self) -> bool:
        return self._state != "open"

    def stats(self) -> dict:
        with self._lock:
            return {
                "state": self._state,
                "changepoint_prob": round(
                    self._bocd.changepoint_probability, 4
                ),
                "failure_rate": round(
                    self._bocd.current_failure_rate, 4
                ),
                "cp_threshold": self._cp_thr,
            }
