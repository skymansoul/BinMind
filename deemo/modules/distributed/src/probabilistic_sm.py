# 概率状态机 — 执行指标驱动的随机守卫条件
#
# state_machine.py 的 TaskStateMachine 用确定性守卫:
#   if task.status == "running" and elapsed > timeout → "failed"
# 实际系统中守卫条件有不确定性:
# GC 暂停造成的假超时 (应重试而非标记失败)
# 瞬态网络故障 (重试即可恢复)
# 资源争用的渐进效应 (负载越高, 超时概率越大)
#
# 本模块用概率守卫替代确定性守卫:
#   P(transition | observation) ∝ likelihood × prior
# 观测: 执行时间、CPU 利用率、内存压力、最近失败率
# 转移: 通过贝叶斯更新计算后验转移概率
#
# 示例:
#   观测到超时 + 系统负载高 → P(failed) ≈ 0.3 (可能是资源争用)
#   观测到超时 + 系统负载低 → P(failed) ≈ 0.85 (很可能是真故障)
#   前者触发重试, 后者触发故障处理——自适应。

from __future__ import annotations

import math
import time
import threading
from collections import deque
from typing import Optional, List, Dict, Tuple


def _sigmoid(x: float) -> float:
    return 1.0 / (1.0 + math.exp(-x))


class ProbabilisticGuard:
    """概率守卫 — 基于逻辑回归的条件转移概率。

    P(transition) = sigmoid(β₀ + β₁·x₁ + ... + βₙ·xₙ)
    其中 xᵢ 是观测特征 (归一化到 [0,1])。
    """

    def __init__(self, name: str, n_features: int = 4):
        self._name = name
        self._beta = [0.0] * (n_features + 1)  # β₀ + β₁..βₙ
        self._n_updates: int = 0

    def probability(self, features: List[float]) -> float:
        """给定观测特征, 计算转移概率。"""
        z = self._beta[0]  # 截距
        for i, x in enumerate(features):
            if i + 1 < len(self._beta):
                z += self._beta[i + 1] * x
        return _sigmoid(z)

    def update(self, features: List[float], actual: bool, lr: float = 0.05):
        """用实际结果更新逻辑回归参数 (SGD)。"""
        p = self.probability(features)
        err = (1.0 if actual else 0.0) - p
        self._beta[0] += lr * err
        for i, x in enumerate(features):
            if i + 1 < len(self._beta):
                self._beta[i + 1] += lr * err * x
        self._n_updates += 1

    @property
    def name(self) -> str:
        return self._name


class ProbabilisticStateMachine:
    """概率状态机 — 执行指标驱动的随机状态转移。

    状态: PENDING → RUNNING → COMPLETED | FAILED | TIMED_OUT
    概率守卫:
      PENDING→RUNNING:    基于队列深度 + 资源可用性
      RUNNING→TIMED_OUT:  基于 CPU 负载 + 历史超时率 + 执行时间比
      RUNNING→FAILED:     基于内存压力 + 失败率 + 熔断器状态
      RUNNING→COMPLETED:  默认转移 (任务正常完成)

    与 AdaptiveCheckpointController 的协同:
      高故障概率 → 降低检查间隔 (增加保护)
      低故障概率 → 提高检查间隔 (减少开销)
    """

    def __init__(self):
        self._guards = {
            "PENDING->RUNNING": ProbabilisticGuard(
                "pending_to_running", n_features=3
            ),
            "RUNNING->TIMED_OUT": ProbabilisticGuard(
                "running_to_timeout", n_features=3
            ),
            "RUNNING->FAILED": ProbabilisticGuard(
                "running_to_failed", n_features=3
            ),
        }
        self._state_history: deque = deque(maxlen=100)
        self._lock = threading.Lock()

    def evaluate(self, current_state: str, features: List[float]
                 ) -> Dict[str, float]:
        """评估从 current_state 的所有可能转移概率。

        features: [cpu_load, memory_pressure, recent_failure_rate]
        """
        probs = {}
        for guard_name, guard in self._guards.items():
            src = guard_name.split("->")[0]
            if src == current_state:
                probs[guard_name] = round(guard.probability(features), 4)
        # COMPLETED 是默认的确定性转移 (兜底)
        if current_state == "RUNNING":
            max_p = max(probs.values()) if probs else 0.0
            probs["RUNNING->COMPLETED"] = round(1.0 - max_p, 4)
        return probs

    def sample_transition(self, current_state: str, features: List[float]
                          ) -> str:
        """按概率采样下一个状态。"""
        import random
        probs = self.evaluate(current_state, features)
        r = random.random()
        cum = 0.0
        for transition, p in probs.items():
            cum += p
            if r <= cum:
                return transition.split("->")[1]
        return "COMPLETED"

    def observe_outcome(self, transition: str, features: List[float],
                        was_correct: bool):
        """观测转移结果 → 更新守卫参数。"""
        with self._lock:
            if transition in self._guards:
                self._guards[transition].update(features, was_correct)
            self._state_history.append((
                time.monotonic(), transition, was_correct
            ))

    def failure_probability(self, features: List[float]) -> float:
        """当前特征下的综合故障概率 (TIMED_OUT + FAILED)。"""
        p_timeout = self._guards["RUNNING->TIMED_OUT"].probability(features)
        p_failed = self._guards["RUNNING->FAILED"].probability(features)
        return min(1.0, p_timeout + p_failed)

    def stats(self) -> dict:
        with self._lock:
            return {
                "guards": {
                    g.name: {
                        "n_updates": g._n_updates,
                        "beta0": round(g._beta[0], 4),
                    }
                    for g in self._guards.values()
                },
                "history_len": len(self._state_history),
            }
