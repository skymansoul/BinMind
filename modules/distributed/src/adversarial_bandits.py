# 对抗多臂老虎机调度 — EXP3-IX 的非随机环境在线决策
#
# ThompsonAutoscaler (thompson_autoscaler.py) 使用汤普森采样——
# 假设奖励服从 Beta 分布 (即随机环境)。当资源竞争者 (其他租户、
# 后台任务、网络抖动) 的行为是 对抗性 的而非随机的，汤普森采样
# 会陷入线性遗憾 (regret Ω(T))。
#
# 对抗多臂老虎机 (Adversarial Bandit) 不做任何随机假设。
# EXP3 (Exponential-weight for Exploration and Exploitation) 的遗憾界:
#   R_T ≤ O(√(T·K·log K))  — 亚线性，即使奖励序列是故意构造的。
# EXP3-IX (Implicit eXploration) 变体去除显式探索参数 γ，
# 用隐式探索 (损失估计加偏置) 简化调参的同时保持相同遗憾界。
#
# 本模块:
#   1. EXP3-IX 作为自适应调度决策的核心算法
#   2. 臂 = 调度动作 (扩容/缩容/维持 或 选择队列/优先级)
#   3. 奖励 = 吞吐增量 - λ·延迟增量 (可配置)
#   4. 遗憾界限可审计: stats() 报告经验遗憾上界
#
# 与 ThompsonAutoscaler 的比较:
#   Thompson: Beta 后验 → 适合平稳环境，快速收敛
#   EXP3-IX:  指数权重 → 适合非平稳/对抗环境，稳健但不收敛到单臂
#   两者互补: 在平稳期用 Thompson (低方差)，检测到漂移后切换 EXP3-IX

from __future__ import annotations

import math
import random
import time
import threading
from typing import Optional, List, Dict, Tuple


def _clamp_prob(p: float) -> float:
    return max(1e-9, min(1.0 - 1e-9, p))


class EXP3IX:
    """EXP3-IX 对抗多臂老虎机。

    每轮:
      1. 按权重采样臂 i: p_i ∝ exp(η·w_i)
      2. 观测奖励 r_i ∈ [0, 1]
      3. 计算重要性加权估计: r̂_i = r_i / (p_i + γ_i)  (γ_i 是隐式探索)
      4. 更新权重: w_i += η · r̂_i
    """

    def __init__(self, n_arms: int, eta: float = 0.1,
                 seed: Optional[int] = None):
        self._K = n_arms
        self._eta = eta
        self._rng = random.Random(seed)
        # 权重 (对数尺度 — 等同于累积奖励)
        self._weights = [0.0] * n_arms
        self._cum_loss: List[float] = [0.0] * n_arms
        self._round: int = 0
        self._lock = threading.Lock()

    def select(self) -> int:
        """依当前权重分布选取臂。返回臂索引。"""
        with self._lock:
            self._round += 1
            max_w = max(self._weights)
            shifted = [w - max_w for w in self._weights]
            # exp(η·shifted) — 数值稳定
            exp_w = [math.exp(self._eta * s) for s in shifted]
            total = sum(exp_w)
            probs = [ew / total for ew in exp_w]

            # 加权采样
            r = self._rng.random()
            cum = 0.0
            for i, p in enumerate(probs):
                cum += p
                if r <= cum:
                    return i
            return self._K - 1

    def update(self, arm: int, reward: float):
        """观测奖励并更新权重。

        reward ∈ [0, 1] — 1 表示最优。
        EXP3 处理损失 (越小越好) — 此处转换为损失 = 1 - reward。
        """
        with self._lock:
            loss = 1.0 - _clamp_prob(min(1.0, max(0.0, reward)))
            # 重算选中概率 (基于当前权重)
            max_w = max(self._weights)
            shifted = [w - max_w for w in self._weights]
            exp_w = [math.exp(self._eta * s) for s in shifted]
            total = sum(exp_w)
            probs = [ew / total for ew in exp_w]
            p_arm = probs[arm]

            # IX: 隐式探索 — 损失估计的分母加一个小量
            gamma = math.sqrt(math.log(self._K) / (self._K * max(1, self._round)))
            ix_denom = p_arm + gamma

            # 重要性加权损失估计
            estimated_loss = loss / max(ix_denom, 1e-9)

            # 更新权重: w_i -= estimated_loss  (损失越小权重越大)
            self._weights[arm] -= estimated_loss
            self._cum_loss[arm] += loss

    def arm_distribution(self) -> List[float]:
        """当前各臂的选择概率分布。"""
        with self._lock:
            max_w = max(self._weights)
            shifted = [w - max_w for w in self._weights]
            exp_w = [math.exp(self._eta * s) for s in shifted]
            total = sum(exp_w)
            return [round(ew / total, 4) for ew in exp_w]

    def regret_bound(self) -> float:
        """经验遗憾上界: √(2·T·K·log K)。"""
        T = max(1, self._round)
        return math.sqrt(2.0 * T * self._K * math.log(max(self._K, 2)))

    def stats(self) -> dict:
        return {
            "n_arms": self._K,
            "rounds": self._round,
            "eta": self._eta,
            "arm_probs": self.arm_distribution(),
            "regret_bound": round(self.regret_bound(), 4),
            "avg_cum_loss": round(
                sum(self._cum_loss) / max(1, self._round), 4
            ),
        }


class AdversarialBanditScheduler:
    """对抗老虎机调度适配器 — EXP3-IX 驱动的动态策略选择。

    维护多个候选调度策略 (臂):
      arm 0: 激进 — 高并行度，低延迟优先
      arm 1: 均衡 — 默认 GRL-Sched
      arm 2: 保守 — HEFT 贪心，最小资源消耗
      arm 3: 批处理 — 积压任务批量处理

    每轮选择策略 → 观测 makespan + 资源利用率 → 计算奖励 → 更新。
    """

    def __init__(self, eta: float = 0.08, seed: Optional[int] = None):
        self._strategies = ["aggressive", "balanced", "conservative", "batch"]
        self._bandit = EXP3IX(len(self._strategies), eta, seed)
        self._last_arm: int = 0

    def select_strategy(self) -> str:
        self._last_arm = self._bandit.select()
        return self._strategies[self._last_arm]

    def observe(self, makespan: float, best_possible_makespan: float,
                cpu_util: float, success: bool = True):
        """观测本轮调度结果并更新。

        reward = 0.4·(best/makespan) + 0.3·cpu_util + 0.3·(success?1:0)
        三项均归一化到 [0,1]，reward ∈ [0,1]。
        """
        if not success:
            reward = 0.05
        else:
            eff = min(1.0, best_possible_makespan / max(makespan, 0.01))
            reward = 0.4 * eff + 0.3 * min(1.0, cpu_util) + 0.3
        self._bandit.update(self._last_arm, reward)

    @property
    def strategies(self) -> List[str]:
        return list(self._strategies)

    def stats(self) -> dict:
        bstats = self._bandit.stats()
        return {
            "strategies": self._strategies,
            "current": self._strategies[self._last_arm],
            **bstats,
        }
