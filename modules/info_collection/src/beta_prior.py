"""
共享贝叶斯统计基元。

online_calibrate 和 bandit_router 各自维护了 Beta 先验类,
结构高度重复。本模块提取共性, 两个模块从此处导入。
"""

from __future__ import annotations

import math
import random
from dataclasses import dataclass


@dataclass
class BetaPrior:
    """Beta(α, β) 先验 —— α 为伪成功计数, β 为伪失败计数。"""
    alpha: float = 1.0
    beta: float = 1.0

    def mean(self) -> float:
        total = self.alpha + self.beta
        return self.alpha / total if total > 0 else 0.5

    def sample(self) -> float:
        """Thompson 采样。"""
        return random.betavariate(max(0.1, self.alpha), max(0.1, self.beta))

    def update(self, success: bool, weight: float = 1.0) -> None:
        if success:
            self.alpha += weight
        else:
            self.beta += weight

    def decay(self, factor: float = 0.995) -> None:
        """向无信息先验收缩。"""
        self.alpha = 1.0 + (self.alpha - 1.0) * factor
        self.beta = 1.0 + (self.beta - 1.0) * factor

    @property
    def variance(self) -> float:
        total = self.alpha + self.beta
        if total <= 0:
            return 0.25
        return (self.alpha * self.beta) / (total * total * (total + 1))

    @property
    def std(self) -> float:
        return math.sqrt(max(0, self.variance))

    def ucb_bonus(self, total_observations: int) -> float:
        """UCB 探索奖励: sqrt(2 * ln(N) / n)。高方差 → 高奖励。"""
        n_effective = self.alpha + self.beta
        if n_effective <= 2:
            return 0.3
        return math.sqrt(2.0 * math.log(total_observations + 1) / n_effective)


__all__ = ["BetaPrior"]
