"""
在线结果驱动校准 (OODC) —— 基于采集结果的贝叶斯参数更新。

已有 CC-RCR 模块提供静态置信度校准, 但校准参数 (温度、Platt 系数、
增益矩阵) 不随实际采集结果更新。这导致:
  1. 初始估计错误时无法自我修正
  2. 目标环境变化时 (如网络延迟改变成本) 参数过时
  3. 采集器实际效用与预估增益的偏差被忽略

方案: 对每个 (采集器, 意图) 对维护 Beta 先验, 建模 "该采集器对
该意图产生有用结果的概率"。每次采集完成后观测二元结果 (useful/not),
以 Thompson 采样更新先验, 自动调节增益矩阵和路由偏好。

新颖性: 在安全工具路由中引入闭环结果反馈 —— 采集器的 "信息增益"
不是人工预设的静态值, 而是从实际运行数据中持续学习的随机变量。
"""

# File: online_calibrate.py  |  2026-07-29 create OODC; 2026-08-04 audit: extract BetaPrior

from __future__ import annotations

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .intent_route import IntentCategory
from .beta_prior import BetaPrior  # 共享贝叶斯基元, 消除与 bandit_router 的重复


@dataclass
class OutcomeObservation:
    """单次采集结果观测。"""
    action_id: str
    intent: IntentCategory
    useful: bool              # 采集器是否返回了有用信息
    quality_score: float      # 0~1, 结果质量的细粒度评分
    latency_ms: float         # 实际延迟
    items_returned: int       # 返回条目数
    timestamp: float = 0.0


@dataclass
class OnlineCalibrationState:
    """在线校准的完整状态。"""
    priors: Dict[Tuple[str, str], BetaPrior] = field(default_factory=dict)
    observation_count: int = 0
    last_decay_time: float = 0.0

    def _key(self, action_id: str, intent: IntentCategory) -> Tuple[str, str]:
        return (action_id, intent.value)

    def get_prior(self, action_id: str, intent: IntentCategory) -> BetaPrior:
        k = self._key(action_id, intent)
        if k not in self.priors:
            self.priors[k] = BetaPrior()
        return self.priors[k]


class OnlineCalibrator:
    """
    在线结果驱动校准器。

    工作流:
    1. 采集前: 用 Thompson 采样从 Beta 先验中抽取增益估计,
       替代静态增益矩阵中的定值。
    2. 采集后: 观测二元结果 (有用/无用) + 质量分, 更新 Beta 后验。
    3. 周期衰减: 每 decay_interval 秒对所有先验施加指数衰减,
       反映 "过去的信息随环境变化而贬值"。

    对 MSIGC 的增益矩阵的修正:
    原始 gain(action, intent) → sampled_gain = Beta.sample() * prior_gain
    其中 prior_gain 是 MSIGC 中的静态增益估计, sampled_gain 是
    从历史结果中学习到的动态修正因子。
    """

    def __init__(self, decay_interval: float = 3600.0, decay_factor: float = 0.995):
        self._state = OnlineCalibrationState()
        self._decay_interval = decay_interval
        self._decay_factor = decay_factor

    def sample_gain(self, action_id: str, intent: IntentCategory, base_gain: float = 0.5) -> float:
        """
        Thompson 采样的动态增益估计。

        对高方差的先验 (观测少) 自动给予更多探索机会,
        对方差收敛的先验则稳定在观测均值附近。
        """
        prior = self._state.get_prior(action_id, intent)
        sampled = prior.sample()
        # 混合: 60% 采样值 + 40% 静态增益, 避免冷启动时完全随机
        return 0.6 * sampled + 0.4 * base_gain

    def observe(self, observation: OutcomeObservation) -> None:
        """提交一次采集结果观测, 更新对应的 Beta 先验。"""
        observation.timestamp = time.time()
        self._state.observation_count += 1

        prior = self._state.get_prior(observation.action_id, observation.intent)

        # 二元结果: useful=True → α+1, useful=False → β+1
        # quality_score 作为加权系数, 高质量的正确路由应获更强正反馈
        weight = 0.5 + 0.5 * observation.quality_score
        prior.update(observation.useful, weight)

        # 同时以弱信号更新邻近意图的 prior (平滑推广)
        self._propagate(observation.action_id, observation.intent, observation.useful, weight * 0.15)

        self._maybe_decay()

    def _propagate(
        self, action_id: str, intent: IntentCategory, success: bool, weight: float
    ) -> None:
        """将观测结果以衰减权重传播到邻近意图类别。"""
        adjacent = self._adjacent_intents(intent)
        for adj in adjacent:
            prior = self._state.get_prior(action_id, adj)
            prior.update(success, weight * 0.3)

    def _adjacent_intents(self, intent: IntentCategory) -> List[IntentCategory]:
        """返回语义上邻近的意图类别。"""
        adjacency = {
            IntentCategory.STATIC_COLLECTION: [
                IntentCategory.DYNAMIC_INTERACTION, IntentCategory.FILE_ANALYSIS,
            ],
            IntentCategory.DYNAMIC_INTERACTION: [
                IntentCategory.STATIC_COLLECTION, IntentCategory.INTEL_CORRELATION,
            ],
            IntentCategory.INTEL_CORRELATION: [
                IntentCategory.FILE_ANALYSIS, IntentCategory.DYNAMIC_INTERACTION,
            ],
            IntentCategory.FILE_ANALYSIS: [
                IntentCategory.STATIC_COLLECTION, IntentCategory.INTEL_CORRELATION,
            ],
            IntentCategory.UNKNOWN: [
                IntentCategory.STATIC_COLLECTION, IntentCategory.INTEL_CORRELATION,
                IntentCategory.DYNAMIC_INTERACTION, IntentCategory.FILE_ANALYSIS,
            ],
        }
        return adjacency.get(intent, [])

    def _maybe_decay(self) -> None:
        """周期衰减: 使旧观测的影响随时间递减。"""
        now = time.time()
        last = self._state.last_decay_time
        if last > 0 and (now - last) < self._decay_interval:
            return
        self._state.last_decay_time = now
        for prior in self._state.priors.values():
            prior.decay(self._decay_factor)

    def get_action_utility_estimate(self, action_id: str) -> Dict[IntentCategory, float]:
        """返回指定采集器对所有意图的当前效用估计 (后验均值)。"""
        result: Dict[IntentCategory, float] = {}
        for intent in IntentCategory:
            prior = self._state.get_prior(action_id, intent)
            result[intent] = prior.mean()
        return result

    def exploration_bonus(self, action_id: str, intent: IntentCategory) -> float:
        """
        计算 UCB 风格的探索奖励。
        方差越高 (观测越少) → 奖励越大 → 鼓励探索未充分测试的采集器。
        """
        prior = self._state.get_prior(action_id, intent)
        # UCB: mean + sqrt(2 * ln(N) / n), 用方差近似
        n_effective = prior.alpha + prior.beta
        if n_effective <= 2:
            return 0.3  # 近乎无观测, 高探索奖励
        total_obs = max(1, self._state.observation_count)
        bonus = math.sqrt(2.0 * math.log(total_obs + 1) / n_effective)
        return min(0.3, bonus)


__all__ = [
    "OutcomeObservation",
    "OnlineCalibrator",
]
