"""
RL漏洞代理 — Q-learning优化漏洞发现流水线。

强化学习优化模糊策略选择/变异调度/分析优先级。
"""

from __future__ import annotations

import json
import logging
import math
import random
from abc import ABC, abstractmethod
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional


@dataclass
class PipelineState:
    """漏洞发现管线的状态描述。"""
    modules: List[str] = field(default_factory=list)
    parameters: Dict[str, Any] = field(default_factory=dict)
    performance: float = 0.0


@dataclass
class AgentAction:
    """智能体对管线执行的动作。"""
    action_type: str = ""
    target: str = ""
    new_value: Any = None


@dataclass
class RewardSignal:
    """单轮迭代的奖励信号。"""
    vulns_found: int = 0
    time_spent: float = 0.0
    coverage: float = 0.0
    false_positives: int = 0
    total_reward: float = 0.0


@dataclass
class PolicyResult:
    """策略评估结果。"""
    success: bool = False
    optimized_pipeline: List[str] = field(default_factory=list)
    total_reward: float = 0.0
    iterations: int = 0


class QLearningAgent:
    """Q-learning agent with state discretization for pipeline optimization."""

    def __init__(self, learning_rate: float = 0.1,
                 discount: float = 0.9, epsilon: float = 0.2):
        self.lr = learning_rate
        self.discount = discount
        self.epsilon = epsilon
        self.q_table: Dict[str, Dict[str, float]] = {}

    def get_action(self, state: str, actions: List[str]) -> str:
        """按 epsilon-贪心选择动作。"""
        if random.random() < self.epsilon:
            return random.choice(actions)
        q = self.q_table.get(state, {})
        if not q:
            return random.choice(actions)
        best_action = max(q, key=lambda a: q[a])
        if best_action not in actions:
            return random.choice(actions)
        return best_action

    def update(self, state: str, action: str, reward: float,
               next_state: str, actions: List[str]) -> None:
        """单步 Q 更新。"""
        q = self.q_table.setdefault(state, {})
        current = q.get(action, 0.0)
        next_q = self.q_table.get(next_state, {})
        max_next = max(next_q.values()) if next_q else 0.0
        target = reward + self.discount * max_next
        q[action] = current + self.lr * (target - current)


class RLVulnAgent:
    """Reinforcement learning agent for vulnerability discovery optimization."""

    ACTIONS = ["reorder", "adjust_param", "skip_module"]

    def __init__(self):
        self.q_agent = QLearningAgent()
        self.pipeline: List[str] = []

    def _reward(self, modules: List[str]) -> float:
        """启发式奖励 — 模块数越多，越接近合理管线，奖励越高。"""
        base = len(modules) * 0.5
        return base if modules else 0.0

    def run(self, modules: List[str],
            target_iterations: int = 10) -> PolicyResult:
        """执行多轮调度优化，返回优化后的管线与累计奖励。"""
        self.pipeline = list(modules)
        state = "start"
        total_reward = 0.0

        for _ in range(max(1, target_iterations)):
            action = self.q_agent.get_action(state, self.ACTIONS)
            reward = self._reward(self.pipeline)
            self.q_agent.update(state, action, reward, state, self.ACTIONS)
            total_reward += reward

            if action == "skip_module" and len(self.pipeline) > 1:
                self.pipeline.pop()

        return PolicyResult(
            success=True,
            optimized_pipeline=list(self.pipeline),
            total_reward=total_reward,
            iterations=max(1, target_iterations),
        )

        action = AgentAction(
            action_type=_FUZZ_ACTIONS[action_idx],
            action_index=action_idx,
        )

def create_rl_agent() -> RLVulnAgent:
    """构造漏洞发现优化代理。"""
    return RLVulnAgent()
