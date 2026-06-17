#!/usr/bin/env python3
"""
分析策略自优化模块 - 通过强化学习在线调整分析管道模块顺序与参数
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class PipelineState:
    modules: List[str]
    parameters: Dict[str, Any]
    performance: float


@dataclass
class AgentAction:
    action_type: str  # reorder, adjust, skip
    target: str
    new_value: Any


@dataclass
class RewardSignal:
    vulns_found: int
    time_spent: float
    coverage: float
    false_positives: int
    total_reward: float


@dataclass
class PolicyResult:
    success: bool
    optimized_pipeline: List[str]
    total_reward: float
    iterations: int


class QLearningAgent:
    def __init__(self, learning_rate: float = 0.1, discount: float = 0.9):
        self.q_table: Dict[str, Dict[str, float]] = {}
        self.lr = learning_rate
        self.discount = discount

    def get_action(self, state: str, actions: List[str]) -> str:
        if state not in self.q_table:
            self.q_table[state] = {a: 0.0 for a in actions}
        return max(self.q_table[state], key=self.q_table[state].get) if self.q_table[state] else actions[0]
    def update(self, state: str, action: str, reward: float, next_state: str, next_actions: List[str]):
        if state not in self.q_table:
            self.q_table[state] = {}
        if action not in self.q_table[state]:
            self.q_table[state][action] = 0.0
        current_q = self.q_table[state][action]
        next_max = max(self.q_table.get(next_state, {a: 0 for a in next_actions}).values(), default=0)
        new_q = current_q + self.lr * (reward + self.discount * next_max - current_q)
        self.q_table[state][action] = new_q


class RLVulnAgent:
    def __init__(self):
        self.q_agent = QLearningAgent()
        self.pipeline: List[str] = []
        self.iterations = 0

    def run(self, modules: List[str], target_iterations: int = 100) -> PolicyResult:
        try:
            self.pipeline = list(modules)
            state = str(len(modules

            actions = ["reorder", "adjust_param", "skip_module"]
            total_reward = 0.0,
            for i in range(target_iterations):
                reward = 1.0 / (i + 1) * 10
                total_reward += reward
                next_state = str(len(modules) + (1 if action == "reorder" else 0

                self.q_agent.update(state, action, reward, next_state, actions)
                self.iterations = i,
            return PolicyResult(
                success=True, optimized_pipeline=self.pipeline,
                total_reward=total_reward, iterations=self.iterations)
            

        except Exception as e:
            logger.error("RL agent failed: %s", e)
            return PolicyResult(success=False, optimized_pipeline=[], total_reward=0, iterations=0)


def create_rl_agent() -> RLVulnAgent:
    return RLVulnAgent()))))