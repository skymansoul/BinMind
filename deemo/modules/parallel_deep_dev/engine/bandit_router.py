"""
创建: 2024-09-02
修改:
  2025-08-02 - 持久化路径统一到 _data_dir()
Thompson Sampling 模块-配置路由 — 为每个模块学习最优生成配置。

问题：不同模块的最优生成参数不同——fuzzing 模块在低 temperature(0.2)下
逻辑更严谨，exploit 模块在中 temperature(0.5)下创意更丰富。当前系统对所有
模块使用统一的全局参数（CONFIG.API_TEMPERATURE / API_MAX_TOKENS），
无法适配模块间的差异性需求。

现有 MAB 路由器将 LLM provider
作为 arm 做成本优化路由，不处理同模型内 per-module 的配置选择。

方案：Thompson Sampling with Beta-Bernoulli conjugate model。
  - Context（上下文）：模块标识 (module_key)
  - Arm（摇臂）：离散化的 (temperature, max_tokens) 组合
  - Reward（奖励）：该配置下产出的综合质量分数 (0-1)
  - 选择策略：从每个 arm 的 Beta(α, β) 后验中采样，选最大采样值
  - 更新策略：观察到质量分数 r 后，α += r, β += (1-r)

配置离散化：
  temperature ∈ {0.1, 0.2, 0.3, 0.5, 0.7}  (5档)
  max_tokens ∈ {4000, 8000, 12000, 16000, 20000}  (5档)
  → 每个模块 25 个 arm，5个模块 = 125个 arm，Beta参数内存占用 ~1KB

为什么 Thompson Sampling 而非 ε-greedy 或 UCB：
  - ε-greedy 浪费探索预算在已知差的 arm 上
  - UCB 确定性选择导致并行 worker 坍缩到同一 arm
  - Thompson 的随机采样自然分散并行 worker 的配置选择
  - Beta-Bernoulli 共轭模型更新 O(1)，决策 O(K)，K=每个模块的arm数

与现有工作的差异：
  - rl-router: provider 间路由，同模型内配置选择文献中未见
  - SmartBandit: 成本优化，本模块优化代码生成质量
  - KernelBand: MAB 用于 kernel 优化，非代码生成管线参数
"""

from __future__ import annotations

import json
import math
import os
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field


# 配置离散化网格
_TEMPERATURE_GRID = [0.1, 0.2, 0.3, 0.5, 0.7]
_TOKENS_GRID = [4000, 8000, 12000, 16000, 20000]

from parallel_deep_dev.config import _data_dir
_CONFIGS_PATH = os.path.join(_data_dir(), "bandit_configs.json")


@dataclass
class ArmState:
    """单个 arm 的 Beta 后验状态。α=成功计数, β=失败计数。"""
    alpha: float = 1.0    # Beta(1,1) = Uniform(0,1) 先验
    beta: float = 1.0
    pulls: int = 0
    last_reward: float = 0.0

    def sample(self) -> float:
        """从 Beta(α, β) 采样——使用 Gamma 近似。"""
        return random.betavariate(self.alpha, self.beta) if self.pulls > 0 else random.random()

    def update(self, reward: float) -> None:
        """用观察到的 reward 更新后验。reward ∈ [0, 1]。"""
        r = max(0.0, min(1.0, reward))
        self.alpha += r
        self.beta += (1.0 - r)
        self.pulls += 1
        self.last_reward = r

    @property
    def mean(self) -> float:
        total = self.alpha + self.beta
        return self.alpha / total if total > 0 else 0.5


@dataclass
class BanditRouter:
    """Thompson Sampling 模块-配置路由器。

    典型用法：
      router = BanditRouter()
      config = router.select("fuzzing")  # 返回 {'temperature': 0.3, 'max_tokens': 12000}
      # ... 执行生成 ...
      router.reward("fuzzing", config, quality_score=0.85)
    """

    _arms: dict[str, dict[str, ArmState]] = field(default_factory=lambda: defaultdict(dict))

    def select(self, module_key: str) -> dict[str, float]:
        """为模块选择最优配置。Thompson Sampling 决策。

        若模块无历史数据，返回默认配置。
        返回 {'temperature': float, 'max_tokens': int}。"""
        arms = self._arms.get(module_key, {})

        if not arms:
            # 冷启动：返回中档默认配置
            cfg = {"temperature": 0.3, "max_tokens": 8000}
            arm_key = self._config_to_key(cfg)
            self._arms[module_key][arm_key] = ArmState()
            return cfg

        # Thompson Sampling：从每个 arm 的后验采样，选最大
        best_arm = None
        best_sample = -1.0
        for arm_key, state in arms.items():
            s = state.sample()
            if s > best_sample:
                best_sample = s
                best_arm = arm_key

        if best_arm is None:
            return {"temperature": 0.3, "max_tokens": 8000}

        return self._key_to_config(best_arm)

    def reward(
        self,
        module_key: str,
        config: dict[str, float],
        quality_score: float,
    ) -> None:
        """记录一次配置选择的奖励。quality_score ∈ [0, 1]。"""
        arm_key = self._config_to_key(config)
        state = self._arms[module_key].get(arm_key)
        if state is None:
            state = ArmState()
            self._arms[module_key][arm_key] = state
        state.update(quality_score)

    def best_config(self, module_key: str) -> dict[str, float] | None:
        """返回模块已知的最优配置（后验均值最大）。"""
        arms = self._arms.get(module_key, {})
        if not arms:
            return None
        best_key = max(arms, key=lambda k: arms[k].mean)
        return self._key_to_config(best_key)

    def module_stats(self, module_key: str) -> dict:
        """返回模块的路由统计。"""
        arms = self._arms.get(module_key, {})
        if not arms:
            return {"configured": False, "arms": 0, "total_pulls": 0}

        total_pulls = sum(a.pulls for a in arms.values())
        best_key = max(arms, key=lambda k: arms[k].mean)
        best_state = arms[best_key]

        return {
            "configured": True,
            "arms": len(arms),
            "total_pulls": total_pulls,
            "best_config": self._key_to_config(best_key),
            "best_mean": round(best_state.mean, 3),
            "best_pulls": best_state.pulls,
        }

    def exploration_ratio(self, module_key: str) -> float:
        """探索率：pull 数 <=2 的 arm 占比。高值 = 仍在探索阶段。"""
        arms = self._arms.get(module_key, {})
        if not arms:
            return 1.0
        exploring = sum(1 for a in arms.values() if a.pulls <= 2)
        return exploring / len(arms)

    # 持久化

    def save(self) -> None:
        payload: dict = {}
        for mod_key, arms in self._arms.items():
            payload[mod_key] = {}
            for arm_key, state in arms.items():
                payload[mod_key][arm_key] = {
                    "alpha": state.alpha, "beta": state.beta,
                    "pulls": state.pulls, "last_reward": state.last_reward,
                }
        try:
            with open(_CONFIGS_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def load(self) -> bool:
        if not os.path.isfile(_CONFIGS_PATH):
            return False
        try:
            with open(_CONFIGS_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return False
        for mod_key, arms_data in payload.items():
            for arm_key, state_data in arms_data.items():
                self._arms[mod_key][arm_key] = ArmState(
                    alpha=state_data.get("alpha", 1.0),
                    beta=state_data.get("beta", 1.0),
                    pulls=state_data.get("pulls", 0),
                    last_reward=state_data.get("last_reward", 0.0),
                )
        return True

    # 内部

    @staticmethod
    def _config_to_key(config: dict[str, float]) -> str:
        t = config.get("temperature", 0.3)
        tk = int(config.get("max_tokens", 8000))
        # 映射到最近的网格点
        t_idx = min(range(len(_TEMPERATURE_GRID)),
                     key=lambda i: abs(_TEMPERATURE_GRID[i] - t))
        tk_idx = min(range(len(_TOKENS_GRID)),
                      key=lambda i: abs(_TOKENS_GRID[i] - tk))
        return f"t{t_idx}_k{tk_idx}"

    @staticmethod
    def _key_to_config(key: str) -> dict[str, float]:
        parts = key.split("_")
        t_idx = int(parts[0][1:])
        k_idx = int(parts[1][1:])
        return {
            "temperature": _TEMPERATURE_GRID[t_idx],
            "max_tokens": float(_TOKENS_GRID[k_idx]),
        }


# 便捷集成入口

def route_and_record(
    router: BanditRouter,
    module_key: str,
    module_defs: dict[str, dict],
    quality_score: float | None = None,
    last_config: dict[str, float] | None = None,
) -> dict[str, float]:
    """路由便利函数：选择配置并可选地记录上一轮的奖励。

    若 quality_score 和 last_config 均提供，先记录奖励再选择新配置。
    这使调用方可以在单个调用中完成"记录上次结果 + 获取下次配置"的闭环。"""
    if quality_score is not None and last_config is not None:
        router.reward(module_key, last_config, quality_score)

    return router.select(module_key)
