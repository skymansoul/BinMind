"""
创建: 2025-08-05

上下文Bandit路由器扩展 — LinUCB + 自适应策略切换。

bandit_router.py 使用非上下文 Thompson Sampling（25个arm），每个模块独立学习。
问题：模块的复杂度、依赖深度、历史成功率等上下文特征被忽略——
复杂模块和简单模块使用相同的 arm 空间，无法利用跨模块的迁移学习。

方案：在 Thompson Sampling 基础上增加上下文策略。
  LinUCB (Disjoint): 每个 arm 维护独立的线性模型 θ_a。
  预测奖励 = θ_a^T · x，其中 x 是模块的上下文特征向量。
  选择 arm = argmax(θ_a^T · x + α · √(x^T · A_a⁻¹ · x))。

  自适应切换：观测数 < 10 使用 Thompson Sampling（探索优先），
  >= 10 切换到 LinUCB（利用上下文信息）。

上下文特征向量（4维）：
  x[0] = 复杂度比值（AST节点数/基准值），归一化到 [0,1]
  x[1] = 依赖深度，归一化到 [0,1]（除以最大深度5）
  x[2] = 历史成功率（0-1）
  x[3] = 偏置项（恒为1.0）

与现有工作的差异：
  - rl-router/SmartBandit: provider间路由，无上下文特征
  - Conduit: 支持 TS+LinUCB 但用于 provider 选择，非 per-module 配置
  - 本模块的"模块特征→配置推荐"的上下文映射在文献中未见，
    将跨模块知识迁移引入并行代码生成的配置选择
"""

from __future__ import annotations

import json
import math
import os
from dataclasses import dataclass, field

from parallel_deep_dev.config import _data_dir

_CONTEXTUAL_PATH = os.path.join(_data_dir(), "bandit_contextual.json")

# LinUCB 探索参数
_ALPHA_DEFAULT: float = 1.0
# 特征维度
_FEAT_DIM: int = 4
# 切换到 LinUCB 的最小观测数
_MIN_OBS_FOR_LINUCB: int = 10


@dataclass
class LinUCBArm:
    """单个 arm 的 LinUCB 状态。"""
    # A_a = D_a^T · D_a + I (ridge regression 的正则化矩阵)
    A: list[list[float]] = field(default_factory=lambda: [[0.0]*_FEAT_DIM for _ in range(_FEAT_DIM)])
    # A_a⁻¹ (Sherman-Morrison 增量更新，避免每步 O(d³) 求逆)
    A_inv: list[list[float]] = field(default_factory=lambda: [[0.0]*_FEAT_DIM for _ in range(_FEAT_DIM)])
    # b_a = Σ r_t · x_t
    b: list[float] = field(default_factory=lambda: [0.0]*_FEAT_DIM)
    # θ_a = A_a⁻¹ · b_a (当前估计的参数向量)
    theta: list[float] = field(default_factory=lambda: [0.0]*_FEAT_DIM)
    pulls: int = 0
    initialized: bool = False

    def _ensure_init(self) -> None:
        if not self.initialized:
            for i in range(_FEAT_DIM):
                self.A[i][i] = 1.0
                self.A_inv[i][i] = 1.0
            self.initialized = True

    def predict(self, features: list[float], alpha: float) -> tuple[float, float]:
        """返回 (predicted_reward, confidence_bound)。"""
        self._ensure_init()
        # θ = A⁻¹ · b
        for i in range(_FEAT_DIM):
            s = sum(self.A_inv[i][j] * self.b[j] for j in range(_FEAT_DIM))
            self.theta[i] = s
        # predicted = θ^T · x
        pred = sum(self.theta[i] * features[i] for i in range(_FEAT_DIM))
        # confidence = α · √(x^T · A⁻¹ · x)
        conf = 0.0
        for i in range(_FEAT_DIM):
            for j in range(_FEAT_DIM):
                conf += features[i] * self.A_inv[i][j] * features[j]
        conf = alpha * math.sqrt(max(conf, 1e-12))
        return pred, conf

    def update(self, features: list[float], reward: float) -> None:
        """Sherman-Morrison 增量更新 A⁻¹ 和 b。O(d²) 而非 O(d³)。"""
        self._ensure_init()
        # A⁻¹ ← A⁻¹ - (A⁻¹·x)(x^T·A⁻¹)/(1 + x^T·A⁻¹·x)
        # 先计算 A⁻¹·x
        ax = [sum(self.A_inv[i][j] * features[j] for j in range(_FEAT_DIM))
              for i in range(_FEAT_DIM)]
        # 分母 = 1 + x^T·A⁻¹·x
        denom = 1.0 + sum(ax[i] * features[i] for i in range(_FEAT_DIM))
        # 更新 A⁻¹
        for i in range(_FEAT_DIM):
            for j in range(_FEAT_DIM):
                self.A_inv[i][j] -= (ax[i] * ax[j]) / denom
        # 更新 b
        for i in range(_FEAT_DIM):
            self.b[i] += reward * features[i]
        self.pulls += 1


@dataclass
class ContextualBanditRouter:
    """上下文 + 非上下文混合 Bandit 路由器。

    自适应策略：观测数少时用 Thompson Sampling，
    足够多时切换到 LinUCB 利用模块上下文特征。"""

    alpha: float = _ALPHA_DEFAULT
    _linucb_arms: dict[str, dict[str, LinUCBArm]] = field(default_factory=dict)

    def select_contextual(
        self, module_key: str, features: list[float],
        ts_router=None,
    ) -> dict[str, float]:
        """上下文感知的配置选择。

        若 ts_router 提供且观测充足，使用 LinUCB；
        否则回退到 Thompson Sampling。

        features: [复杂度, 依赖深度, 历史成功率, 1.0]"""
        total_pulls = self._total_pulls(module_key)

        if total_pulls >= _MIN_OBS_FOR_LINUCB and len(features) == _FEAT_DIM:
            return self._linucb_select(module_key, features)
        elif ts_router is not None:
            return ts_router.select(module_key)
        # 无 TS router，回退到 LinUCB 即使数据不足
        return self._linucb_select(module_key, features)

    def reward_contextual(
        self, module_key: str, config: dict[str, float],
        features: list[float], quality_score: float,
    ) -> None:
        """记录 LinUCB 的奖励，更新对应 arm 的线性模型。"""
        if len(features) != _FEAT_DIM:
            return
        arm_key = _config_to_key(config)
        arms = self._linucb_arms.setdefault(module_key, {})
        arm = arms.setdefault(arm_key, LinUCBArm())
        arm.update(features, quality_score)

    def _linucb_select(self, module_key: str, features: list[float]) -> dict[str, float]:
        arms = self._linucb_arms.get(module_key, {})
        if not arms:
            from parallel_deep_dev.engine.bandit_router import BanditRouter
            cfg = BanditRouter().select(module_key)
            arm_key = _config_to_key(cfg)
            arms[arm_key] = LinUCBArm()
            self._linucb_arms[module_key] = arms
            return cfg

        best_arm = None
        best_ucb = -1e9
        for arm_key, arm in arms.items():
            pred, conf = arm.predict(features, self.alpha)
            ucb = pred + conf
            if ucb > best_ucb:
                best_ucb = ucb
                best_arm = arm_key

        if best_arm is None:
            return {"temperature": 0.3, "max_tokens": 8000}
        return _key_to_config(best_arm)

    def _total_pulls(self, module_key: str) -> int:
        return sum(a.pulls for a in self._linucb_arms.get(module_key, {}).values())

    def save(self) -> None:
        payload: dict = {}
        for mod_key, arms in self._linucb_arms.items():
            payload[mod_key] = {}
            for arm_key, arm in arms.items():
                payload[mod_key][arm_key] = {
                    "A_inv": arm.A_inv, "b": arm.b,
                    "theta": arm.theta, "pulls": arm.pulls,
                }
        try:
            with open(_CONTEXTUAL_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2, ensure_ascii=False)
        except OSError:
            pass

    def load(self) -> bool:
        if not os.path.isfile(_CONTEXTUAL_PATH):
            return False
        try:
            with open(_CONTEXTUAL_PATH, "r", encoding="utf-8") as f:
                payload = json.load(f)
        except (OSError, json.JSONDecodeError):
            return False
        for mod_key, arms_data in payload.items():
            for arm_key, state_data in arms_data.items():
                arm = LinUCBArm(
                    A_inv=state_data["A_inv"], b=state_data["b"],
                    theta=state_data.get("theta", [0.0]*_FEAT_DIM),
                    pulls=state_data.get("pulls", 0),
                )
                arm.initialized = True
                self._linucb_arms.setdefault(mod_key, {})[arm_key] = arm
        return True


# 与 bandit_router 共享的 key 编码
_TEMPERATURE_GRID = [0.1, 0.2, 0.3, 0.5, 0.7]
_TOKENS_GRID = [4000, 8000, 12000, 16000, 20000]


def _config_to_key(config: dict[str, float]) -> str:
    t = config.get("temperature", 0.3)
    tk = int(config.get("max_tokens", 8000))
    t_idx = min(range(len(_TEMPERATURE_GRID)),
                 key=lambda i: abs(_TEMPERATURE_GRID[i] - t))
    tk_idx = min(range(len(_TOKENS_GRID)),
                  key=lambda i: abs(_TOKENS_GRID[i] - tk))
    return f"t{t_idx}_k{tk_idx}"


def _key_to_config(key: str) -> dict[str, float]:
    parts = key.split("_")
    return {
        "temperature": _TEMPERATURE_GRID[int(parts[0][1:])],
        "max_tokens": float(_TOKENS_GRID[int(parts[1][1:])]),
    }


def make_features(complexity: float, dep_depth: int, hist_success: float) -> list[float]:
    """从模块特征构建归一化的上下文特征向量。
    全归一化到 [0,1]，第4维为偏置项。"""
    return [
        min(1.0, max(0.0, complexity / 5.0)),
        min(1.0, max(0.0, dep_depth / 5.0)),
        min(1.0, max(0.0, hist_success)),
        1.0,
    ]
