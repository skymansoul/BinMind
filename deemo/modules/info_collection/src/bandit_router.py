"""
Bandit 采集器路由器 (BCR) —— 基于 Thompson 采样的动态采集器选择。

LLM Bandit (arXiv:2502.02743) 将 LLM 模型选择建模为多目标 MAB,
MixLLM (arXiv:2502.18482) 使用上下文 Bandit 联合优化质量/成本/延迟。
本模块将同一框架适配到安全采集器选择: 每个采集器是一个 arm,
奖励 = 采集结果质量, 成本 = 执行延迟 + 资源消耗。

与 LLM Bandit 的关键差异:
1. Arms 是采集器而非 LLM 模型, reward 来自采集结果有用性而非生成质量
2. 偏好向量 ω 编码的是 depth/cost/speed 三维权衡, 而非单一的 quality/cost
3. 跨采集器迁移: 新注册的采集器从语义相似采集器继承先验, 实现零样本引导

Thompson 采样: 每个 arm 维护 Beta(α, β) 先验, α = 成功次数, β = 失败次数。
每次选择时从每个 arm 的后验中采样, 选 reward/cost 比值最高的 arm。
"""

# File: bandit_router.py  |  2026-08-01 create BCR; 2026-08-04 audit: use shared BetaPrior

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory
from .beta_prior import BetaPrior  # 共享基元, 消除与 online_calibrate 的重复


@dataclass
class ArmState:
    """单个采集器 (arm) 的状态。使用共享 BetaPrior 管理奖励分布。"""
    action_id: str
    prior: BetaPrior = field(default_factory=BetaPrior)
    total_cost: float = 0.0
    total_latency: float = 0.0
    pull_count: int = 0
    last_pull_time: float = 0.0
    tags: Set[str] = field(default_factory=set)

    @property
    def mean_reward(self) -> float:
        return self.prior.mean()

    @property
    def avg_cost(self) -> float:
        return self.total_cost / self.pull_count if self.pull_count > 0 else 1.0

    @property
    def avg_latency(self) -> float:
        return self.total_latency / self.pull_count if self.pull_count > 0 else 100.0

    def thompson_sample(self) -> float:
        return self.prior.sample()


@dataclass
class PreferenceWeights:
    """偏好权重向量 ω。"""
    quality: float = 0.5    # 采集结果质量权重
    cost: float = 0.3       # 成本敏感度 (越高越倾向低成本)
    speed: float = 0.2      # 速度敏感度 (越高越倾向低延迟)
    # 总和应为 1.0

    def normalized(self) -> "PreferenceWeights":
        total = self.quality + self.cost + self.speed
        if total == 0:
            return PreferenceWeights(0.5, 0.3, 0.2)
        return PreferenceWeights(
            self.quality / total, self.cost / total, self.speed / total,
        )


@dataclass
class BanditSelection:
    """Bandit 选择结果。"""
    action_id: str
    sampled_reward: float
    score: float              # 综合评分 (reward / weighted_cost)
    rank: int
    is_exploration: bool       # 是否为探索性选择 (> 2σ 偏离均值)


# 采集器语义标签 —— 用于跨采集器迁移
_COLLECTOR_TAGS: Dict[str, Set[str]] = {
    "host_enum": {"host", "local", "static", "fast"},
    "net_mapping": {"network", "remote", "static", "medium"},
    "service_enum": {"service", "local", "static", "fast"},
    "ioctl_probe": {"device", "kernel", "dynamic", "slow", "risky"},
    "driver_probe": {"driver", "kernel", "dynamic", "slow", "risky"},
    "input_fuzz": {"fuzz", "dynamic", "slow", "risky"},
    "cve_lookup": {"intel", "remote", "network", "medium"},
    "ioc_lookup": {"intel", "remote", "network", "medium"},
    "osint_recon": {"intel", "remote", "network", "slow"},
    "pe_analyze": {"file", "local", "static", "fast"},
    "strings_extract": {"file", "local", "static", "fast"},
    "hash_compute": {"file", "local", "static", "fast"},
}


class BanditCollectorRouter:
    """
    Thompson 采样驱动的采集器选择。

    选择策略:
    1. 对每个候选 arm, 从 Beta(α, β) 后验采样得到采样奖励 r̂
    2. 计算评分: score = r̂ / (ω_cost * cost_norm + ω_speed * latency_norm)
    3. 选 score 最高的 arm
    4. 观察实际结果后更新后验

    偏好调节: 保守场景提高 quality 权重 → 倾向选择历史表现好的采集器;
    成本敏感场景提高 cost 权重 → 倾向选择低成本采集器;
    实时场景提高 speed 权重 → 倾向选择低延迟采集器。
    """

    def __init__(self, preferences: Optional[PreferenceWeights] = None):
        self._arms: Dict[str, ArmState] = {}
        self._prefs = (preferences or PreferenceWeights()).normalized()
        self._exploration_count = 0
        self._exploitation_count = 0

    def register(self, action_id: str, tags: Optional[Set[str]] = None) -> None:
        """注册采集器。若存在语义相似的已注册采集器, 从其继承先验。"""
        if action_id in self._arms:
            return
        arm_tags = tags or _COLLECTOR_TAGS.get(action_id, set())
        arm = ArmState(action_id=action_id, tags=arm_tags)

        # 跨采集器迁移: 从标签最相似的已有 arm 继承先验
        best_sim = 0.0
        best_existing: Optional[ArmState] = None
        for existing in self._arms.values():
            if not existing.tags or not arm_tags:
                continue
            sim = len(existing.tags & arm_tags) / max(1, len(existing.tags | arm_tags))
            if sim > best_sim and existing.pull_count >= 5:
                best_sim = sim
                best_existing = existing

        if best_existing is not None and best_sim > 0.3:
            # 按相似度权重继承先验, 同时向无信息先验收缩
            transfer_weight = best_sim * 0.5
            arm.prior.alpha = 1.0 + (best_existing.prior.alpha - 1.0) * transfer_weight
            arm.prior.beta = 1.0 + (best_existing.prior.beta - 1.0) * transfer_weight

        self._arms[action_id] = arm

    def select(
        self, candidates: List[str], intent: IntentCategory,
    ) -> BanditSelection:
        """
        从候选采集器中选择最优 arm。

        对未注册的候选自动注册 (冷启动: 无信息先验 + 标签迁移)。
        """
        for cid in candidates:
            if cid not in self._arms:
                self.register(cid)

        if not candidates:
            return BanditSelection("", 0.0, 0.0, 0, False)

        scores: List[Tuple[str, float, float, bool]] = []
        for cid in candidates:
            arm = self._arms[cid]
            sampled_r = arm.thompson_sample()

            # 归一化成本和延迟
            max_cost = max((self._arms[c].avg_cost for c in candidates), default=1.0)
            max_lat = max((self._arms[c].avg_latency for c in candidates), default=100.0)
            cost_norm = arm.avg_cost / max(1.0, max_cost)
            latency_norm = arm.avg_latency / max(1.0, max_lat)

            # 综合评分: 奖励 / 加权成本
            weighted_cost = (
                self._prefs.cost * cost_norm
                + self._prefs.speed * latency_norm
            )
            if weighted_cost <= 0:
                weighted_cost = 0.01
            score = sampled_r / weighted_cost

            # 探索标记: 采样值显著偏离均值 (> 2σ)
            var = arm.prior.variance
            is_explore = abs(sampled_r - arm.mean_reward) > 2 * math.sqrt(max(0.001, var))

            scores.append((cid, sampled_r, score, is_explore))

        scores.sort(key=lambda x: x[2], reverse=True)
        best = scores[0]

        if best[3]:
            self._exploration_count += 1
        else:
            self._exploitation_count += 1

        return BanditSelection(
            action_id=best[0],
            sampled_reward=best[1],
            score=best[2],
            rank=1,
            is_exploration=best[3],
        )

    def observe(self, action_id: str, useful: bool, latency_ms: float, cost: float = 1.0) -> None:
        """观察采集结果, 更新对应 arm 的后验。"""
        arm = self._arms.get(action_id)
        if arm is None:
            return
        if useful:
            arm.prior.update(True)
        else:
            arm.prior.update(False)
        arm.total_cost += cost
        arm.total_latency += latency_ms
        arm.pull_count += 1
        arm.last_pull_time = time.time()

    def update_preferences(self, prefs: PreferenceWeights) -> None:
        self._prefs = prefs.normalized()

    def get_arm_stats(self) -> List[Dict[str, Any]]:
        stats: List[Dict[str, Any]] = []
        for aid, arm in self._arms.items():
            stats.append({
                "action_id": aid,
                "mean_reward": round(arm.mean_reward, 4),
                "pulls": arm.pull_count,
                "avg_latency_ms": round(arm.avg_latency, 1),
                "avg_cost": round(arm.avg_cost, 2),
                "tags": list(arm.tags),
            })
        return sorted(stats, key=lambda x: x["mean_reward"], reverse=True)

    @property
    def explore_ratio(self) -> float:
        total = self._exploration_count + self._exploitation_count
        return self._exploration_count / total if total > 0 else 0.0

    def reset(self) -> None:
        self._arms.clear()
        self._exploration_count = 0
        self._exploitation_count = 0


__all__ = [
    "ArmState",
    "PreferenceWeights",
    "BanditSelection",
    "BanditCollectorRouter",
]
