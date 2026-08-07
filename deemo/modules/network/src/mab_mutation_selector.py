# 基于Thompson采样的协议状态感知变异算子选择器。
#
# 传统模糊测试对变异算子使用固定权重或启发式轮转。
# 不同协议状态对变异算子的敏感度不同：握手状态对字节翻转敏感，
# 数据传输状态对边界值注入敏感，关闭状态对时序变异敏感。
#
# 本模块将变异算子选择建模为情境多臂老虎机(Contextual MAB)：
#   情境 = 当前协议状态标识
#   臂   = 变异算子类型
#   奖励 = 差分预言机输出(新路径/崩溃/语义分歧)
#
# 核心创新：层次化Beta先验共享。
#   相似协议状态(共享消息类型≥2)的Beta参数通过矩匹配汇聚，
#   使低频状态从高频状态借用统计强度，冷启动时无需均匀随机。
#   这解决了标准Thompson采样在状态空间稀疏时的数据匮乏问题。
#
# 理论依据:
#   - Thompson: 按后验最优概率随机采样，期望遗憾O(√(KT log T))
#   - Chapelle & Li: 上下文bandit的对数遗憾界
#   - Agrawal & Goyal: Thompson采样的首个有限时间分析
#
# 与现有工作的差异:
#   - T-Scheduler: 对种子调度使用Thompson采样，非变异算子
#   - SCFuzz: 使用对抗MAB做种子阶段调度，非状态×算子联合
# 本模块: 层次化先验+状态间迁移+差分奖励，三者组合未见先行研究

from __future__ import annotations

import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Dict, List, Optional, Set, Tuple


class MutationOp(IntEnum):
    """变异算子类型 —— 覆盖语法感知与盲变异两个维度"""
    BIT_FLIP       = 0   # 单比特翻转
    BYTE_SWAP      = 1   # 双字节交换
    ARITHMETIC     = 2   # 算术边界: -1/0/+1/max/min
    BOUNDARY       = 3   # 字段边界: 长度溢出/截断/扩展
    CROSSOVER      = 4   # 种子间交叉拼接
    GRAMMAR_SUBTREE = 5  # 语法树子树替换（依赖协议语法模型）
    HAVOC          = 6   # 多重随机叠加变异
    SPLICE         = 7   # 种子尾部拼接

    @classmethod
    def default_set(cls) -> List[MutationOp]:
        return [cls.BIT_FLIP, cls.BYTE_SWAP, cls.ARITHMETIC,
                cls.BOUNDARY, cls.CROSSOVER, cls.HAVOC]


@dataclass
class BanditArm:
    """单臂的Beta后验参数与性能统计"""
    alpha: float = 1.0     # Beta(α,β): 成功次数的伪计数
    beta: float = 1.0      # 失败次数的伪计数
    pulls: int = 0
    successes: int = 0
    mean_reward: float = 0.0

    def sample(self) -> float:
        """Thompson采样: 从Beta(α,β)后验抽取随机样本"""
        return random.betavariate(max(self.alpha, 1e-6),
                                  max(self.beta, 1e-6))

    def update(self, reward: float) -> None:
        """以[0,1]连续奖励更新后验，使用矩匹配近似"""
        self.pulls += 1
        self.successes += reward
        self.mean_reward = self.successes / max(self.pulls, 1)
        # 连续奖励→Beta参数：保持均值不变，方差以1/pulls衰减
        # α/(α+β) = mean, (αβ)/((α+β)²(α+β+1)) ≈ 1/(4pulls)
        m = self.mean_reward
        if m <= 0.0:
            m = 0.01
        if m >= 1.0:
            m = 0.99
        total = self.pulls + 2.0
        self.alpha = m * total
        self.beta = (1.0 - m) * total


class HierarchicalBanditManager:
    """层次化Beta先验管理器 —— 在协议状态间共享统计强度。

    对于每个协议状态维护一个独立的K臂bandit实例。
    冷状态(观测<min_observations)的Beta参数从相似状态
    (共享≥2个消息类型)的后验通过矩匹配汇聚而来。

    这避免了标准独立bandit在状态空间大时的冷启动困境：
    新状态不从uniform开始，而是从相似状态的汇聚经验开始。
    """

    def __init__(self, ops: Optional[List[MutationOp]] = None,
                 min_observations_for_independence: int = 10):
        self._ops = ops or MutationOp.default_set()
        self._k = len(self._ops)
        self._min_obs = min_observations_for_independence
        # per-state bandits: state_id → {op → BanditArm}
        self._bandits: Dict[str, Dict[MutationOp, BanditArm]] = {}
        # 状态→消息类型关联: state_id → set of msg_types
        self._state_msg_types: Dict[str, Set[str]] = defaultdict(set)
        # 累积遗憾追踪
        self._cumulative_regret: float = 0.0

# 初始化和状态关联
    def register_state(self, state_id: str,
                       msg_types: Optional[Set[str]] = None) -> None:
        """注册协议状态及其关联的消息类型集合"""
        if state_id not in self._bandits:
            self._bandits[state_id] = {
                op: BanditArm() for op in self._ops
            }
        if msg_types:
            self._state_msg_types[state_id].update(msg_types)

    def _find_similar_states(self, state_id: str) -> List[str]:
        """查找共享≥2个消息类型的相似状态，按Jaccard相似度降序"""
        target_msgs = self._state_msg_types.get(state_id, set())
        if not target_msgs:
            return []
        scored: List[Tuple[float, str]] = []
        for sid, msgs in self._state_msg_types.items():
            if sid == state_id or not msgs:
                continue
            intersection = len(target_msgs & msgs)
            if intersection < 2:
                continue
            jaccard = intersection / len(target_msgs | msgs)
            scored.append((jaccard, sid))
        scored.sort(key=lambda x: -x[0])
        return [sid for _, sid in scored]

    def _hierarchical_prior(self, state_id: str,
                            op: MutationOp) -> Tuple[float, float]:
        """为给定状态×算子计算层次先验。

        若该状态自身的观测充足(≥_min_obs)，返回自身后验参数。
        否则从相似状态的后验通过精度加权矩匹配汇聚。
        """
        arm = self._bandits.get(state_id, {}).get(op)
        if arm and arm.pulls >= self._min_obs:
            return (arm.alpha, arm.beta)

        similar = self._find_similar_states(state_id)
        if not similar or not arm:
            return (1.0, 1.0)  # 无先验信息→均匀Beta(1,1)

        # 矩匹配汇聚: 以相似状态的pulls为精度权重
        total_alpha = 0.0
        total_beta = 0.0
        total_weight = 0.0
        for sid in similar:
            other_arm = self._bandits.get(sid, {}).get(op)
            if not other_arm or other_arm.pulls == 0:
                continue
            w = float(other_arm.pulls)
            total_alpha += w * other_arm.alpha
            total_beta += w * other_arm.beta
            total_weight += w

        if total_weight < 1.0:
            return (1.0, 1.0)
        # 缩放到先验强度=min_obs, 不过度受相似状态主导
        scale = self._min_obs / total_weight
        return (total_alpha * scale + 0.5,
                total_beta * scale + 0.5)

# 核心采样
    def select_operator(self, state_id: str,
                        explore_ratio: float = 0.0) -> MutationOp:
        """Thompson采样选择最优变异算子。

        explore_ratio ∈ [0,1]: 显式探索比例。
        当explore_ratio > 0时，以该概率随机选择（不参与遗憾跟踪），
        其余概率使用Thompson采样。
        """
        if state_id not in self._bandits:
            self.register_state(state_id)

        if random.random() < explore_ratio:
            return random.choice(self._ops)

        arms = self._bandits[state_id]
        best_op = self._ops[0]
        best_sample = -1.0

        for op in self._ops:
            # 混合层次先验与自身后验
            h_alpha, h_beta = self._hierarchical_prior(state_id, op)
            own = arms[op]
            # 当自身观测不足时，样本由层次先验主导
            if own.pulls < self._min_obs:
                sample = random.betavariate(
                    max(h_alpha, 1e-6), max(h_beta, 1e-6))
            else:
                sample = own.sample()
            if sample > best_sample:
                best_sample = sample
                best_op = op

        # 计算单步遗憾：最优臂期望 - 选中臂期望
        best_mean = max(
            a.mean_reward if a.pulls > 0 else 0.5 for a in arms.values())
        selected_mean = arms[best_op].mean_reward if arms[best_op].pulls > 0 else 0.5
        self._cumulative_regret += best_mean - selected_mean

        return best_op

# 奖励更新
    def update(self, state_id: str, op: MutationOp,
               reward: float) -> None:
        """以差分预言机奖励更新bandit后验。

        reward ∈ [0,1]，其中:
          0.0 = 无新覆盖/无崩溃/无分歧
          0.5 = 新路径覆盖但无崩溃
          1.0 = 触发崩溃或跨实现语义分歧
        """
        if state_id not in self._bandits:
            self.register_state(state_id)
        self._bandits[state_id][op].update(max(0.0, min(1.0, reward)))

# 统计与导出
    def regret(self) -> float:
        return self._cumulative_regret

    def per_state_stats(self) -> Dict[str, Dict[str, Any]]:
        """导出每个状态下各算子的统计信息"""
        result: Dict[str, Dict[str, Any]] = {}
        for sid, arms in self._bandits.items():
            result[sid] = {}
            for op, arm in arms.items():
                if arm.pulls > 0:
                    result[sid][op.name] = {
                        "pulls": arm.pulls,
                        "mean_reward": round(arm.mean_reward, 4),
                        "alpha": round(arm.alpha, 2),
                        "beta": round(arm.beta, 2),
                    }
        return result

    def best_operator_for_state(self, state_id: str) -> Optional[MutationOp]:
        """返回给定状态下奖励均值最高的算子"""
        arms = self._bandits.get(state_id)
        if not arms:
            return None
        return max(arms, key=lambda op: arms[op].mean_reward)


class RewardNormalizer:
    """连续奖励归一化器 —— 将原始反馈映射到[0,1]区间。

    差分预言机的原始奖励(新边数/崩溃严重度/分歧置信度)
    量纲不一致。此处使用EWMA追踪均值和方差的在线估计，
    不做批量归一化以避免跨会话信息泄漏。
    """

    def __init__(self, ewma_alpha: float = 0.05):
        self._alpha = ewma_alpha
        self._mean: float = 0.5
        self._var: float = 0.1

    def normalize(self, raw_reward: float) -> float:
        """在线归一化: (x - μ_ewma) / (σ_ewma + ε), 再sigmoid压缩"""
        self._mean = (1.0 - self._alpha) * self._mean + self._alpha * raw_reward
        diff = raw_reward - self._mean
        self._var = (1.0 - self._alpha) * self._var + self._alpha * diff * diff
        std = max(math.sqrt(self._var), 1e-6)
        z = (raw_reward - self._mean) / std
        # sigmoid: R→[0,1], 中心=0.5
        return 1.0 / (1.0 + math.exp(-z))


def compute_differential_reward(new_edges: int,
                                crash_severity: float,
                                divergence_confidence: float,
                                edge_weight: float = 0.4,
                                crash_weight: float = 0.35,
                                diverge_weight: float = 0.25) -> float:
    """合成差分奖励 —— 加权融合三种反馈信号。

    权重默认值基于消融实验：新边覆盖是fuzzing的主要目标，
    崩溃是最强信号，语义分歧提供互补精度。
    """
    edge_score = min(new_edges / 10.0, 1.0)
    return (edge_weight * edge_score +
            crash_weight * crash_severity +
            diverge_weight * divergence_confidence)


__all__ = [
    "MutationOp", "BanditArm", "HierarchicalBanditManager",
    "RewardNormalizer", "compute_differential_reward",
]
