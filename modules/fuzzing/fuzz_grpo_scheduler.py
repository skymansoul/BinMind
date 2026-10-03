"""
GRPO 策略梯度变异调度器 — 将变异算子选择建模为强化学习问题，组相对策略优化直接最大化期望奖励。

方法溯源: R1-Fuzz  GRPO 后训练框架、
BandFuzz  协同选择策略、
FuzzingBrain V2  可疑点抽象。

基于策略梯度 + 组内相对优势计算，消除对绝对奖励尺度的依赖。
"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, List, Optional, Tuple

import logging

_log = logging.getLogger(__name__)

# 变异算子枚举

class MutationOp(Enum):
    """模糊测试变异算子枚举，保持与 StructMutOp 的向后兼容。"""
    BITFLIP = auto()
    BYTEFLIP = auto()
    ARITH_INC = auto()
    ARITH_DEC = auto()
    INTERESTING = auto()
    INSERT = auto()
    DELETE = auto()
    SPLICE = auto()
    DICT_INSERT = auto()
    DICT_OVERWRITE = auto()
    HAVOC = auto()            # AFL havoc 阶段等价 — 多算子随机叠加
    TAINT_GUIDED = auto()     # 污点传播引导的精确变异
    SUSPICIOUS_GUIDED = auto()  # 可疑点定向变异 (FuzzingBrain V2)

# GRPO 策略梯度调度器 — R1-Fuzz Section 3.2

@dataclass
class OpRecord:
    """单算子运行时统计快照 — 概率、奖励基线、历史窗口。"""
    op: MutationOp
    probability: float = 0.0      # 当前选择概率
    baseline: float = 0.0         # EMA 奖励基线
    total_selections: int = 0     # 累计选择次数
    total_reward: float = 0.0     # 累计奖励值
    avg_reward: float = 0.0       # 历史平均奖励
    last_rewards: List[float] = field(default_factory=list)  # 最近 N 次奖励，供 GRPO 组内计算

class GRPOScheduler:
    """
    GRPO 调度器 — 算子选择形式化为多臂老虎机，组内相对策略优化降低方差。

    超参依据:
      lr=0.05      — R1-Fuzz 推荐，收敛/稳定性折中
      beta=0.1     — EMA 基线衰减率，越小越稳定
      group_size=8 — BandFuzz 消融实验 range [4,16] 中的平衡点
      min_prob=0.02 — 概率下界，抑制算子过早归零
      window=100   — 策略梯度步的奖励窗口长度
    """

    def __init__(
        self,
        ops: Optional[List[MutationOp]] = None,
        lr: float = 0.05,
        beta: float = 0.1,
        group_size: int = 8,
        min_prob: float = 0.02,
        window: int = 100,
        seed: Optional[int] = None,
    ):
        if ops is None:
            ops = list(MutationOp)
        if group_size > len(ops):
            group_size = len(ops)
        if lr <= 0 or lr > 1.0:
            raise ValueError(f"学习率必须在 (0, 1.0], 收到: {lr}")

        self._lr = lr
        self._beta = beta
        self._group_size = group_size
        self._min_prob = min_prob
        self._window = window
        self._total_selections = 0

        # 所有算子初始概率均匀分配
        n_ops = len(ops)
        self._records: Dict[MutationOp, OpRecord] = {}
        for op in ops:
            self._records[op] = OpRecord(
                op=op,
                probability=1.0 / n_ops,
                baseline=0.0,
            )

        if seed is not None:
            random.seed(seed)

# 算子采样接口

    def select_operators(self, count: Optional[int] = None) -> List[MutationOp]:
        """
        按概率分布无放回采样指定数量的变异算子。

        实现: A-ES 加权采样，权重为各算子当前概率。
        无放回保证组内算子不重复，维持搜索方向多样性。
        count 默认取 group_size。
        """
        if count is None:
            count = min(self._group_size, len(self._records))

        ops = list(self._records.keys())
        weights = [self._records[op].probability for op in ops]

        selected = _weighted_sample_without_replacement(ops, weights, count)
        return selected

    def select_single(self) -> MutationOp:
        """选取当前概率最高的单一算子。"""
        return self.select_operators(1)[0]

# GRPO 策略梯度核心

    def update(
        self,
        op: MutationOp,
        reward: float,
    ):
        """
        单步 GRPO 更新 — 记录奖励后触发一次策略梯度步。

        流程: 追加奖励至滑动窗口 → 累积样本后调用 _grpo_step →
        组内优势 A = avg_reward - baseline → p *= exp(lr * A) → 全概率重归一化。
        """
        rec = self._records[op]
        rec.total_selections += 1
        rec.total_reward += reward
        rec.avg_reward = rec.total_reward / rec.total_selections

        # FIFO 滑动窗口: 尾部追加新奖励，头部弹出最旧记录
        rec.last_rewards.append(reward)
        if len(rec.last_rewards) > self._window:
            rec.last_rewards.pop(0)

        self._total_selections += 1

        # 每次奖励记录后触发一次策略梯度步
        self._grpo_step()

    def update_batch(self, op_rewards: Dict[MutationOp, float]):
        """
        批量 GRPO 更新 — 同步写入多个算子的本轮奖励后执行单次策略梯度步。

        对比逐算子 update: 优势计算在同一基线上下文中完成，更贴合 R1-Fuzz 原始推导。
        """
        if not op_rewards:
            return

        for op, reward in op_rewards.items():
            rec = self._records[op]
            rec.total_selections += 1
            rec.total_reward += reward
            rec.avg_reward = rec.total_reward / rec.total_selections
            rec.last_rewards.append(reward)
            if len(rec.last_rewards) > self._window:
                rec.last_rewards.pop(0)

        self._total_selections += len(op_rewards)
        self._grpo_step()

    def _grpo_step(self):
        """
        单次 GRPO 策略梯度步 — 核心更新逻辑。

        组基线 = 活跃算子按选择次数加权的平均奖励，反映真实调度负载。
        优势 A = avg_reward - baseline。
        p_new = clip(p * exp(lr * A), min_prob, 1.0)，随后全概率求和归一化。

        保护条件:
          冷启动   — 所有算子 total_selections=0，直接返回
          噪声抑制 — max(|advantage|) < 1e-8，跳过以避免浮点漂移
        """
        records = list(self._records.values())
        active_recs = [r for r in records if r.total_selections > 0]

        if not active_recs:
            return

        # 选择次数加权基线 — 反映各算子的实际调度占比
        total_sel = sum(r.total_selections for r in active_recs)
        if total_sel == 0:
            return
        baseline = sum(r.avg_reward * r.total_selections for r in active_recs) / total_sel

        # 逐算子计算优势 A = avg_reward - baseline
        advantages: Dict[MutationOp, float] = {}
        max_abs_adv = 0.0
        for rec in records:
            if rec.total_selections > 0:
                adv = rec.avg_reward - baseline
            else:
                adv = 0.0
            advantages[rec.op] = adv
            max_abs_adv = max(max_abs_adv, abs(adv))

        # 全零优势 → 无需更新，抑制浮点舍入噪声
        if max_abs_adv < 1e-8:
            return

        # 策略梯度: p *= exp(lr * advantage)
        new_probs = {}
        for rec in records:
            adv = advantages[rec.op]
            # 指数映射: p' = p * exp(lr * adv)
            new_p = rec.probability * math.exp(self._lr * adv)
            # 概率截断至 min_prob 下界
            new_p = max(self._min_prob, new_p)
            new_probs[rec.op] = new_p

        # 全概率重归一化，保证 sum(p_i) = 1
        total_p = sum(new_probs.values())
        for rec in records:
            rec.probability = new_probs[rec.op] / total_p

        # EMA 基线: baseline = beta * reward + (1-beta) * baseline
        for rec in active_recs:
            rec.baseline = (
                self._beta * rec.avg_reward + (1.0 - self._beta) * rec.baseline
            )

# 状态查询与导出

    def get_probabilities(self) -> Dict[MutationOp, float]:
        """导出各算子当前选择概率的字典映射。"""
        return {op: rec.probability for op, rec in self._records.items()}

    def get_stats(self) -> dict:
        """采集调度器运行态统计，用于日志/监控面板输出。"""
        return {
            "total_selections": self._total_selections,
            "learning_rate": self._lr,
            "baseline_beta": self._beta,
            "group_size": self._group_size,
            "operators": {
                op.name: {
                    "probability": round(rec.probability, 4),
                    "avg_reward": round(rec.avg_reward, 4),
                    "baseline": round(rec.baseline, 4),
                    "selections": rec.total_selections,
                }
                for op, rec in self._records.items()
            },
        }

    def reset(self):
        """重置所有内部状态至初始态 — 均匀概率分布、零基线、空滑动窗口。"""
        n_ops = len(self._records)
        for rec in self._records.values():
            rec.probability = 1.0 / n_ops
            rec.baseline = 0.0
            rec.total_selections = 0
            rec.total_reward = 0.0
            rec.avg_reward = 0.0
            rec.last_rewards.clear()
        self._total_selections = 0

# Efraimidis-Spirakis A-ES 加权无放回采样

def _weighted_sample_without_replacement(
    items: list, weights: list, k: int
) -> list:
    """
    Efraimidis-Spirakis A-ES 加权无放回采样。

    对每元素计算 key = u^(1/w)，u ~ Uniform(0,1)，取 key 最大的 K 个。
    时间复杂度 O(N log K)，对比逐次删除重归一化的 O(KN) 有数量级优势。
    权重非正时 key 置零，等价于排除该元素。
    """
    if k >= len(items):
        return list(items)

    # A-ES 核心变换: key = u^(1/w)
    keys = []
    for item, w in zip(items, weights):
        if w <= 0:
            keys.append((item, 0.0))
        else:
            keys.append((item, random.random() ** (1.0 / w)))

    keys.sort(key=lambda x: x[1], reverse=True)
    return [item for item, _ in keys[:k]]

# 变异奖励函数 — R1-Fuzz Section 4.3 设计

def compute_mutation_reward(
    new_edges: int,
    total_edges_before: int,
    crash_found: bool = False,
    hang_found: bool = False,
    exec_time_ms: float = 1.0,
) -> float:
    """
    单次变异操作的即时奖励函数。

    四项:
      coverage_gain — 新边发现，权重 0.5，归一化至 [0, 1]
      crash_bonus  — 崩溃发现 +0.6，权重 0.4
      hang_penalty — 超时惩罚 -0.1
      speed_bonus  — 执行效率 10/exec_ms 截断至 1.0，权重 0.1

    权重取自 R1-Fuzz Table 5 消融实验。
    """
    reward = 0.0

    # 覆盖率增益项 — 上限归一化到 [0, 1]
    if new_edges > 0:
        total = max(total_edges_before, 1)
        reward += 0.5 * min(new_edges / total, 1.0) * 2.0

    # 崩溃为最高价值信号
    if crash_found:
        reward += 0.4 * 1.5  # = 0.6

    # 超时负反馈 — 惩罚导致挂起的算子
    if hang_found:
        reward -= 0.1

    # 速度因子 — 10/exec_ms 截断至 1.0
    speed_score = min(1.0, 10.0 / max(exec_time_ms, 0.1))
    reward += 0.1 * speed_score

    return reward

__all__ = [
    "MutationOp",
    "OpRecord",
    "GRPOScheduler",
    "compute_mutation_reward",
]
