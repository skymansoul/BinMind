# 操作符分组衰减耦合，避免同类操作符同时被压制
# 奖励归一化为分位排名，消除绝对值漂移
# 添加 operator_entropy() 诊断接口

# 自适应变异操作符选择器 - 基于覆盖反馈的操作符概率分布动态调整
#
# 设计动机:
#   power_schedule.py调度"哪个种子值得变异"，seed_selector.py决定"下一轮选哪个种子"。
#   两者均未回答"对这个种子，哪种变异操作符最可能产生新覆盖"-
#   这是正交于种子调度的第三维度。
#
# 核心方法:
#   每个操作符维护指数加权移动平均 (EWMA) 奖励，奖励=本次变异产生的新覆盖边数。
#   选择时按 softmax(EWMA / temperature) 采样。定期注入epsilon均匀探索防止局部最优。
#
# 操作符分组衰减:
#   同类操作符（如bitflip_1/bitflip_2/bitflip_4）共享衰减因子-
#   若bitflip组整体表现差，组内各操作符概率同步压低，避免组内轮换维持虚假多样性。
#
# 文献:
#   CovRL-Fuzz - coverage-guided RL for fuzzer mutator;
#       本项目取其覆盖反馈驱动变异选择思想但替换为轻量EWMA在线学习。
#   CTFuzz - multi-level mutation action
#       sequences learned via deep Q-learning; 本项目借鉴操作符分层思想
#       但采用非参数统计 (分位排名) 替代神经网络，降低计算开销。
import math
import time
from typing import Dict, List, Tuple, Optional, Set
from collections import defaultdict
from dataclasses import dataclass, field


# 操作符分组: 组名 - [操作符名...]
# 同组内操作符共享衰减耦合，防止"bitflip 1/1不好但bitflip 2/2尚可"
# 导致该组长期占据概率质量。
_OPERATOR_GROUPS: Dict[str, List[str]] = {
    "bitflip":   ["bitflip_1_1", "bitflip_2_2", "bitflip_4_4",
                  "bitflip_8_8", "bitflip_16_16", "bitflip_32_32"],
    "arithmetic": ["arith_8", "arith_16", "arith_32", "arith_64"],
    "interesting": ["interest_8", "interest_16", "interest_32"],
    "havoc":      ["havoc_static", "havoc_splice", "havoc_random"],
    "dictionary": ["dict_insert", "dict_replace", "dict_overwrite"],
    "crossover":  ["splice", "combine"],
}


@dataclass
class OperatorStats:
    """单个操作符的在线统计。"""
    name: str
    trials: int = 0
    ewma_reward: float = 0.0         # alpha=0.3的EWMA，初值0.5
    last_seen_round: int = -1
    group: str = ""

    def update(self, reward: float, alpha: float = 0.3) -> None:
        self.trials += 1
        # EWMA: r_t = alpha * r + (1-alpha) * r_{t-1}
        self.ewma_reward = alpha * reward + (1.0 - alpha) * self.ewma_reward


class AdaptiveMutationSelector:
    """自适应变异操作符选择器。

    工作流:
      select_operator() - 按当前概率分布选操作符
      record_outcome(operator_name, new_edges) - 更新该操作符的EWMA奖励
      decay_epoch() - 每N轮调用一次全局衰减

    选择策略:
      概率 ∝ softmax(ewma_reward / temperature)
      temperature随轮次从2.0退火至0.3，早期鼓励探索，后期聚焦已验证的高效操作符。
    """

    def __init__(self,
                 operator_names: Optional[List[str]] = None,
                 epsilon: float = 0.05):
        """
        epsilon: 均匀探索概率 [0, 1]。每轮有epsilon概率忽略EWMA直接从全部
                  操作符中均匀随机选。默认0.05，操作符集合<20时可适当降低。
        """
        self._epsilon = epsilon
        self._round = 0
        self._operators: Dict[str, OperatorStats] = {}
        self._recent_rewards: List[float] = []  # 最近128轮奖励值，用于分位计算

        # 默认操作符集: 覆盖AFL++标准变异阶段
        _default_ops = [
            "bitflip_1_1", "bitflip_2_2", "bitflip_4_4",
            "bitflip_8_8", "bitflip_16_16", "bitflip_32_32",
            "arith_8", "arith_16", "arith_32", "arith_64",
            "interest_8", "interest_16", "interest_32",
            "havoc_static", "havoc_splice", "havoc_random",
            "dict_insert", "dict_replace", "dict_overwrite",
            "splice", "combine",
        ]
        for op_name in (operator_names or _default_ops):
            grp = self._resolve_group(op_name)
            self._operators[op_name] = OperatorStats(
                name=op_name, ewma_reward=0.5, group=grp)

    @staticmethod
    def _resolve_group(op_name: str) -> str:
        for grp, members in _OPERATOR_GROUPS.items():
            if op_name in members:
                return grp
        return ""

    # 选择
    def select_operator(self) -> str:
        """返回选中的操作符名。冷启动时均匀随机。"""
        self._round += 1

        # epsilon探索
        import random as _rnd
        if _rnd.random() < self._epsilon:
            return _rnd.choice(list(self._operators.keys()))

        # softmax采样
        temp = max(0.3, 2.0 * math.exp(-self._round / 500.0))
        return self._softmax_sample(self._operators, temp)

    @staticmethod
    def _softmax_sample(stats: Dict[str, OperatorStats],
                        temperature: float) -> str:
        import random as _rnd
        names = list(stats.keys())
        # 数值稳定: 减去max
        rewards = [stats[n].ewma_reward for n in names]
        max_r = max(rewards) if rewards else 0.0
        exp_sum = 0.0
        probs = []
        for r in rewards:
            e = math.exp((r - max_r) / max(0.01, temperature))
            probs.append(e)
            exp_sum += e
        if exp_sum <= 0:
            return _rnd.choice(names)
        # 轮盘赌
        r = _rnd.random() * exp_sum
        acc = 0.0
        for name, p in zip(names, probs):
            acc += p
            if r <= acc:
                return name
        return names[-1]

    # 反馈
    def record_outcome(self, operator_name: str, new_edges: int) -> None:
        """记录操作符执行结果。new_edges: 本次变异产生的新覆盖边数。"""
        op = self._operators.get(operator_name)
        if op is None:
            return

        # 将原始new_edges转为分位排名奖励 [0, 1]
        reward = self._quantile_reward(new_edges)
        self._recent_rewards.append(float(new_edges))
        if len(self._recent_rewards) > 256:
            self._recent_rewards = self._recent_rewards[-128:]

        op.update(reward)
        op.last_seen_round = self._round

    def _quantile_reward(self, new_edges: int) -> float:
        """将绝对new_edges映射到相对分位 [0, 1]。

        分位排名消除了"前期普遍高产/后期普遍低产"的绝对值漂移问题。
        """
        if not self._recent_rewards or new_edges <= 0:
            return 0.0
        recent = self._recent_rewards[-128:]
        below = sum(1 for v in recent if v <= new_edges)
        return below / max(1, len(recent))

    # 衰减
    def decay_epoch(self, decay_factor: float = 0.95) -> None:
        """全局衰减: 每轮对所有操作符的EWMA乘以decay_factor。

        效果: 长期未被选中的操作符概率自然回升（回归均值），防止早期优势
        操作符永久垄断。

        分组耦合: 同组操作符衰减系数 = decay_factor的几何平均与当前组内
        最低EWMA的加权。
        """
        if not self._operators:
            return

        # 计算组级衰减因子
        group_penalty: Dict[str, float] = {}
        for grp, members in _OPERATOR_GROUPS.items():
            active = [self._operators[m].ewma_reward for m in members
                      if m in self._operators]
            if not active:
                continue
            grp_min = min(active)
            grp_mean = sum(active) / len(active)
            # 组内最小值远低于均值 - 组整体被压制
            ratio = grp_min / max(0.01, grp_mean)
            group_penalty[grp] = 0.7 + 0.3 * ratio  # 在 [0.7, 1.0] 区间

        for op in self._operators.values():
            gpf = group_penalty.get(op.group, 1.0)
            op.ewma_reward *= decay_factor * gpf
            # 截断在 [0.05, 10.0]，防止数值溢出
            op.ewma_reward = max(0.05, min(10.0, op.ewma_reward))

    # 诊断
    def operator_entropy(self) -> float:
        """操作符概率分布的香农熵 [0, log2(N)]。

        高熵 - 选择接近均匀（探索充分）；低熵 - 集中于少数操作符。
        """
        if not self._operators:
            return 0.0
        rewards = [op.ewma_reward for op in self._operators.values()]
        total = sum(rewards)
        if total <= 0:
            return 0.0
        entropy = 0.0
        for r in rewards:
            p = r / total
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def stats(self) -> Dict:
        """返回各操作符的当前统计。"""
        return {
            name: {
                "trials": op.trials,
                "ewma": round(op.ewma_reward, 4),
                "group": op.group,
                "last_round": op.last_seen_round,
            }
            for name, op in sorted(
                self._operators.items(),
                key=lambda x: -x[1].ewma_reward)
        }

    def reset(self) -> None:
        self._round = 0
        self._recent_rewards.clear()
        for op in self._operators.values():
            op.trials = 0
            op.ewma_reward = 0.5
            op.last_seen_round = -1
