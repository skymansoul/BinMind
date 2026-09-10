"""在线突变策略集成 (Ensemble) — 指数梯度(EG)自适应加权融合多种突变算子.

  Kivinen & Warmuth "Exponentiated Gradient Versus Gradient Descent
    for Linear Predictors" — EG 算法的 regret bound: R_T ≤ sqrt(2T ln N)
  PAMSSAFL   — 分层 MAB 用于突变位置+算子选择 (离散臂)
  CLUTCH  — 深度组合 bandit + 注意力机制用于 JS 引擎突变
  Cesa-Bianchi & Lugosi "Prediction, Learning, and Games"
    — 连续专家集成中的 Hedge 算法族, 本项目使用其 EG 变体

  PAMSSAFL 在两个离散层级上做 arm selection → 每次只使用一种算子。
  本模块维护所有策略的连续权重分布, 每次变异时从分布中采样算子,
  并根据覆盖反馈用 EG 更新权重。这等价于将"算子选择"从离散的组合优化
  转化为连续的在线凸优化, 收敛到 hindsight-optimal 的策略混合。

  附加: 追踪策略对 (A, B) 的协同效应 — 操作 A 产生的种子经 B 进一步变异后
  是否产生新覆盖。检测出 A→B 增益链后提升 B 在 A 后的采样概率。
"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

# 突变策略类型
# 每个策略是一个 (名称, 权重) 对, 权重随反馈动态调整
@dataclass
class MutationStrategy:
    name: str
    weight: float = 1.0           # EG 权重 (非归一化)
    prob: float = 0.0             # 归一化后的采样概率
    # 统计
    total_calls: int = 0
    total_rewards: float = 0.0     # 累积奖励
    recent_reward_ema: float = 0.0 # 近期奖励的指数移动平均
    # 协同效应追踪
    # 记录: 哪些前置策略产生了输入, 本策略在此基础上变异后获得奖励
    precursor_rewards: Dict[str, float] = field(default_factory=lambda: defaultdict(float))

# 策略定义
# 返回变异后的 bytes 和变更位置列表
MutatorFn = Callable[[bytes], Tuple[bytes, List[int]]]

def _build_default_strategies() -> Dict[str, MutatorFn]:
    """构建默认的 8 种突变策略。

    每种策略实现为闭包, 接收 bytes 返回 (mutated_bytes, [affected_offsets])。
    策略覆盖 AFL 的确定性阶段、havoc 阶段及本项目特有的结构感知/污点引导。
    """
    strategies: Dict[str, MutatorFn] = {}

    # 确定性变异族
    def bitflip_1_1(data: bytes) -> Tuple[bytes, List[int]]:
        if not data:
            return data, []
        raw = bytearray(data)
        pos = random.randint(0, len(raw) - 1)
        bit = random.randint(0, 7)
        raw[pos] ^= (1 << bit)
        return bytes(raw), [pos]

    def byteflip_1_1(data: bytes) -> Tuple[bytes, List[int]]:
        if not data:
            return data, []
        raw = bytearray(data)
        pos = random.randint(0, len(raw) - 1)
        raw[pos] ^= 0xFF
        return bytes(raw), [pos]

    def arith_gradient(data: bytes) -> Tuple[bytes, List[int]]:
        if not data:
            return data, []
        raw = bytearray(data)
        pos = random.randint(0, len(raw) - 1)
        delta = random.choice([-35, -1, 1, 35])
        raw[pos] = (raw[pos] + delta) & 0xFF
        return bytes(raw), [pos]

    def interesting_inject(data: bytes) -> Tuple[bytes, List[int]]:
        if not data:
            return data, []
        raw = bytearray(data)
        pos = random.randint(0, len(raw) - 1)
        interesting = [0x00, 0x01, 0x7F, 0x80, 0xFF, 0xFE]
        candidates = [v for v in interesting if v != raw[pos]]
        if candidates:
            raw[pos] = random.choice(candidates)
        return bytes(raw), [pos]

    # 随机变异族 (havoc)
    def havoc_random(data: bytes) -> Tuple[bytes, List[int]]:
        if not data:
            return data, []
        raw = bytearray(data)
        positions = []
        # 随机选 1~16 个位置, 每个位置做随机操作
        n_muts = random.randint(1, min(16, len(raw)))
        for _ in range(n_muts):
            pos = random.randint(0, len(raw) - 1)
            op = random.randint(0, 3)
            if op == 0:
                raw[pos] ^= (1 << random.randint(0, 7))
            elif op == 1:
                raw[pos] = random.randint(0, 255)
            elif op == 2:
                raw[pos] = (raw[pos] + random.randint(-35, 35)) & 0xFF
            else:
                raw[pos] = random.choice([0, 1, 0x7F, 0x80, 0xFF])
            positions.append(pos)
        return bytes(raw), positions

    # 结构操作族
    def splice_block(data: bytes) -> Tuple[bytes, List[int]]:
        if len(data) < 4:
            return data, []
        raw = bytearray(data)
        chunk_size = max(1, len(raw) // 4)
        src_start = random.randint(0, max(0, len(raw) - chunk_size))
        dst_start = random.randint(0, max(0, len(raw) - chunk_size))
        chunk = raw[src_start:src_start + chunk_size]
        raw[dst_start:dst_start + chunk_size] = chunk
        return bytes(raw), list(range(dst_start, dst_start + chunk_size))

    def delete_chunk(data: bytes) -> Tuple[bytes, List[int]]:
        if len(data) < 2:
            return data, []
        raw = bytearray(data)
        chunk_size = random.randint(1, max(1, len(raw) // 8))
        start = random.randint(0, max(0, len(raw) - chunk_size))
        del raw[start:start + chunk_size]
        return bytes(raw), [start]

    def insert_cloned(data: bytes) -> Tuple[bytes, List[int]]:
        if len(data) < 2:
            return data, []
        raw = bytearray(data)
        chunk_size = random.randint(1, max(1, len(raw) // 8))
        src = random.randint(0, max(0, len(raw) - chunk_size))
        dst = random.randint(0, len(raw))
        chunk = raw[src:src + chunk_size]
        raw[dst:dst] = chunk
        return bytes(raw), list(range(dst, dst + chunk_size))

    strategies["bitflip"] = bitflip_1_1
    strategies["byteflip"] = byteflip_1_1
    strategies["arith"] = arith_gradient
    strategies["interesting"] = interesting_inject
    strategies["havoc"] = havoc_random
    strategies["splice"] = splice_block
    strategies["delete"] = delete_chunk
    strategies["insert"] = insert_cloned

    return strategies

class MutationEnsemble:
    """在线突变策略集成 — 指数梯度 (EG) 自适应加权。

    维护 N 个突变策略的连续权重分布 w₁,...,w_N。
    每轮采样一个策略 i ~ softmax(η·w), 对其变异结果评估,
    根据 reward 更新 wᵢ ← wᵢ·exp(η·(reward - baseline)), 其中 baseline
    是近期奖励的 EMA, 用于降低方差。

    EG 算法在 regret bound 上优于常规 SGD 当梯度稀疏时
    (大部分策略大多数时候 reward=0 → 梯度为零), 因为 EG 的
    乘法更新天然处理稀疏性。

    用法:
      ensemble = MutationEnsemble()
      strategy_name = ensemble.sample()
      mutated, positions = ensemble.mutate(seed_data, strategy_name)
      # ... 执行变异后的种子 ...
      ensemble.update(strategy_name, reward=1.0 if new_coverage else 0.0)
    """

    def __init__(self, learning_rate: float = 0.1,
                 ema_decay: float = 0.95,
                 min_weight: float = 0.01):
        """
        learning_rate: EG 学习率 η, 越大自适应越快但越不稳定
        ema_decay: 奖励 EMA 的衰减系数
        min_weight: 策略的最小权重 (防止零奖励退化导致某策略永久不被选中)
        """
        self.lr = learning_rate
        self.ema_decay = ema_decay
        self.min_weight = min_weight

        self._strategies: Dict[str, MutationStrategy] = {}
        self._mutators: Dict[str, MutatorFn] = _build_default_strategies()
        for name in self._mutators:
            self._strategies[name] = MutationStrategy(name=name)

        # 全局奖励 EMA (baseline)
        self._global_reward_ema: float = 0.0
        self._total_calls: int = 0
        self._total_rewards: float = 0.0

        # 上一轮使用的策略名称 (用于协同追踪)
        self._last_strategy: Optional[str] = None

        # 协同效应矩阵: (precursor, current) → 增益次数
        self._synergy_counts: Dict[Tuple[str, str], int] = defaultdict(int)

        self._recalc_probs()

    # //// 采样策略 ////
    def sample(self) -> str:
        """从当前权重分布中采样一个策略名称。

        采样概率 = softmax(weights), 等价于从 N 面 loaded dice 中投掷。
        若所有权重退化到 min_weight, 退化为均匀采样。
        """
        probs = [s.prob for s in self._strategies.values()]
        names = list(self._strategies.keys())
        r = random.random()
        cum = 0.0
        for i, p in enumerate(probs):
            cum += p
            if r <= cum:
                self._last_strategy = names[i]
                return names[i]
        self._last_strategy = names[-1]
        return names[-1]

    # //// 执行变异 ////
    def mutate(self, data: bytes, strategy_name: Optional[str] = None
               ) -> Tuple[bytes, List[int], str]:
        """使用指定策略 (或采样) 对数据进行变异。

        返回 (mutated_data, affected_positions, strategy_name)。
        """
        if strategy_name is None:
            strategy_name = self.sample()

        mutator = self._mutators.get(strategy_name)
        if mutator is None:
            # 回退: 任意选一个存在的策略
            strategy_name = random.choice(list(self._mutators.keys()))
            mutator = self._mutators[strategy_name]

        result, positions = mutator(data)
        self._strategies[strategy_name].total_calls += 1
        self._total_calls += 1

        return result, positions, strategy_name

    # //// 反馈更新 ////
    def update(self, strategy_name: str, reward: float,
               precursor: Optional[str] = None) -> None:
        """根据变异结果的奖励更新策略权重。

        reward: 0.0 (无新覆盖), 0.5 (微小改善), 1.0 (新覆盖/新路径), 1.5 (新崩溃)
        precursor: 若此变异是在其他策略的输出上叠加的, 记录协同效应
        """
        strat = self._strategies.get(strategy_name)
        if strat is None:
            return

        reward = max(0.0, min(2.0, reward))
        strat.total_rewards += reward
        self._total_rewards += reward

        # 更新该策略的近期奖励 EMA
        strat.recent_reward_ema = (
            self.ema_decay * strat.recent_reward_ema
            + (1 - self.ema_decay) * reward
        )

        # 更新全局 baseline EMA
        self._global_reward_ema = (
            self.ema_decay * self._global_reward_ema
            + (1 - self.ema_decay) * reward
        )

        # EG 权重更新: w ← w·exp(η·(reward - baseline))
        excess = reward - self._global_reward_ema
        strat.weight *= math.exp(self.lr * excess)
        strat.weight = max(self.min_weight, strat.weight)

        # 权重上限防止数值溢出
        max_w = 100.0
        if strat.weight > max_w:
            # 所有权重等比例缩放
            scale = max_w / strat.weight
            for s in self._strategies.values():
                s.weight = max(self.min_weight, s.weight * scale)

        # 协同效应追踪
        prec = precursor or self._last_strategy
        if prec and prec != strategy_name and reward > 0:
            self._synergy_counts[(prec, strategy_name)] += 1

        self._recalc_probs()

    # //// 概率重算 ////
    def _recalc_probs(self) -> None:
        """将权重映射到采样概率 (softmax)。"""
        names = list(self._strategies.keys())
        weights = [self._strategies[n].weight for n in names]
        max_w = max(weights) if weights else 1.0
        # 减去 max 做数值稳定 (softmax 平移不变性)
        exp_sum = 0.0
        exps = []
        for w in weights:
            e = math.exp(w - max_w)
            exps.append(e)
            exp_sum += e
        for i, name in enumerate(names):
            self._strategies[name].prob = exps[i] / max(1e-12, exp_sum)

    # //// 协同效应查询 ////
    def get_synergy_bonus(self, strategy_name: str,
                          precursor: Optional[str] = None) -> float:
        """查询 precursor → strategy_name 的协同效应强度。

        返回值 ∈ [0, 1], 表示该前置-后置组合的历史成功率。
        用于在确定变异序列时调整策略采样概率。
        """
        if precursor is None:
            return 0.0
        key = (precursor, strategy_name)
        synergy_hits = self._synergy_counts.get(key, 0)
        if synergy_hits == 0:
            return 0.0
        total = self._strategies[strategy_name].total_calls
        return min(1.0, synergy_hits / max(1, total))

    def sample_with_synergy(self, precursor: Optional[str] = None) -> str:
        """考虑协同效应的策略采样: 在 EG 概率基础上, 对与 precursor 有
        正向协同的策略给予额外加成 (×1.3), 对无协同关系的策略不做惩罚。
        """
        synergy_bonuses = {}
        for name in self._strategies:
            synergy_bonuses[name] = 1.0 + 0.3 * self.get_synergy_bonus(name, precursor)

        names = list(self._strategies.keys())
        adjusted = [
            self._strategies[n].prob * synergy_bonuses.get(n, 1.0)
            for n in names
        ]
        total = sum(adjusted)
        r = random.random()
        cum = 0.0
        for i, n in enumerate(names):
            cum += adjusted[i] / max(1e-12, total)
            if r <= cum:
                self._last_strategy = n
                return n
        return names[-1]

    # //// 统计 ////
    def stats(self) -> dict:
        strat_stats = {}
        for name, strat in self._strategies.items():
            strat_stats[name] = {
                "weight": round(strat.weight, 4),
                "prob": round(strat.prob, 4),
                "calls": strat.total_calls,
                "total_reward": round(strat.total_rewards, 2),
                "avg_reward": (
                    strat.total_rewards / max(1, strat.total_calls)
                ),
                "recent_ema": round(strat.recent_reward_ema, 4),
            }

        top_synergies = sorted(
            [(f"{a}→{b}", cnt) for (a, b), cnt in self._synergy_counts.items()],
            key=lambda x: x[1], reverse=True
        )[:10]

        return {
            "strategy_count": len(self._strategies),
            "total_calls": self._total_calls,
            "global_avg_reward": self._total_rewards / max(1, self._total_calls),
            "global_reward_ema": round(self._global_reward_ema, 4),
            "learning_rate": self.lr,
            "strategies": strat_stats,
            "top_synergies": top_synergies,
        }

    # //// 导出/导入权重 (跨会话迁移) ////
    def export_weights(self) -> Dict[str, float]:
        return {n: s.weight for n, s in self._strategies.items()}

    def import_weights(self, weights: Dict[str, float]) -> None:
        for name, w in weights.items():
            if name in self._strategies:
                self._strategies[name].weight = w
        self._recalc_probs()

    def reset(self) -> None:
        for s in self._strategies.values():
            s.weight = 1.0
            s.total_calls = 0
            s.total_rewards = 0.0
            s.recent_reward_ema = 0.0
            s.precursor_rewards.clear()
        self._global_reward_ema = 0.0
        self._total_calls = 0
        self._total_rewards = 0.0
        self._synergy_counts.clear()
        self._last_strategy = None
        self._recalc_probs()
