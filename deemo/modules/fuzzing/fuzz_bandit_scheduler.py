"""多臂老虎机(MAB)种子调度器 --- LinUCB / UCB / Exp3 / Thompson Sampling 四种策略。

  LinFuzz  -- 上下文MAB调度, LinUCB 建模种子价值
  pAFL       -- UCB 自适应能量分配, exploration/exploitation 平衡
  RumFuzz  -- 改进 Exp3 + 种子-崩溃距离度量
  TMS-Fuzz       -- Thompson Sampling 种子组选择

与 src/scheduler.py 中 AFLfast 调度器互补: AFLfast 基于马尔可夫链,
此处提供基于统计学习理论的替代方案, 均可通过 strategy 参数切换。
"""

import math
import random
import time
import logging
from collections import defaultdict
from typing import Dict, List, Optional, Tuple, Sequence

logger = logging.getLogger(__name__)

# 上下文特征提取
# LinUCB 要求每个臂(种子)关联一个特征向量, 此处选取 6 维特征:
#   [exec_time_norm, edge_count_norm, generation_inv, file_size_norm,
#    is_recent_find, rarity_score]
#
# 各维度归一化到 [0, 1], 未提供值时填 0.5 (中性先验)

def _extract_context(seed_meta: dict, data_len: int = 0) -> List[float]:
    """从种子元数据提取归一化上下文特征向量。

    LinFuzz 原文使用 8 维特征 (包含路径频率和基本块熵), 此处精简为 6 维,
    因为路径频率信息需额外插桩数据, 在生产环境中常不可用。
    """
    exec_t = seed_meta.get("exec_time_ms", 10.0)
    edge_cnt = seed_meta.get("edge_count", 0)
    gen = seed_meta.get("generation", 0)
    is_recent = 1.0 if seed_meta.get("is_recent_find") else 0.0
    rarity = seed_meta.get("rarity_score", 0.5)

    feat = [
        min(1.0, exec_t / 100.0),              # 执行时间归一化 (100ms -> 1.0)
        min(1.0, math.log2(1 + edge_cnt) / 10.0),  # 覆盖边数 (log2)
        1.0 / (1.0 + gen),                     # 代数倒数衰减
        min(1.0, data_len / 4096.0),           # 文件大小
        is_recent,                             # 最近发现标志
        max(0.0, min(1.0, rarity)),            # 稀有度
    ]
    return feat

# LinUCB 调度器

class LinUCBScheduler:
    """LinUCB 在线学习调度器。

    对每个种子维护 ridge 回归参数 (A_a, b_a), 每次选择时:
      p = θ_a^T x + α * sqrt(x^T A_a^{-1} x)
    其中 θ_a = A_a^{-1} b_a 为岭回归系数, α 控制探索强度。

    选择使 p 最大的种子, 并在观测到奖励后更新参数。
    奖励定义为: 产生新覆盖 → +1, 否则 → 0。
    """

    def __init__(self, context_dim: int = 6, alpha: float = 1.0):
        self.d = context_dim
        self.alpha = alpha      # UCB探索系数, 越大越偏向探索
        # 每个种子ID对应的参数矩阵
        self._A: Dict[str, List[List[float]]] = {}   # d×d 单位矩阵
        self._b: Dict[str, List[float]] = {}          # d×1 向量
        self._A_inv_cache: Dict[str, List[List[float]]] = {}

    def _init_arm(self, seed_id: str) -> None:
        if seed_id in self._A:
            return
        # d×d 单位矩阵 + d×1 零向量
        id_mat = [[1.0 if i == j else 0.0 for j in range(self.d)] for i in range(self.d)]
        self._A[seed_id] = id_mat
        self._b[seed_id] = [0.0] * self.d
        self._A_inv_cache[seed_id] = [list(r) for r in id_mat]

    def _mat_vec_mul(self, mat: List[List[float]], vec: List[float]) -> List[float]:
        return [sum(mat[i][j] * vec[j] for j in range(self.d)) for i in range(self.d)]

    def _inv_update(self, seed_id: str, x: List[float]) -> None:
        """Sherman-Morrison 秩-1更新: (A + x x^T)^{-1} 的增量计算。

        相比每步重新求逆, O(d²) → O(d²) but 常数因子小得多。
        """
        A_inv = self._A_inv_cache[seed_id]
        # v = A^{-1} x
        v = self._mat_vec_mul(A_inv, x)
        # dot = x^T v
        dot = sum(x[i] * v[i] for i in range(self.d))
        if dot < -0.999:
            return  # 数值不稳定, 跳过本次更新
        denom = 1.0 + dot
        # A^{-1} ← A^{-1} - (v v^T) / (1 + x^T v)
        for i in range(self.d):
            for j in range(self.d):
                A_inv[i][j] -= v[i] * v[j] / denom

    def select(self, seeds: Sequence, seed_ids: List[str],
               contexts: List[List[float]]) -> Tuple[int, float]:
        if not seeds:
            return -1, float('-inf')
        best_idx, best_score = 0, float('-inf')
        for i, sid in enumerate(seed_ids):
            self._init_arm(sid)
            ctx = contexts[i] if i < len(contexts) else [0.5] * self.d
            A_inv = self._A_inv_cache[sid]
            theta = self._mat_vec_mul(A_inv, self._b[sid])
            exploit = sum(theta[j] * ctx[j] for j in range(self.d))
            # exploration bonus: α·√(xᵗA⁻¹x)
            xTAx = max(0.0, sum(ctx[j] * self._mat_vec_mul(A_inv, ctx)[j] for j in range(self.d)))
            explore = self.alpha * math.sqrt(xTAx)
            p = exploit + explore
            if p > best_score:
                best_score = p
                best_idx = i
        return best_idx, best_score

    def update(self, seed_id: str, context: List[float], reward: float) -> None:
        """以观测奖励更新种子参数。

        reward ∈ {0, 1}: 1 表示该种子产生了新覆盖或崩溃。
        """
        self._init_arm(seed_id)
        x = context

        # A += x x^T
        A = self._A[seed_id]
        for i in range(self.d):
            for j in range(self.d):
                A[i][j] += x[i] * x[j]

        # b += reward * x
        b = self._b[seed_id]
        for j in range(self.d):
            b[j] += reward * x[j]

        self._inv_update(seed_id, x)

# UCB1 调度器

class UCBScheduler:
    """UCB1 种子调度 [pAFL 2024]。

    对每个种子记录 n_i (被选中次数) 和 r_i (累计奖励),
    选择: seed = argmax( r_i/n_i + c * sqrt(ln(N) / n_i) )
    其中 N 为总选择次数, c 控制探索程度。

    相比 LinUCB, 无需特征向量, 计算开销更低, 但忽略种子间差异。
    """

    def __init__(self, explore_coeff: float = 2.0):
        self.c = explore_coeff
        self._counts: Dict[str, int] = defaultdict(int)    # n_i
        self._rewards: Dict[str, float] = defaultdict(float)  # r_i
        self._total_picks: int = 0

    def select(self, seeds: Sequence, seed_ids: List[str]) -> Tuple[int, float]:
        if not seeds:
            return -1, float('-inf')

        best_idx, best_val = 0, float('-inf')
        N = max(1, self._total_picks)

        for i, sid in enumerate(seed_ids):
            n_i = self._counts.get(sid, 0)
            # 冷启动: 未选择过的种子默认具有无限大上界(强制探索)
            if n_i == 0:
                return i, float('inf')

            avg_r = self._rewards[sid] / n_i
            explore_bonus = self.c * math.sqrt(math.log(N) / n_i)
            ucb_val = avg_r + explore_bonus

            if ucb_val > best_val:
                best_val = ucb_val
                best_idx = i

        return best_idx, best_val

    def update(self, seed_id: str, reward: float) -> None:
        self._counts[seed_id] += 1
        self._rewards[seed_id] += reward
        self._total_picks += 1

# Exp3 调度器

class Exp3Scheduler:
    """对抗性老虎机 Exp3 调度 [RumFuzz 2024]。

    适用于非平稳奖励环境 (如 fuzzing 中随时间变化的新覆盖出现率)。
    维护每个种子的概率权重, 每轮按指数加权随机选择。
    """

    def __init__(self, gamma: float = 0.07, learning_rate: float = 0.01):
        """
        gamma:  均匀探索概率 (越大越偏向随机)
        learning_rate: 权重更新步长
        """
        self.gamma = gamma
        self.lr = learning_rate
        self._weights: Dict[str, float] = defaultdict(lambda: 1.0)
        self._prob_cache: Dict[str, float] = {}
        self._total_weight: float = 0.0

    def _recalc_probs(self, seed_ids: List[str]) -> List[float]:
        K = len(seed_ids)
        if K == 0:
            return []
        total = sum(self._weights[sid] for sid in seed_ids) or K
        probs = []
        for sid in seed_ids:
            p = (1.0 - self.gamma) * (self._weights[sid] / total) + self.gamma / K
            probs.append(p)
            self._prob_cache[sid] = p
        return probs

    def select(self, seeds: Sequence, seed_ids: List[str]) -> Tuple[int, float]:
        if not seeds:
            return -1, float('-inf')
        probs = self._recalc_probs(seed_ids)
        r = random.random()
        cum = 0.0
        for i, p in enumerate(probs):
            cum += p
            if r <= cum:
                return i, p
        return len(seeds) - 1, probs[-1]

    def update(self, seed_id: str, reward: float) -> None:
        """奖励∈[0,1], 按重要性采样调整权重。

        RumFuzz 原文还结合了 crash_distance_metric, 此处简化为纯 Exp3。
        """
        prob = self._prob_cache.get(seed_id, 0.01)
        if prob <= 0:
            prob = 0.01

        # 重要性加权: reward_hat = reward / prob
        r_hat = reward / prob
        old_w = self._weights[seed_id]
        self._weights[seed_id] = old_w * math.exp(self.lr * r_hat / max(1, prob))

# Thompson Sampling 调度器

class ThompsonScheduler:
    """Beta-Bernoulli Thompson Sampling 种子调度 [TMS-Fuzz 2026]。

    对每个种子维护 Beta(α, β) 先验: 成功=产生新覆盖, 失败=无新覆盖。
    每次从后验中采样, 选采样值最大的种子。
    天然平衡 exploration/exploitation, 无需额外超参数。
    """

    def __init__(self):
        self._alpha: Dict[str, float] = defaultdict(lambda: 1.0)  # 成功计数+1
        self._beta: Dict[str, float] = defaultdict(lambda: 1.0)   # 失败计数+1

    def select(self, seeds: Sequence, seed_ids: List[str]) -> Tuple[int, float]:
        if not seeds:
            return -1, float('-inf')

        best_idx, best_sample = 0, -1.0
        for i, sid in enumerate(seed_ids):
            a = self._alpha[sid]
            b = self._beta[sid]
            sample = random.betavariate(a, b)
            if sample > best_sample:
                best_sample = sample
                best_idx = i

        return best_idx, best_sample

    def update(self, seed_id: str, reward: float) -> None:
        """reward ≥0.5 → beta计数为成功, <0.5 → 失败"""
        if reward >= 0.5:
            self._alpha[seed_id] += 1.0
        else:
            self._beta[seed_id] += 1.0

# 统一调度门面
# 将四种 MAB 调度器封装为与 Scheduler.pick_seed() 兼容的接口

_VALID_BANDIT_STRATEGIES = frozenset({"linucb", "ucb", "exp3", "thompson"})

class BanditScheduler:
    """MAB 种子调度器统一入口。

    内部委托给四种策略实现之一。对外暴露 select()/update() 接口,
    与 Scheduler.pick_seed() 语义兼容。

    典型用法:
        bs = BanditScheduler("linucb", alpha=0.8)
        idx, score = bs.select(queue, ids, contexts)
        bs.update(chosen_id, ctx, reward=1.0)
    """

    def __init__(self, strategy: str = "linucb", **kwargs):
        if strategy not in _VALID_BANDIT_STRATEGIES:
            raise ValueError(
                f"Unknown bandit strategy: {strategy}, valid: {_VALID_BANDIT_STRATEGIES}"
            )
        self.strategy = strategy
        self._impl = self._build_impl(strategy, kwargs)
        self._pick_counts: Dict[str, int] = defaultdict(int)
        self._reward_history: List[float] = []

    def _build_impl(self, strategy: str, kw: dict):
        if strategy == "linucb":
            return LinUCBScheduler(
                context_dim=kw.get("context_dim", 6),
                alpha=kw.get("alpha", 1.0),
            )
        elif strategy == "ucb":
            return UCBScheduler(explore_coeff=kw.get("explore_coeff", 2.0))
        elif strategy == "exp3":
            return Exp3Scheduler(
                gamma=kw.get("gamma", 0.07),
                learning_rate=kw.get("lr", 0.01),
            )
        elif strategy == "thompson":
            return ThompsonScheduler()
        else:
            raise ValueError(f"Unhandled strategy: {strategy}")

    def select_seed(self, seed_queue: list,
                    contexts: Optional[List[List[float]]] = None) -> Optional[Tuple[int, float]]:
        """从种子队列中选择一个种子。

        contexts: 每个种子的特征向量(仅 LinUCB 使用, 其他策略忽略)。
        返回 (队列索引, 得分) 或 None。
        """
        if not seed_queue:
            return None
        ids = [getattr(s, 'id', str(i)) for i, s in enumerate(seed_queue)]
        if contexts is None:
            # 为每个种子生成默认上下文
            contexts = [
                _extract_context(
                    getattr(s, 'metadata', {}),
                    len(getattr(s, 'data', b''))
                )
                for s in seed_queue
            ]

        idx, score = self._impl.select(seed_queue, ids, contexts)
        if idx < 0 or idx >= len(seed_queue):
            return None

        sid = ids[idx]
        self._pick_counts[sid] += 1
        return idx, score

    def notify_reward(self, seed_id: str, context: Optional[List[float]],
                      is_new_find: bool, crash_found: bool = False) -> None:
        """通知调度器一次选择的结果。

        is_new_find → reward=1.0; crash → reward=1.5; 否则 reward=0.0。
        crash 的超额奖励借鉴 RumFuzz 的 crash_distance 思想。
        """
        reward = 1.5 if crash_found else (1.0 if is_new_find else 0.0)
        self._reward_history.append(reward)

        if hasattr(self._impl, 'update'):
            # LinUCB 需要 context
            if self.strategy == "linucb" and context is not None:
                self._impl.update(seed_id, context, reward)
            elif self.strategy != "linucb":
                # UCB/Exp3/Thompson 不需要特征向量
                self._impl.update(seed_id, reward)

    def get_stats(self) -> dict:
        return {
            "strategy": self.strategy,
            "unique_seeds_picked": len(self._pick_counts),
            "total_picks": sum(self._pick_counts.values()),
            "avg_reward": sum(self._reward_history) / max(1, len(self._reward_history)),
            "reward_variance": (
                sum((r - self.avg_reward()) ** 2 for r in self._reward_history)
                / max(1, len(self._reward_history))
            ) if self._reward_history else 0.0,
        }

    def avg_reward(self) -> float:
        if not self._reward_history:
            return 0.0
        return sum(self._reward_history) / len(self._reward_history)

    def reset(self) -> None:
        """重置所有内部状态 -- 用于新的模糊测试会话"""
        self._impl = self._build_impl(self.strategy, {})
        self._pick_counts.clear()
        self._reward_history.clear()

# 便捷工厂函数

def create_bandit_scheduler(strategy: str = "linucb", **kw) -> BanditScheduler:
    """根据策略名称创建 BanditScheduler 实例。

    支持的 strategy 值:
      - linucb    -- LinFuzz 2024 上下文 LinUCB
      - ucb       -- pAFL 2024 UCB1
      - exp3      -- RumFuzz 2024 Exp3
      - thompson  -- TMS-Fuzz 2026 Thompson Sampling
    """
    return BanditScheduler(strategy, **kw)
