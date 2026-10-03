"""RL变异序列调度器 --- 对数线性自回归策略对变异序列整体建模。

对长度为L的序列打分, 每一步条件概率由四项权重求和后经softmax导出:
  score(op_t | op_{t-1}, t, ctx)
    = w1[op_t] + w2[(op_{t-1}, op_t)] + w3[(op_t, t)] + <Wc[op_t], ctx>

w1: 算子边际价值, w2: 邻接转移价值, w3: 位置效用, Wc: 上下文调制项。
奖励信号: 覆盖率增益。REINFORCE + 组内相对基线 (GRPO) + 熵正则。

既有调度对比:
  BanditScheduler: 无状态种子选择, 无序列建模。
  GRPOScheduler: 单算子独立概率, 无转移矩阵。
  本模块: 序列级策略, w2转移 + w3位置权重。可经 HybridSeedMutationScheduler 叠加。
"""

import math
import random
from collections import Counter, defaultdict
from typing import Dict, List, Optional, Sequence, Tuple

import logging

_log = logging.getLogger(__name__)


# 算子词表

# 统一算子标识集, 横向兼容 MutationOp.name 与 StructMutOp.value
DEFAULT_RL_OPS: Tuple[str, ...] = (
    "BIT_FLIP", "BYTE_FLIP", "ARITH_INC", "ARITH_DEC", "INTERESTING",
    "INSERT", "DELETE", "SPLICE", "DICT_INSERT", "DICT_OVERWRITE",
    "FIELD_SWAP", "FIELD_DUPLICATE", "FIELD_DELETE", "FIELD_SHUFFLE",
    "LENGTH_UPDATE", "MAGIC_TAMPER", "CHUNK_REVERSE", "HAVOC",
)

# 默认上下文维度: [log2(1+edge)/10, 1/(1+gen), exec_time_norm, size_norm, novelty]
# 对齐 fuzz_bandit_scheduler._extract_context 的5维约定
DEFAULT_CONTEXT_DIM: int = 5


def map_op_name(name) -> str:
    """异构算子标识归一化到大写字符串。入参可为枚举成员或裸串。"""
    return str(name).strip().upper()


def default_ops(merge_grpo: bool = True) -> List[str]:
    """构造算子词表; merge_grpo=True时合并GRPO枚举成员。"""
    ops = list(DEFAULT_RL_OPS)
    if merge_grpo:
        try:
            from .fuzz_grpo_scheduler import MutationOp
            for o in MutationOp:
                n = map_op_name(o.name)
                if n not in ops:
                    ops.append(n)
        except ImportError:
            pass  # GRPO 模块缺失时仅用内置词表
    return ops


def seed_context_features(seed_meta: dict, data_len: int = 0,
                          edge_count: int = 0) -> List[float]:
    """从种子元数据导出5维归一化上下文向量。

    缺失字段以0.5中性值补齐, 与BanditScheduler默认上下文策略对齐。
    """
    exec_t = seed_meta.get("exec_time_ms", 10.0)
    gen = seed_meta.get("generation", 0)
    is_recent = 1.0 if seed_meta.get("is_recent_find") else 0.0
    rarity = seed_meta.get("rarity_score", 0.5)
    feat = [
        min(1.0, math.log2(1 + edge_count) / 10.0),   # 覆盖规模因子
        1.0 / (1.0 + gen),                            # 代数衰减因子
        min(1.0, exec_t / 100.0),                     # 执行耗时归一化
        min(1.0, data_len / 4096.0),                  # 载荷尺寸归一化
        max(0.0, min(1.0, rarity + is_recent)),       # 稀有度与新近性融合
    ]
    return feat


# 对数线性自回归序列打分

class SequenceScorer:
    """对数线性自回归变异序列策略核心。

    每步条件概率由softmax(score)严格导出, log_prob可解析求值,
    满足REINFORCE对梯度解析性的要求。w2显式编码相邻算子时序依赖,
    w3编码同算子在不同序列位置的效用分化。

    边界: 位置索引从0开始; 超出训练所见长度的位置权重为0。
    """

    def __init__(self, ops: Sequence[str], context_dim: int = 0,
                 default_weight: float = 0.0):
        self._ops = [map_op_name(o) for o in ops]
        if not self._ops:
            raise ValueError("ops 不能为空")
        # 保序去重
        seen = set()
        self._ops = [o for o in self._ops if not (o in seen or seen.add(o))]
        self._K = len(self._ops)
        self._ctx_dim = max(0, int(context_dim))
        # 四组可学习权重表
        self._unigram: Dict[str, float] = {o: default_weight for o in self._ops}
        self._trans: Dict[Tuple[str, str], float] = {
            (a, b): default_weight for a in self._ops for b in self._ops
        }
        self._pos: Dict[Tuple[str, int], float] = {}
        self._ctx: Dict[Tuple[str, int], float] = {}

    # 打分与概率计算

    def score_step(self, op: str, prev_op: Optional[str],
                   pos: int, ctx: Optional[List[float]]) -> float:
        """单步条件分数: unigram + transition + position + context 求和。"""
        s = self._unigram.get(op, 0.0)
        if prev_op is not None:
            s += self._trans.get((prev_op, op), 0.0)
        s += self._pos.get((op, pos), 0.0)
        if self._ctx_dim and ctx:
            for j in range(min(self._ctx_dim, len(ctx))):
                s += self._ctx.get((op, j), 0.0) * ctx[j]
        return s

    def probs(self, prev_op: Optional[str], pos: int,
              ctx: Optional[List[float]], temperature: float = 1.0) -> Dict[str, float]:
        """给定前驱和位置的算子分布。温度缩放后max-减除再归一化, 防数值溢出。"""
        if abs(temperature - 1.0) > 1e-6 and temperature > 0:
            raw = {o: self.score_step(o, prev_op, pos, ctx) / temperature
                   for o in self._ops}
        else:
            raw = {o: self.score_step(o, prev_op, pos, ctx) for o in self._ops}
        mx = max(raw.values())
        exps = {o: math.exp(v - mx) for o, v in raw.items()}
        total = sum(exps.values()) or 1.0
        return {o: e / total for o, e in exps.items()}

    def log_prob(self, seq: Sequence[str], ctx: Optional[List[float]] = None) -> float:
        """序列对数概率, 每步概率下界裁剪至log(1e-12)。"""
        lp = 0.0
        prev: Optional[str] = None
        for t, op in enumerate(seq):
            p = self.probs(prev, t, ctx).get(map_op_name(op), 0.0)
            lp += math.log(max(p, 1e-12))
            prev = map_op_name(op)
        return lp

    # 自回归采样

    def sample_sequence(self, length: int, ctx: Optional[List[float]] = None,
                        temperature: float = 1.0,
                        rng: Optional[random.Random] = None) -> List[str]:
        """按当前策略自回归采样长度为length的算子序列。"""
        rng = rng or random
        seq: List[str] = []
        prev: Optional[str] = None
        for t in range(max(1, int(length))):
            probs = self.probs(prev, t, ctx, temperature)
            seq.append(_sample_from_probs(probs, rng))
            prev = seq[-1]
        return seq

    # REINFORCE + 熵正则化步进

    def apply_update(self, seq: Sequence[str], ctx: Optional[List[float]],
                     advantage: float, lr: float, entropy_coef: float) -> None:
        """REINFORCE策略梯度单步更新, 含熵正则项抑制策略过早坍缩。

        更新式: Δw = lr * (advantage * ∇logπ + entropy_coef * ∇H)
        四组权重 (unigram/trans/pos/ctx) 独立更新。
        """
        lp1: Dict[str, float] = defaultdict(float)
        lp2: Dict[Tuple[str, str], float] = defaultdict(float)
        lp3: Dict[Tuple[str, int], float] = defaultdict(float)
        lp4: Dict[Tuple[str, int], float] = defaultdict(float)
        en1: Dict[str, float] = defaultdict(float)
        en2: Dict[Tuple[str, str], float] = defaultdict(float)
        en3: Dict[Tuple[str, int], float] = defaultdict(float)
        en4: Dict[Tuple[str, int], float] = defaultdict(float)

        prev: Optional[str] = None
        for t, raw_op in enumerate(seq):
            op = map_op_name(raw_op)
            if op not in self._unigram:
                continue
            probs = self.probs(prev, t, ctx)
            # 对数概率梯度项
            for o, p in probs.items():
                lp1[o] -= p
                if prev is not None:
                    lp2[(prev, o)] -= p
                lp3[(o, t)] -= p
                if self._ctx_dim and ctx:
                    for j in range(min(self._ctx_dim, len(ctx))):
                        lp4[(o, j)] -= p * ctx[j]
            lp1[op] += 1.0
            if prev is not None:
                lp2[(prev, op)] += 1.0
            lp3[(op, t)] += 1.0
            if self._ctx_dim and ctx:
                for j in range(min(self._ctx_dim, len(ctx))):
                    lp4[(op, j)] += ctx[j]
            # 熵梯度项
            H = -sum(p * math.log(p) for p in probs.values())
            for o, p in probs.items():
                dH = -p * (math.log(p) + H)
                en1[o] += dH
                if prev is not None:
                    en2[(prev, o)] += dH
                en3[(o, t)] += dH
                if self._ctx_dim and ctx:
                    for j in range(min(self._ctx_dim, len(ctx))):
                        en4[(o, j)] += dH * ctx[j]
            prev = op

        for o, g in lp1.items():
            self._unigram[o] += lr * (advantage * g + entropy_coef * en1.get(o, 0.0))
        for k, g in lp2.items():
            self._trans[k] += lr * (advantage * g + entropy_coef * en2.get(k, 0.0))
        for k, g in lp3.items():
            self._pos[k] = self._pos.get(k, 0.0) + lr * (
                advantage * g + entropy_coef * en3.get(k, 0.0))
        for k, g in lp4.items():
            self._ctx[k] = self._ctx.get(k, 0.0) + lr * (
                advantage * g + entropy_coef * en4.get(k, 0.0))

    # 统计查询

    def op_prior(self) -> Dict[str, float]:
        """unigram权重经softmax后的边际分布, 排除转/位/上下文影响。"""
        mx = max(self._unigram.values())
        exps = {o: math.exp(v - mx) for o, v in self._unigram.items()}
        total = sum(exps.values()) or 1.0
        return {o: e / total for o, e in exps.items()}

    def policy_entropy(self, ctx: Optional[List[float]] = None) -> float:
        """无先验状态下的分布熵, 用于感知策略探索度。"""
        p = self.probs(None, 0, ctx)
        return -sum(v * math.log(v) for v in p.values() if v > 0)


def _sample_from_probs(probs: Dict[str, float], rng) -> str:
    """轮盘赌采样, O(K)。"""
    r = rng.random()
    cum = 0.0
    for op, p in probs.items():
        cum += p
        if r <= cum:
            return op
    return next(iter(probs))


# RL序列调度器 (外部入口)

class RLSequenceScheduler:
    """策略梯度驱动的变异序列调度器, 在线学习算子序列生成策略。

    外部契约:
      select_sequence(context=None) -> List[str]    采样一条序列
      notify_reward(reward, seq, context=None)       反馈奖赏, 组满后执行更新

    组更新为GRPO式组内相对优势: 积累至group_size条后以EMA基线计算
    advantage = r - baseline, 对每条序列执行REINFORCE步。
    """

    def __init__(
        self,
        ops: Optional[Sequence[str]] = None,
        lr: float = 0.05,
        group_size: int = 8,
        seq_len: int = 4,
        baseline_beta: float = 0.1,
        entropy_coef: float = 0.01,
        temperature: float = 1.0,
        context_dim: int = 0,
        seed: Optional[int] = None,
    ):
        if lr <= 0 or lr > 1.0:
            raise ValueError(f"学习率必须在 (0, 1.0], 收到: {lr}")
        if group_size < 1 or seq_len < 1:
            raise ValueError("group_size 与 seq_len 必须为正整数")

        self._lr = lr
        self._group_size = int(group_size)
        self._seq_len = int(seq_len)
        self._baseline_beta = baseline_beta
        self._entropy_coef = entropy_coef
        self._temperature = temperature
        self._scorer = SequenceScorer(ops or default_ops(), context_dim=context_dim)
        self._rng = random.Random(seed)
        self._pending: List[Tuple[List[str], Optional[List[float]], float]] = []
        self._ema_baseline: Optional[float] = None
        self._pick_counts: Counter = Counter()
        self._total_selections = 0
        self._total_updates = 0
        self._reward_history: List[float] = []

    # 序列选择入口

    def select_sequence(self, context: Optional[List[float]] = None) -> List[str]:
        """按当前策略采样一条算子序列, 更新选择计数。"""
        seq = self._scorer.sample_sequence(
            self._seq_len, ctx=context,
            temperature=self._temperature, rng=self._rng,
        )
        for op in seq:
            self._pick_counts[op] += 1
        self._total_selections += 1
        return seq

    # 奖赏反馈与组触发更新

    def notify_reward(self, reward: float, seq: Sequence[str],
                      context: Optional[List[float]] = None) -> Optional[dict]:
        """接收单条序列奖赏; 组满后触发策略梯度更新, 未满返回None。"""
        if seq is None:
            _log.warning("notify_reward 收到空序列, 忽略")
            return None
        self._pending.append(([map_op_name(s) for s in seq],
                              list(context) if context else None, float(reward)))
        self._reward_history.append(float(reward))
        if len(self._pending) < self._group_size:
            return None
        return self._flush_group()

    def _flush_group(self) -> dict:
        """计算组内相对优势, 对每条序列执行REINFORCE步并返回摘要。"""
        rewards = [r for _, _, r in self._pending]
        group_mean = sum(rewards) / len(rewards)
        if self._ema_baseline is None:
            self._ema_baseline = group_mean
        else:
            self._ema_baseline = (
                self._baseline_beta * self._ema_baseline
                + (1.0 - self._baseline_beta) * group_mean
            )
        base = self._ema_baseline
        summary = {"group_size": len(self._pending),
                   "group_mean_reward": round(group_mean, 4),
                   "baseline": round(base, 4)}
        max_abs_adv = 0.0
        advantages = []
        for seq, ctx, r in self._pending:
            adv = r - base
            advantages.append(adv)
            max_abs_adv = max(max_abs_adv, abs(adv))
        if max_abs_adv >= 1e-9:
            for (seq, ctx, r), adv in zip(self._pending, advantages):
                self._scorer.apply_update(seq, ctx, adv, self._lr, self._entropy_coef)
                self._total_updates += 1
        summary["applied_updates"] = self._total_updates
        self._pending = []
        return summary

    # 统计查询

    def get_probabilities(self) -> Dict[str, float]:
        """unigram边际概率, 与GRPOScheduler.get_probabilities同接口形状。"""
        return self._scorer.op_prior()

    def get_transition_matrix(self) -> Dict[Tuple[str, str], float]:
        """非零转移权重表 (prev_op, next_op)->w2。"""
        return {k: v for k, v in self._scorer._trans.items() if abs(v) > 1e-12}

    def get_stats(self) -> dict:
        """运行统计摘要: 选择次数、更新次数、策略熵与算子偏好分布。"""
        probs = self.get_probabilities()
        return {
            "total_selections": self._total_selections,
            "total_updates": self._total_updates,
            "learning_rate": self._lr,
            "group_size": self._group_size,
            "seq_len": self._seq_len,
            "policy_entropy": round(self._scorer.policy_entropy(), 4),
            "pending_group": len(self._pending),
            "avg_reward": (sum(self._reward_history) / max(1, len(self._reward_history))
                           if self._reward_history else 0.0),
            "operator_picks": dict(self._pick_counts),
            "operator_prior": {k: round(v, 4) for k, v in sorted(probs.items())},
        }

    def reset(self) -> None:
        """重置至均匀策略+空基线, 清空全部历史统计, 适配新fuzz会话。"""
        self._scorer = SequenceScorer(self._scorer._ops,
                                      context_dim=self._scorer._ctx_dim)
        self._pending = []
        self._ema_baseline = None
        self._pick_counts.clear()
        self._total_selections = 0
        self._total_updates = 0
        self._reward_history.clear()


# 奖赏塑形

def compute_sequence_reward(new_edges: int, total_edges_before: int,
                            crash_found: bool = False, hang_found: bool = False,
                            exec_time_ms: float = 1.0, novelty: float = 0.0) -> float:
    """序列奖赏标量函数。

    分量:
      coverage_gain: 新边主导项 (相对增益缩放)
      crash_bonus:   崩溃正奖赏
      hang_penalty:  挂起负奖赏
      speed_bonus:   执行速度激励
      novelty:       附加新颖性分

    边界: 新边数归一化到[0,1]防止大绝对规模主导。
    """
    reward = 0.0
    if new_edges > 0:
        total = max(total_edges_before, 1)
        reward += 0.5 * min(new_edges / total, 1.0) * 2.0
    if crash_found:
        reward += 0.6
    if hang_found:
        reward -= 0.1
    speed = min(1.0, 10.0 / max(exec_time_ms, 0.1))
    reward += 0.1 * speed
    reward += max(0.0, min(0.3, novelty))
    return reward


# Bandit种子选择 + RL变异序列叠加

class HybridSeedMutationScheduler:
    """Bandit种子调度与RL变异序列调度的组合调度器。

    职责分工:
      种子选择 -> BanditScheduler (UCB/LinUCB/Exp3/Thompson)
      变异选择 -> RLSequenceScheduler (覆盖率增益在线学习)
    select_seed()返回(index, score), 与Scheduler.pick_seed()语义兼容。
    """

    def __init__(self, bandit_strategy: str = "linucb",
                 bandit_kwargs: Optional[dict] = None,
                 rl_kwargs: Optional[dict] = None,
                 context_dim: int = DEFAULT_CONTEXT_DIM):
        try:
            from .fuzz_bandit_scheduler import BanditScheduler
            self._bandit = BanditScheduler(bandit_strategy, **(bandit_kwargs or {}))
        except ImportError:
            _log.warning("fuzz_bandit_scheduler 不可用, 回退为轮询种子选择")
            self._bandit = None
        rl_kwargs = dict(rl_kwargs or {})
        rl_kwargs.setdefault("context_dim", context_dim)
        self._rl = RLSequenceScheduler(**rl_kwargs)
        self._bandit_strategy = bandit_strategy

    def select_seed(self, seed_queue: list,
                    contexts: Optional[List[List[float]]] = None):
        """从种子队列中选择一个种子, 返回(index, score)或None。

        BanditScheduler各策略参数签名存在差异, 此处按底层impl实际签名分派。
        """
        if not seed_queue:
            return None
        if self._bandit is None:
            return 0, 0.0
        impl = getattr(self._bandit, "_impl", None)
        if impl is not None and hasattr(impl, "select"):
            ids = [getattr(s, "id", str(i)) for i, s in enumerate(seed_queue)]
            if contexts is None:
                # 直接调用impl时自行构造默认上下文
                contexts = _default_bandit_contexts(seed_queue)
            try:
                import inspect
                n_params = len(inspect.signature(impl.select).parameters) - 1
            except (TypeError, ValueError):
                n_params = 2
            try:
                if n_params >= 3:
                    idx, score = impl.select(seed_queue, ids, contexts)
                else:
                    idx, score = impl.select(seed_queue, ids)
            except TypeError:
                return 0, 0.0  # 参数不匹配退化为均匀选择
            if idx < 0 or idx >= len(seed_queue):
                return None
            return idx, score
        # 走通用门面路径
        try:
            return self._bandit.select_seed(seed_queue, contexts)
        except TypeError:
            return (0, 0.0) if seed_queue else None

    def select_mutation_sequence(self, context: Optional[List[float]] = None) -> List[str]:
        """从RL策略采样变异算子序列。"""
        return self._rl.select_sequence(context)

    def notify_seed_reward(self, seed_id: str, context: Optional[List[float]],
                           is_new_find: bool, crash_found: bool = False) -> None:
        """将种子选择结果反馈给Bandit调度器。"""
        if self._bandit is not None:
            self._bandit.notify_reward(seed_id, context, is_new_find, crash_found)

    def notify_mutation_reward(self, reward: float, seq: Sequence[str],
                               context: Optional[List[float]] = None) -> Optional[dict]:
        """将变异序列奖赏反馈给RL调度器, 返回更新摘要或None。"""
        return self._rl.notify_reward(reward, seq, context)

    def get_stats(self) -> dict:
        """返回Bandit与RL两部分的合并运行时统计。"""
        stats = {
            "bandit_strategy": self._bandit_strategy,
            "rl": self._rl.get_stats(),
        }
        if self._bandit is not None:
            try:
                stats["bandit"] = self._bandit.get_stats()
            except Exception:
                pass
        return stats

    def reset(self) -> None:
        """重置底层Bandit与RL调度器全部状态。"""
        if self._bandit is not None:
            self._bandit.reset()
        self._rl.reset()


def create_rl_sequence_scheduler(strategy: str = "rl", **kw) -> RLSequenceScheduler:
    """工厂函数: 构造RL序列调度器实例。strategy参数预留。"""
    return RLSequenceScheduler(**kw)


def _default_bandit_contexts(seed_queue: list) -> List[List[float]]:
    """为种子队列生成默认5维上下文特征列表。

    直接调用底层impl.select时需复刻BanditScheduler的默认上下文构造,
    避免传入None触发LinUCB的参数类型错误。
    """
    try:
        from .fuzz_bandit_scheduler import _extract_context
        return [
            _extract_context(getattr(s, "metadata", {}), len(getattr(s, "data", b"")))
            for s in seed_queue
        ]
    except ImportError:
        return [
            seed_context_features(getattr(s, "metadata", {}),
                                  len(getattr(s, "data", b"")),
                                  edge_count=len(getattr(s, "coverage", set())))
            for s in seed_queue
        ]


__all__ = [
    "DEFAULT_RL_OPS", "DEFAULT_CONTEXT_DIM", "map_op_name", "default_ops",
    "seed_context_features", "SequenceScorer", "RLSequenceScheduler",
    "compute_sequence_reward", "HybridSeedMutationScheduler",
    "create_rl_sequence_scheduler",
]
