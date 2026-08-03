# Markov链模糊测试生成器 — 从种子语料学习字节转移概率矩阵
# 参考 "Seed Scheduling in Fuzz Testing as a Markov Decision Process"
# (Cunha et al. 2025)的MDP形式化思想，降级为轻量Markov链:
# 对每个偏移位置学习P(next_byte | prev_byte)，生成保留统计结构的输入。
# 复杂度: O(N*256^2)内存 / O(N*C)生成，N=最大长度 C=生成数
import random
import struct
import math
from typing import List, Dict, Tuple, Optional
from collections import defaultdict, Counter


class MarkovByteModel:
    """单偏移位置的马尔可夫转移矩阵 — 对输入第i个字节，学习
    P(byte_i = b | byte_{i-1} = prev)的经验分布。相邻位置间无耦合
    (naive Bayes假设)，以控制O(N*256^2)内存。

    参考LinFuzz (Su et al. 2024)的上下文向量思路: 若缺乏
    足够转移样本，回退到该位置的全局边际分布。
    """

    __slots__ = ("_transitions", "_marginal", "_position")

    def __init__(self, position: int):
        self._position = position
        # prev_byte -> Counter[next_byte]
        self._transitions: Dict[int, Counter] = defaultdict(Counter)
        self._marginal: Counter = Counter()

    def observe(self, prev_byte: int, curr_byte: int) -> None:
        """记录一次转移事件"""
        self._transitions[prev_byte][curr_byte] += 1
        self._marginal[curr_byte] += 1

    def sample(self, prev_byte: int, rng: random.Random,
               fallback_marginal: bool = True) -> int:
        """给定前一字节，按转移概率采样当前字节。

        fallback_marginal=True: 转移样本不足时回退到全局分布。
        """
        dist = self._transitions.get(prev_byte)
        if not dist:
            if fallback_marginal and self._marginal:
                return _weighted_choice(self._marginal, rng)
            return rng.randint(0, 255)

        return _weighted_choice(dist, rng)

    @property
    def entropy(self) -> float:
        """该位置转移矩阵的平均香农熵 [0, 8]，越低表示越确定"""
        total_trans = sum(
            sum(cnt.values()) for cnt in self._transitions.values())
        if total_trans == 0:
            return 0.0
        ent = 0.0
        for cnt in self._transitions.values():
            subtotal = sum(cnt.values())
            for c in cnt.values():
                p = c / subtotal
                ent -= p * math.log2(p) * (subtotal / total_trans)
        return ent


class MarkovFuzzGenerator:
    """Markov链驱动的模糊测试输入生成器。

    工作流:
    1. fit(corpus) — 从种子集学习逐位置转移矩阵
    2. generate(n) — 采样生成保留统计结构的输入
    3. evolve(best_seed) — 对高产种子做Markov导向局部变异

    生成时若超出训练数据最大长度，用前一字节在边界位置的转移分布做自举。

    参考文献:
    - Cunha et al. 2025, "Seed Scheduling as MDP"
    - Su et al. 2024, "LinFuzz: Program-Sensitive Seed Scheduling via LinUCB"
    - Bohme et al. 2017, "AFLFast: Coverage-based Greybox Fuzzing as MDP" (CCS 2017)
    """

    def __init__(self, order: int = 1, seed: int = None):
        """
        order: Markov阶数（目前仅支持1阶，高阶用_extend_order实现）
        seed: 随机种子，None则使用系统熵
        """
        self._order = order
        self._rng = random.Random(seed)
        self._models: Dict[int, MarkovByteModel] = {}  # offset -> model
        self._max_len = 0
        self._global_freqs: Counter = Counter()
        self._trained = False

    # ---- 训练 ----
    def fit(self, corpus: List[bytes]) -> None:
        """从语料库学习Markov转移矩阵。空输入自动过滤。"""
        self._models.clear()
        self._global_freqs.clear()

        if not corpus:
            self._trained = False
            return

        self._max_len = max(len(s) for s in corpus)

        for seed in corpus:
            if not seed:
                continue
            for i, byte_val in enumerate(seed):
                if i >= self._max_len:
                    break
                if i not in self._models:
                    self._models[i] = MarkovByteModel(i)
                prev = seed[i - 1] if i > 0 else 0x00
                self._models[i].observe(prev, byte_val)
                self._global_freqs[byte_val] += 1

        self._trained = True

    def partial_fit(self, new_seed: bytes) -> None:
        """增量更新: 对单个新种子追加转移统计，避免全量重训练。

        用于在线学习场景。
        """
        if not new_seed:
            return
        if len(new_seed) > self._max_len:
            self._max_len = len(new_seed)
        for i, byte_val in enumerate(new_seed):
            if i not in self._models:
                self._models[i] = MarkovByteModel(i)
            prev = new_seed[i - 1] if i > 0 else 0x00
            self._models[i].observe(prev, byte_val)
            self._global_freqs[byte_val] += 1
        self._trained = True

    # ---- 生成 ----
    def generate(self, count: int = 64,
                 length: Optional[int] = None) -> List[bytes]:
        """生成count个保留统计分布的输入。

        length=None: 从训练数据长度分布随机采样。
        """
        if not self._trained:
            return [bytes(self._rng.randint(0, 255)
                         for _ in range(self._rng.randint(4, 128)))
                    for _ in range(count)]

        results = []
        for _ in range(count):
            n = length if length is not None else self._rng.randint(
                1, max(8, self._max_len))
            results.append(self._sample_one(n))
        return results

    def _sample_one(self, length: int) -> bytes:
        """采样一个长度为length的字节序列。"""
        if length == 0:
            return b""
        buf = bytearray(length)
        prev = 0x00
        for i in range(length):
            model = self._models.get(i)
            if model is not None:
                buf[i] = model.sample(prev, self._rng)
            else:
                # 超出训练长度 -> 回退到全局频率
                buf[i] = _weighted_choice(
                    self._global_freqs, self._rng)
            prev = buf[i]
        return bytes(buf)

    # ---- 进化变异 (Markov-guided mutation) ----
    def evolve(self, seed: bytes, rounds: int = 5) -> bytes:
        """对高产种子做Markov导向局部变异:

        在低熵位置（高确定性区）保留原值，在高熵位置随机重采样。
        低熵=模型认为该偏移字节非常确定（如魔数），不应破坏。
        """
        if not self._trained or not seed:
            return seed
        buf = bytearray(seed)
        for _ in range(rounds):
            i = self._rng.randint(0, len(buf) - 1)
            model = self._models.get(i)
            if model is None:
                continue
            # 低熵位置 (<1.5 bit)跳过变异（通常是固定字段）
            if model.entropy < 1.5:
                continue
            prev = buf[i - 1] if i > 0 else 0x00
            buf[i] = model.sample(prev, self._rng)
        return bytes(buf)

    def crossover(self, parent_a: bytes, parent_b: bytes) -> bytes:
        """两点交叉: 在两父本间选取同偏移位置，以转移概率较高者为准。"""
        if not self._trained:
            return parent_a
        length = self._rng.randint(
            min(len(parent_a), len(parent_b)),
            max(len(parent_a), len(parent_b)))
        buf = bytearray(length)
        prev = 0x00
        for i in range(length):
            model = self._models.get(i)
            ba = parent_a[i] if i < len(parent_a) else None
            bb = parent_b[i] if i < len(parent_b) else None
            if ba is not None and bb is not None and model is not None:
                # 选择转移概率更高的那个字节
                pa = model._transitions.get(prev, {}).get(ba, 0)
                pb = model._transitions.get(prev, {}).get(bb, 0)
                buf[i] = ba if pa >= pb else bb
            elif ba is not None:
                buf[i] = ba
            elif bb is not None:
                buf[i] = bb
            else:
                buf[i] = _weighted_choice(self._global_freqs, self._rng)
            prev = buf[i]
        return bytes(buf)

    # ---- 分析 ----
    def position_entropy_report(self) -> Dict[int, float]:
        """返回每个偏移位置的平均转移熵，用于识别固定/可变字段边界。"""
        return {offset: model.entropy
                for offset, model in self._models.items()}

    def low_entropy_positions(self, threshold: float = 1.5) -> List[int]:
        """返回低熵位置列表（可能是魔数、版本号等固定字段）。"""
        return sorted(
            offset for offset, model in self._models.items()
            if model.entropy < threshold)

    @property
    def trained(self) -> bool:
        return self._trained

    @property
    def max_length(self) -> int:
        return self._max_len


# ---------------------------------------------------------------------------
# 高阶扩展: n-gram Markov，当语料足够大时启用 (order >= 2)
# 存储: prev_bytes (tuple) -> next_byte Counter
# ---------------------------------------------------------------------------
# N-gram Markov (高阶，用于实验场景)
class NGramMarkovModel:
    def __init__(self, n: int = 3):
        self._n = n
        self._transitions: Dict[Tuple[int, ...], Counter] = defaultdict(Counter)
        self._cnt = 0

    def observe(self, context: Tuple[int, ...], next_byte: int) -> None:
        self._transitions[context][next_byte] += 1
        self._cnt += 1

    def sample(self, context: Tuple[int, ...], rng: random.Random) -> int:
        ctx = context
        while len(ctx) > 0:
            dist = self._transitions.get(ctx)
            if dist:
                return _weighted_choice(dist, rng)
            ctx = ctx[1:]  # Katz回退: 截断上下文前缀
        return rng.randint(0, 255)


# ================ 辅助函数 ================
def _weighted_choice(counter: Counter, rng: random.Random) -> int:
    """从Counter中按权重随机抽取一个key"""
    total = sum(counter.values())
    if total <= 0:
        return rng.randint(0, 255)
    r = rng.random() * total
    acc = 0
    for k, v in counter.items():
        acc += v
        if r <= acc:
            return k
    # 浮点舍入保护
    return next(iter(counter))


def build_markov_from_corpus(corpus_dir: str,
                              order: int = 1) -> MarkovFuzzGenerator:
    import os
    gen = MarkovFuzzGenerator(order=order)
    seeds = []
    if os.path.isdir(corpus_dir):
        for fname in os.listdir(corpus_dir):
            fpath = os.path.join(corpus_dir, fname)
            try:
                with open(fpath, 'rb') as fh:
                    data = fh.read()
                if data:
                    seeds.append(data)
            except (OSError, PermissionError):
                continue  # 静默跳过不可读文件
    if seeds:
        gen.fit(seeds)
    return gen
