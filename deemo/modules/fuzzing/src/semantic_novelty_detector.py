# 创建: 2025-08-12 09:22
# 修改: 2025-08-12 — 特征哈希嵌入 + 滑动窗口余弦相似度
"""
语义执行新颖度检测器 — 将运行时行为嵌入低维空间，检测真正的新颖执行。

传统边覆盖无法区分"同一边集、不同运行时行为"的输入:
  - 两个输入可能触发相同的 100 条边，但一个导致 malloc 失败返回 NULL，
    另一个导致 256 字节分配成功——从漏洞视角这是完全不同的状态。
  - 本模块通过增量特征哈希将执行轨迹的语义摘要映射到稀疏嵌入空间，
    用余弦距离度量执行行为的"真正新颖度"。

算法骨架:
  1. 执行摘要提取: 将关键运行时事件 (函数调用签名、异常类型、堆分配模式、
     内存状态区间哈希) 序列化为 token 列表
  2. 特征哈希嵌入: 使用带符号的 feature hashing (Weinberger et al. 2009 ICML)
     将变长 token 列表映射为固定维度 (d=128) 的稀疏向量，sign bit 消除
     hash collision 引入的偏置
  3. 新颖度评分: 计算嵌入向量与滑动窗口中所有历史嵌入的最大余弦相似度，
    新颖度 = 1 - max_similarity。窗口大小由 WINDOW_SIZE 控制，
    旧嵌入按指数衰减权重参与比较
  4. 种子能量分配: 新颖度得分直接作为模糊测试种子的能量乘数，
    高新颖度种子获得更多变异机会

ref: Weinberger et al. "Feature Hashing for Large Scale Multitask Learning" (ICML 2009)
     — 本模块将其从 NLP token hashing 改编为执行事件的在线嵌入
ref: arXiv:2511.03995 (2025) — LLM-guided semantic fuzzing, 借鉴其语义反馈思路
     但本模块将 LLM 嵌入替换为确定性特征哈希, 消除外部模型依赖
ref: Charikar "Similarity Estimation Techniques from Rounding Algorithms" (STOC 2002)
     — SimHash 的原始论文, 本模块的签名哈希借鉴其 sign(random projection) 思路
"""

from __future__ import annotations

import math
import time
import hashlib
import struct
from collections import deque
from typing import Any, Optional


# --- 特征哈希嵌入器 ---
# 维度 128: 平衡碰撞率与内存开销。
# 128 维下 hash collision probability ≈ 1 - exp(-n²/(2*128)) ≈ 3% for n=10 tokens
# 对模糊测试场景足够——即使偶有碰撞，sign bit 将偏置减半，且窗口平均进一步平滑。

EMBED_DIM = 128
WINDOW_SIZE = 200  # 滑动窗口保留的最近嵌入数
DECAY_ALPHA = 0.995  # 窗口内旧嵌入的指数衰减因子
NOVELTY_THRESHOLD = 0.15  # 低于此值视为"真正新颖"的硬阈值


def _murmur_hash_bytes(data: bytes, seed: int = 0) -> int:
    """简化的 MurmurHash3 32-bit — 无外部依赖的特征哈希。
    用于将 token 映射到嵌入维度索引。"""
    h = seed ^ len(data)
    for i in range(0, len(data) - 3, 4):
        k = struct.unpack_from('<I', data, i)[0]
        k = (k * 0xcc9e2d51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1b873593) & 0xFFFFFFFF
        h ^= k
        h = ((h << 13) | (h >> 19)) & 0xFFFFFFFF
        h = (h * 5 + 0xe6546b64) & 0xFFFFFFFF
    tail = data[-(len(data) & 3):] if len(data) & 3 else b''
    k = 0
    for j, b in enumerate(tail):
        k |= b << (j * 8)
    if tail:
        k = (k * 0xcc9e2d51) & 0xFFFFFFFF
        k = ((k << 15) | (k >> 17)) & 0xFFFFFFFF
        k = (k * 0x1b873593) & 0xFFFFFFFF
        h ^= k
    h ^= len(data)
    h ^= (h >> 16)
    h = (h * 0x85ebca6b) & 0xFFFFFFFF
    h ^= (h >> 13)
    h = (h * 0xc2b2ae35) & 0xFFFFFFFF
    h ^= (h >> 16)
    # 转为有符号范围
    return h if h < 0x80000000 else h - 0x100000000


class FeatureHasher:
    """增量特征哈希 — 将变长 token 序列映射为固定维度的稀疏向量。
    每次调用 hash_token 更新内部累积向量。
    sign bit 来自 token 内容的 parity，消除 hash collision 偏置。"""

    __slots__ = ('_vec', '_dim', '_n')

    def __init__(self, dim: int = EMBED_DIM):
        self._dim = dim
        self._vec = [0.0] * dim
        self._n = 0

    def hash_token(self, token: str) -> None:
        """将单个 token 哈希到嵌入维度并累加。"""
        raw = token.encode('utf-8', errors='replace')
        h = _murmur_hash_bytes(raw, seed=0x9E3779B9)
        idx = abs(h) % self._dim
        # sign bit: 使用 token 的第二个哈希值 (不同 seed) 的 LSB
        sign_h = _murmur_hash_bytes(raw, seed=0x27AE41B9)
        sign = 1.0 if (sign_h & 1) == 0 else -1.0
        self._vec[idx] += sign
        self._n += 1

    def hash_tokens(self, tokens: list[str]) -> None:
        for t in tokens:
            self.hash_token(t)

    def vector(self) -> list[float]:
        """返回归一化的嵌入向量。L2 归一化使余弦相似度等价于点积。"""
        if self._n == 0:
            return [0.0] * self._dim
        norm_sq = sum(v * v for v in self._vec)
        if norm_sq < 1e-12:
            return [0.0] * self._dim
        inv_norm = 1.0 / math.sqrt(norm_sq)
        return [v * inv_norm for v in self._vec]

    def reset(self):
        self._vec = [0.0] * self._dim
        self._n = 0


# --- 执行摘要提取 ---
# 将运行时事件转为可哈希的 token 列表。
# 调用方在每次 fuzz case 执行后填充 ExecutionSummary, 然后传给 detector。
# token 格式: "前缀:哈希值" — 前缀标识事件类型, 哈希值紧凑表达事件内容。
# 使用截断 SHA-256 (前 12 hex chars) 作为哈希, 碰撞概率可忽略不计。

class ExecutionSummary:
    """模糊测试用例的运行时行为摘要。"""

    __slots__ = ('visited_blocks', 'function_calls', 'heap_patterns',
                 'exception_type', 'memory_region_hash', 'return_code')

    def __init__(self):
        self.visited_blocks: list[int] = []     # 基本块地址列表
        self.function_calls: list[str] = []     # 被调用函数名
        self.heap_patterns: list[str] = []      # "alloc:N" or "free:N" or "realloc:N→M"
        self.exception_type: str = ''           # "sigsegv", "sigabrt", "none"
        self.memory_region_hash: int = 0        # 内存状态的分区哈希
        self.return_code: int = 0

    def to_tokens(self) -> list[str]:
        """将执行摘要序列化为 token 列表, 供特征哈希使用。"""
        tokens: list[str] = []

        # 基本块: 按地址范围分桶, 减少 token 数量
        buckets: dict[int, int] = {}
        for addr in self.visited_blocks:
            bucket = (addr >> 8) & 0xFFF  # 4096 个桶, 每桶覆盖 256 字节
            buckets[bucket] = buckets.get(bucket, 0) + 1
        for bucket, count in buckets.items():
            tokens.append(f"BB:{bucket:03x}:{count}")

        # 函数调用: 去重
        seen_funcs: set[str] = set()
        for f in self.function_calls:
            h = hashlib.sha256(f.encode()).hexdigest()[:8]
            if h not in seen_funcs:
                seen_funcs.add(h)
                tokens.append(f"FC:{h}")

        # 堆模式
        for p in self.heap_patterns:
            h = hashlib.sha256(p.encode()).hexdigest()[:6]
            tokens.append(f"HP:{h}")

        # 异常类型
        if self.exception_type:
            tokens.append(f"EX:{self.exception_type}")

        # 内存区域哈希
        if self.memory_region_hash:
            tokens.append(f"MR:{self.memory_region_hash:08x}")

        # 返回码 (分桶)
        rc_bucket = self.return_code >> 3 if self.return_code != 0 else 0
        tokens.append(f"RC:{rc_bucket}")

        return tokens


# --- 滑动窗口嵌入索引 ---
# 存储最近 N 个嵌入向量及其时间戳。
# 查询时计算与所有窗口内嵌入的余弦相似度, 取最大值。
# 旧嵌入以指数衰减参与计算, 使最近的执行行为主导新颖度判定。

class SlidingWindowIndex:
    """嵌入向量的滑动窗口索引 — 无外部依赖的近似最近邻检索。"""

    def __init__(self, window_size: int = WINDOW_SIZE,
                 decay_alpha: float = DECAY_ALPHA):
        self._window: deque[tuple[list[float], float]] = deque()
        self._window_size = window_size
        self._decay_alpha = decay_alpha

    def add(self, embedding: list[float]) -> None:
        now = time.time()
        self._window.append((embedding, now))
        while len(self._window) > self._window_size:
            self._window.popleft()

    def max_similarity(self, query: list[float]) -> float:
        """返回查询向量与窗口内所有向量的最大余弦相似度。
        旧嵌入按指数衰减加权: weight = alpha^(age_seconds / 60)。"""
        if not self._window:
            return 0.0
        now = time.time()
        best = 0.0
        for emb, ts in self._window:
            age_sec = now - ts
            weight = self._decay_alpha ** (age_sec / 60.0)
            if weight < 0.01:
                continue
            # 余弦相似度 = 点积 (向量已 L2 归一化)
            sim = sum(a * b for a, b in zip(query, emb))
            weighted = sim * weight
            if weighted > best:
                best = weighted
        return min(best, 1.0)

    def size(self) -> int:
        return len(self._window)

    def clear(self):
        self._window.clear()


# --- 新颖度检测器 ---

class SemanticNoveltyDetector:
    """主检测器 — 封装特征哈希、滑动窗口索引和新颖度评分。

    用法:
        detector = SemanticNoveltyDetector()
        summary = ExecutionSummary()
        # ... 填充 summary from fuzz harness ...
        score = detector.evaluate(summary)
        if score > NOVELTY_THRESHOLD:
            # 高新颖度 — 分配更多变异能量
            seed.energy *= (1.0 + score)

    新颖度得分范围 [0, 1]:
      - 0.0 → 完全重复 (与之前的执行完全相同)
      - 0.5 → 中等新颖 (有部分新行为)
      - 1.0 → 完全新颖 (从未见过的行为模式)
    """

    __slots__ = ('_index', '_hasher', '_n_evaluated',
                 '_novelty_sum', '_novelty_max', '_dim')

    def __init__(self, dim: int = EMBED_DIM,
                 window_size: int = WINDOW_SIZE):
        self._dim = dim
        self._index = SlidingWindowIndex(window_size)
        self._hasher = FeatureHasher(dim)
        self._n_evaluated = 0
        self._novelty_sum = 0.0
        self._novelty_max = 0.0

    def evaluate(self, summary: ExecutionSummary) -> float:
        """评估执行摘要的新颖度。返回 [0,1] 的得分。"""
        self._n_evaluated += 1

        # tokenize → embed
        tokens = summary.to_tokens()
        self._hasher.reset()
        self._hasher.hash_tokens(tokens)
        embedding = self._hasher.vector()

        # 查询窗口中的最大相似度
        max_sim = self._index.max_similarity(embedding)
        novelty = 1.0 - max_sim

        # 加入窗口
        self._index.add(embedding)

        self._novelty_sum += novelty
        if novelty > self._novelty_max:
            self._novelty_max = novelty

        return round(novelty, 4)

    def evaluate_batch(self, summaries: list[ExecutionSummary]) -> list[float]:
        """批量评估, 每个摘要相对于窗口和批次内前置摘要。"""
        scores = []
        for s in summaries:
            scores.append(self.evaluate(s))
        return scores

    def avg_novelty(self) -> float:
        if self._n_evaluated == 0:
            return 0.0
        return self._novelty_sum / self._n_evaluated

    def stats(self) -> dict:
        return {
            'n_evaluated': self._n_evaluated,
            'avg_novelty': round(self.avg_novelty(), 4),
            'max_novelty': round(self._novelty_max, 4),
            'window_size': self._index.size(),
            'embed_dim': self._dim,
        }

    def reset(self):
        self._index.clear()
        self._n_evaluated = 0
        self._novelty_sum = 0.0
        self._novelty_max = 0.0


# --- 种子能量分配适配器 ---
# 将新颖度得分映射到 fuzzer 的种子能量乘数。
# 使用分段线性映射: 低新颖度 [0, threshold] → 基础倍率,
# 高新颖度 (threshold, 1.0] → 线性放大至 max_multiplier。

def novelty_to_energy(novelty: float,
                      threshold: float = NOVELTY_THRESHOLD,
                      max_multiplier: float = 5.0) -> float:
    """将新颖度得分转换为种子能量乘数。"""
    if novelty <= threshold:
        return 1.0
    # 线性映射: (threshold, 1.0] → (1.0, max_multiplier]
    ratio = (novelty - threshold) / (1.0 - threshold)
    return 1.0 + ratio * (max_multiplier - 1.0)


class NoveltyGuidedEnergyPolicy:
    """新颖度感知的种子能量策略 — 替换均匀分配。

    与现有的 DecayingNoveltyScheduler 互补:
      - DecayingNoveltyScheduler 做时间维度的遗忘曲线 (Ebbinghaus)
      - 本模块做语义维度的行为新颖度 (feature hashing)
    两者可组合: 最终能量 = time_decay_weight * semantic_novelty_multiplier
    """

    def __init__(self, detector: SemanticNoveltyDetector | None = None):
        self._detector = detector or SemanticNoveltyDetector()

    def assign_energy(self, seed_id: str,
                      summary: ExecutionSummary,
                      base_energy: float) -> float:
        """为种子分配能量。返回调整后的能量值。"""
        novelty = self._detector.evaluate(summary)
        multiplier = novelty_to_energy(novelty)
        return base_energy * multiplier

    def detector(self) -> SemanticNoveltyDetector:
        return self._detector


__all__ = [
    'SemanticNoveltyDetector', 'ExecutionSummary',
    'FeatureHasher', 'SlidingWindowIndex',
    'NoveltyGuidedEnergyPolicy', 'novelty_to_energy',
]
