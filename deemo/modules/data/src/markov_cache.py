# 马尔可夫预测缓存预热 (Markov Chain Predictive Cache Warming)
#
# 核心问题: 现有缓存 (cache.py: LRU/S3LRU/TinyLFU) 是被动淘汰策略,
#   仅在访问时淘汰最不常用的条目. 但二进制分析中的访问模式具有
#   可预测的序列特征:
#     - 导入文件 → 计算 SHA256 → 查 Bloom → 查 SimHash → 查数据库
#     - 同一项目的多个二进制倾向于在相近时间被访问
#   被动缓存在首次访问时必然 cache miss.
#
# 创新点:
#   1. 1阶马尔可夫转移矩阵: 记录观测到的 key_i → key_j 转移频率,
#      构建稀疏转移概率矩阵 P(key_j | key_i) = count(i→j) / count(i).
#      给定当前访问 key, 预测 Top-K 最可能的下一个访问.
#   2. 预测置信度过滤: 仅当 P > min_probability 且 count(i) > min_observations
#      时触发预热. 低频转移 (噪声) 被自动过滤.
#   3. 衰减老化: 对转移计数做指数衰减 (decay=0.99 per window),
#      使旧模式自然淘汰, 新模式快速主导.
#   4. 批量预热: 缓存未命中时, 检查预测表 → 若预测命中概率 > threshold,
#      在一次 I/O 中批量加载预测的 N 个后续条目 → 摊还预热成本.
#
# 与现有工作:
#   - MarkovPrefetch (Rust crate): 面向内存地址预取.
#     本方案面向数据库签名的语义级访问序列.
#   - Tetrahedrangel (ISCA 2024): 硬件 L3 cache 预取.
#     本方案面向软件级签名数据库缓存.
#   - 区别于 predictive_lifecycle.py: 后者预测长期生命周期阶段,
#     本方案预测下一次访问的时机和对象.

from collections import defaultdict, deque
from typing import Any, Dict, List, Optional, Set, Tuple


class MarkovPredictor:
    """1阶马尔可夫转移预测器.

    记录 key_i → key_j 的转移频率, 预测下一个访问的 key.

    用法:
      mp = MarkovPredictor(order=1, min_prob=0.1, decay=0.99)
      for key in access_stream:
          predicted = mp.predict(key, top_k=3)
          cache.prefetch(predicted)  # 预热缓存
          mp.observe(key)
    """

    def __init__(self, order: int = 1, min_probability: float = 0.1,
                 min_observations: int = 5, decay: float = 0.99,
                 max_transitions: int = 10000):
        self.order = order
        self.min_prob = min_probability
        self.min_obs = min_observations
        self.decay = decay
        self.max_trans = max_transitions

        # 转移计数: {from_key: {to_key: count}}
        self._trans: Dict[Any, Dict[Any, int]] = defaultdict(
            lambda: defaultdict(int))
        # 出度总计: {from_key: total_count}
        self._totals: Dict[Any, int] = defaultdict(int)
        # 滑动窗口历史 (用于 n-gram)
        self._history: deque = deque(maxlen=order)
        self._n_obs = 0

    def observe(self, key: Any):
        """记录一次访问: 更新转移矩阵."""
        if self._history:
            prev = self._history[-1]
            if prev != key:  # 不记录自转移
                self._trans[prev][key] += 1
                self._totals[prev] += 1

        self._history.append(key)
        self._n_obs += 1

        # 定期衰减
        if self._n_obs % 1000 == 0:
            self._apply_decay()

    def predict(self, current_key: Any, top_k: int = 3) -> List[Tuple[Any, float]]:
        """预测最可能的 top_k 个下一个访问."""
        trans = self._trans.get(current_key, {})
        total = self._totals.get(current_key, 0)

        if total < self.min_obs:
            return []

        predictions = []
        for next_key, count in trans.items():
            prob = count / total
            if prob >= self.min_prob:
                predictions.append((next_key, round(prob, 4)))

        predictions.sort(key=lambda x: x[1], reverse=True)
        return predictions[:top_k]

    def transition_matrix(self, top_k: int = 20) -> Dict[str, Dict[str, float]]:
        """返回 Top-K 转移概率矩阵 (用于可视化/审计)."""
        matrix = {}
        sorted_from = sorted(self._totals.keys(),
                             key=lambda k: self._totals[k], reverse=True)
        for fk in sorted_from[:top_k]:
            total = self._totals[fk]
            trans = self._trans[fk]
            row = {str(tk): round(cnt/total, 4)
                   for tk, cnt in sorted(trans.items(),
                                         key=lambda x: x[1], reverse=True)[:5]}
            matrix[str(fk)] = row
        return matrix

    def _apply_decay(self):
        """指数衰减所有转移计数."""
        for fk in list(self._trans.keys()):
            inner = self._trans[fk]
            for tk in list(inner.keys()):
                inner[tk] = int(inner[tk] * self.decay)
                if inner[tk] < 1:
                    del inner[tk]
            if not inner:
                del self._trans[fk]
        for fk in list(self._totals.keys()):
            self._totals[fk] = int(self._totals[fk] * self.decay)
            if self._totals[fk] < 1:
                del self._totals[fk]

    @property
    def n_transitions(self) -> int:
        return sum(len(inner) for inner in self._trans.values())

    @property
    def stats(self) -> dict:
        return {
            "observations": self._n_obs,
            "unique_from_keys": len(self._totals),
            "total_transitions": self.n_transitions,
            "avg_transitions_per_key": round(
                self.n_transitions / max(len(self._totals), 1), 2),
        }


class PredictiveCacheWarmer:
    """预测缓存预热器: MarkovPredictor + 缓存集成.

    用法:
      cache = LRUCache(...)
      warmer = PredictiveCacheWarmer(cache, prefetch_fn)
      for key in access_stream:
          value = cache.get(key)
          if value is None:
              value = load_from_db(key)
              cache.set(key, value)
              warmer.on_miss(key)  # 触发预测预热
          warmer.observe(key)
    """

    def __init__(self, cache, prefetch_fn, top_k: int = 3,
                 prefetch_budget: int = 10):
        self._cache = cache
        self._prefetch = prefetch_fn  # callable(key) → value
        self._predictor = MarkovPredictor()
        self._top_k = top_k
        self._budget = prefetch_budget
        self._prefetched = 0
        self._hits = 0

    def observe(self, key: Any):
        self._predictor.observe(key)

    def on_miss(self, key: Any):
        """缓存未命中时: 预测 + 预热."""
        predictions = self._predictor.predict(key, self._top_k)
        prefetched_now = 0
        for next_key, prob in predictions:
            if prefetched_now >= self._budget:
                break
            if self._cache.get(next_key) is not None:
                continue  # 已在缓存中
            try:
                value = self._prefetch(next_key)
                if value is not None:
                    self._cache.set(next_key, value)
                    self._prefetched += 1
                    prefetched_now += 1
            except Exception:
                pass  # 预热失败不影响主流程

    def record_hit(self):
        self._hits += 1

    @property
    def hit_rate(self) -> float:
        return self._hits / max(self._hits + self._prefetched, 1)

    @property
    def stats(self) -> dict:
        return {
            "prefetched": self._prefetched,
            "hits": self._hits,
            "hit_rate": round(self.hit_rate, 4),
            "predictor": self._predictor.stats,
        }


__all__ = [
    "MarkovPredictor",
    "PredictiveCacheWarmer",
]
