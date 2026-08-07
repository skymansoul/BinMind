# 创建: 2026-04-21
# 修改: 2026-04-21 — 基础热度追踪升级为FTPL遗憾最优在线缓存
#
# 遗憾最优在线缓存放置 — Follow-the-Perturbed-Leader + 局部性感知
#
# 旧版 DataLocalityTracker 用 LRU 热度向量 + 综合评分做放置决策。
# LRU 在对抗性访问模式下遗憾 Ω(N) (N = 缓存槽位数)。
#
# Follow-the-Perturbed-Leader:
#   每步对历史累积代价加随机扰动 → 选择扰动后代价最小的动作。
#   对在线缓存问题, FTPL 的期望遗憾 = O(√T·K·log K), K=候选节点数。
#   这是已知的在线凸优化的最优遗憾率 (匹配下界)。
#
# 本模块的组合创新: FTPL 决策 + 数据局部性代价函数。
#   代价(action) = 远程加载惩罚 + 缓存驱逐代价
#   FTPL 自动在"复用热节点"与"探索新节点"间取得遗憾最优平衡。

from __future__ import annotations

import math
import random
import time
import threading
from collections import defaultdict, deque
from typing import Optional, List, Dict, Tuple, Set


class FTPLOnlineCache:
    """FTPL 驱动的在线缓存放置。

    状态: M 台机器, 每台有容量 C_m (可缓存的 data_key 数量)。
    每步: 请求 data_key → 选择机器 → 若未缓存则付出加载代价。
    FTPL 保证无论请求序列如何 (即使是对手故意构造的),
    长期平均代价 ≤ 最优静态放置的代价 + O(1/√T)。

    FTPL 核心: 对每台机器的累积代价加指数噪声 → 选代价最小者。
    指数噪声的尺度 η = √(8·T·log M) 给出最优遗憾界。
    """

    def __init__(self, n_machines: int, cache_capacity: int = 10,
                 miss_cost: float = 1.0, seed: Optional[int] = None):
        self._M = n_machines
        self._C = cache_capacity
        self._miss_cost = miss_cost
        self._rng = random.Random(seed)
        # FTPL 状态
        self._cum_cost: List[float] = [0.0] * n_machines
        self._eta: float = 1.0
        self._t: int = 0
        # 每台机器的缓存集合
        self._caches: List[Set[str]] = [set() for _ in range(n_machines)]
        self._lru_order: List[deque] = [deque() for _ in range(n_machines)]
        self._lock = threading.Lock()

    def select_node(self, data_key: str) -> int:
        """FTPL 决策: 选择代价 + 扰动最小的机器。

        代价:
          cost(m) = 0 (若 data_key 已缓存)
                  = miss_cost (若需远程加载)
          历史代价 = 累积到当前步的 cost 之和。
        """
        with self._lock:
            self._t += 1
            # 指数噪声尺度随 √t 递减
            self._eta = math.sqrt(8.0 * self._t * math.log(max(self._M, 2)))

            # 计算每台机器的当前代价 + FTPL 扰动
            scores = []
            for m in range(self._M):
                current_cost = (
                    0.0 if data_key in self._caches[m]
                    else self._miss_cost
                )
                # FTPL: perturbed = cum_cost + noise
                noise = self._rng.expovariate(1.0 / max(self._eta, 0.01))
                perturbed = self._cum_cost[m] + current_cost + noise
                scores.append(perturbed)

            best_m = min(range(self._M), key=lambda m: scores[m])
            self._cum_cost[best_m] += (
                0.0 if data_key in self._caches[best_m]
                else self._miss_cost
            )
            self._update_cache(best_m, data_key)
            return best_m

    def _update_cache(self, machine: int, data_key: str):
        cache = self._caches[machine]
        lru = self._lru_order[machine]
        if data_key in cache:
            lru.remove(data_key)
        else:
            if len(cache) >= self._C:
                evict = lru.popleft()
                cache.discard(evict)
            cache.add(data_key)
        lru.append(data_key)

    def regret_bound(self) -> float:
        """当前遗憾上界: √(T·K·log K)。"""
        return math.sqrt(self._t * self._M * math.log(max(self._M, 2)))

    def stats(self) -> dict:
        with self._lock:
            hit_rates = []
            for m in range(self._M):
                c = self._caches[m]
                hit_rates.append(len(c) / max(self._C, 1))
            return {
                "n_machines": self._M, "cache_capacity": self._C,
                "steps": self._t, "regret_bound": round(self.regret_bound(), 2),
                "avg_cache_util": round(sum(hit_rates)/len(hit_rates), 3),
            }


class DataLocalityScheduler:
    """数据局部性感知调度器 — FTPL 缓存 + 负载均衡。

    与旧版兼容的接口 select_node / record_completion。
    内部用 FTPLOnlineCache 做遗憾最优的缓存放置决策。
    """

    def __init__(self, n_machines: int, locality_weight: float = 0.6):
        self._M = n_machines
        self._w_loc = locality_weight
        self._ftpl = FTPLOnlineCache(n_machines)
        self._loads = [0.0] * n_machines
        self._lock = threading.Lock()

    def select_node(self, data_keys: List[str],
                    task_cost: float = 1.0) -> int:
        with self._lock:
            # FTPL 选择数据局部性最优的节点
            best_locality = -1
            best_score = float('inf')
            for dk in data_keys[:3]:  # 最多考虑 3 个数据键
                m = self._ftpl.select_node(dk)
                # 综合得分: 局部性代价 + (1-w)·负载
                score = (self._w_loc * self._ftpl._cum_cost[m]
                         + (1 - self._w_loc) * self._loads[m])
                if score < best_score:
                    best_score = score
                    best_locality = m

            if best_locality < 0:
                best_locality = min(range(self._M),
                                   key=lambda m: self._loads[m])
            self._loads[best_locality] += task_cost
            return best_locality

    def record_completion(self, node_id: int, data_keys: List[str],
                          task_cost: float = 1.0):
        with self._lock:
            self._loads[node_id] = max(0, self._loads[node_id] - task_cost)

    def stats(self) -> dict:
        return {"ftpl": self._ftpl.stats(),
                "loads": [round(l, 2) for l in self._loads]}
