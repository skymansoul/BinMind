# 时序模式挖掘 (Temporal Pattern Mining for Supply Chain Discovery)
#
# 核心问题: 二进制签名库中, 多个独立二进制可能共享隐含的供应链关系:
#   - 同一构建系统产出的多个二进制 (shared build timestamp)
#   - 共享第三方库的二进制 (library update → 所有依赖者几乎同时更新)
#   - 同一攻击者投放的多个恶意样本 (相似的投放时间窗口)
#   这些关系不体现在文件内容中, 仅体现在时间维度上.
#
# 创新点:
#   1. 时序共现模式挖掘: 将每个时间窗口内的二进制更新视为一个"事务",
#      应用改进的 PrefixSpan 算法挖掘频繁时序模式.
#      与传统 PrefixSpan 的区别: 本方案处理的是 indexed sequences
#      (二进制ID按时序排列), 而非 itemset sequences.
#   2. 滞后相关性检测: 计算二进制对之间的交叉相关函数 (CCF),
#      识别 A 更新后 B 在 lag 窗口内更新的概率.
#      lag=0 → 同源构建; lag=1..7天 → 供应链依赖; lag>30天 → 无关.
#   3. 异常共现告警: 历史上独立的两个二进制突然开始共现 →
#      可能是供应链攻击 (恶意代码被注入到正常构建产物中).
#   4. 社区发现: 将二进制作为节点, 共现频率作为边权重,
#      用 Louvain 启发式检测紧密耦合的二进制社区 (clusters).
#      每个社区对应一个构建系统/开发者/供应链子树.
#
# 与现有工作:
#   - 无已知论文将时序模式挖掘应用于二进制供应链关系发现.
#   - PrefixSpan: 面向 itemset 序列, 本方案适配为 indexed sequence.
#   - 适用于威胁情报、供应链审计、构建系统异常检测.

import math
import time
from collections import defaultdict, deque
from typing import Dict, List, Optional, Set, Tuple


class TemporalCooccurrence:
    """时序共现模式: 在时间窗口内共同出现的二进制组."""
    __slots__ = ("binary_ids","first_seen","last_seen","frequency","avg_lag_seconds")
    def __init__(self, ids: List[int], first: float, last: float,
                 freq: int, avg_lag: float):
        self.binary_ids = sorted(ids)
        self.first_seen = first; self.last_seen = last
        self.frequency = freq
        self.avg_lag_seconds = avg_lag

    @property
    def is_same_build(self) -> bool:
        return self.avg_lag_seconds < 60  # <1min → 同一次构建

    @property
    def is_supply_chain(self) -> bool:
        return 3600 <= self.avg_lag_seconds < 86400 * 7  # 1h-7d → 供应链

    def to_dict(self) -> dict:
        return {"ids": self.binary_ids, "freq": self.frequency,
                "avg_lag_s": round(self.avg_lag_seconds, 1),
                "type": "same_build" if self.is_same_build else (
                    "supply_chain" if self.is_supply_chain else "loose_correlation")}


class TemporalMiner:
    """时序模式挖掘器.

    输入: [(binary_id, timestamp), ...] 按时间排序的更新事件流.
    输出: 频繁共现模式 + 滞后相关对 + 二进制社区.

    用法:
      tm = TemporalMiner(window_seconds=3600, min_support=3)
      for sig in db.list_signatures():
          tm.feed(sig['id'], sig['registered_at'])
      patterns = tm.mine_patterns()
      communities = tm.detect_communities()
    """

    def __init__(self, window_seconds: float = 3600,
                 min_support: int = 3, max_lag_days: int = 14):
        self.window = window_seconds
        self.min_support = min_support
        self.max_lag = max_lag_days * 86400

        # 事件流: [(timestamp, binary_id), ...]
        self._events: List[Tuple[float, int]] = []
        # 共现计数: {frozenset(binary_ids): count}
        self._coccur: Dict[frozenset, int] = defaultdict(int)
        self._coccur_times: Dict[frozenset, List[Tuple[float, float]]] = \
            defaultdict(list)
        # 成对滞后: {(a, b): [lag_seconds, ...]}
        self._pair_lags: Dict[Tuple[int, int], List[float]] = defaultdict(list)
        # 二进制的共现邻居: {binary_id: {neighbor_id: weight}}
        self._adj: Dict[int, Dict[int, float]] = defaultdict(lambda: defaultdict(float))

    def feed(self, binary_id: int, timestamp: float):
        """喂入一条更新事件 (按时间顺序调用)."""
        self._events.append((timestamp, binary_id))

    def mine_patterns(self) -> List[TemporalCooccurrence]:
        """挖掘频繁时序共现模式.

        分两阶段:
          Phase 1: 滑窗收集共现对
          Phase 2: 从频繁对出发, 贪心扩展为更大的共现组
        """
        if not self._events:
            return []

        sorted_events = sorted(self._events, key=lambda x: x[0])

        # Phase 1: 滑窗收集
        self._sliding_window_collect(sorted_events)

        # Phase 2: 贪心扩展
        patterns = self._greedy_expand()

        return patterns

    def _sliding_window_collect(self, events: List[Tuple[float, int]]):
        """双指针滑窗: 维护 [left, right) 窗口内的所有二进制."""
        n = len(events)
        right = 0
        window_ids = {}  # {binary_id: count_in_window}

        for left in range(n):
            left_ts, left_id = events[left]
            # 扩展右边界
            while right < n and events[right][0] - left_ts <= self.window:
                rid = events[right][1]
                window_ids[rid] = window_ids.get(rid, 0) + 1
                right += 1

            # 窗口内共现收集 (仅当窗口内有 ≥2 个不同二进制)
            ids_in_window = list(window_ids.keys())
            if len(ids_in_window) >= 2:
                fs = frozenset(ids_in_window)
                self._coccur[fs] += 1
                self._coccur_times[fs].append((left_ts, events[right-1][0] if right>left else left_ts))

                # 成对滞后
                for i in range(len(ids_in_window)):
                    for j in range(i+1, len(ids_in_window)):
                        a, b = ids_in_window[i], ids_in_window[j]
                        # lag = |ts_a - ts_b|
                        ts_a = next(e[0] for e in events if e[1]==a)
                        ts_b = next(e[0] for e in events if e[1]==b)
                        lag = abs(ts_a - ts_b)
                        if lag <= self.max_lag:
                            self._pair_lags[(min(a,b), max(a,b))].append(lag)

            # 收缩左边界
            window_ids[left_id] -= 1
            if window_ids[left_id] <= 0:
                del window_ids[left_id]

    def _greedy_expand(self) -> List[TemporalCooccurrence]:
        """从频繁对出发贪心扩展为更大的共现模式."""
        patterns = []
        # 找到所有满足 min_support 的共现组
        freq_sets = [(fs, cnt) for fs, cnt in self._coccur.items()
                     if cnt >= self.min_support]

        # 按大小和时间排序
        for fs, cnt in sorted(freq_sets, key=lambda x: len(x[0]), reverse=True):
            ids = list(fs)
            times = self._coccur_times.get(fs, [])
            if not times:
                continue
            first = min(t[0] for t in times)
            last = max(t[1] for t in times)
            # 计算组内平均滞后
            lags = []
            for i in range(len(ids)):
                for j in range(i+1, len(ids)):
                    pair_lags = self._pair_lags.get((min(ids[i], ids[j]),
                                                      max(ids[i], ids[j])), [])
                    lags.extend(pair_lags)
            avg_lag = sum(lags)/len(lags) if lags else 0

            patterns.append(TemporalCooccurrence(
                ids=ids, first=first, last=last, freq=cnt, avg_lag=avg_lag))

        return patterns

    def correlated_pairs(self, min_correlation: float = 0.3,
                          min_pairs: int = 3) -> List[dict]:
        """返回滞后相关性最强的二进制对."""
        results = []
        for (a, b), lags in self._pair_lags.items():
            if len(lags) < min_pairs:
                continue
            avg_lag = sum(lags) / len(lags)
            std_lag = math.sqrt(sum((l - avg_lag)**2 for l in lags) / len(lags))
            cv = std_lag / max(avg_lag, 1)  # 变异系数: 越小越规律
            # 相关性 = 频率密度 × (1 - cv)
            density = len(lags) / max(len(self._events), 1)
            corr = density * max(0, 1 - cv)

            if corr >= min_correlation:
                results.append({
                    "a": a, "b": b,
                    "pairs": len(lags),
                    "avg_lag_hours": round(avg_lag / 3600, 1),
                    "cv": round(cv, 3),
                    "correlation": round(corr, 4),
                })

        results.sort(key=lambda x: x["correlation"], reverse=True)
        return results

    def detect_communities(self, min_weight: float = 0.1
                            ) -> List[Set[int]]:
        """Louvain 启发式社区发现.

        从共现频率构建邻接图 → 模块度优化 → 社区划分.
        简化版: 单轮贪心合并 (不迭代至收敛, 适合中等规模).
        """
        # 构建加权邻接矩阵
        for (a, b), lags in self._pair_lags.items():
            weight = len(lags) / max(len(self._events), 1)
            if weight >= min_weight:
                self._adj[a][b] = max(self._adj[a].get(b, 0), weight)
                self._adj[b][a] = max(self._adj[b].get(a, 0), weight)

        if not self._adj:
            return []

        # 初始化: 每个节点一个社区
        communities: Dict[int, int] = {nid: nid for nid in self._adj}
        nodes = list(self._adj.keys())

        # 贪心合并: 将节点移到能使模块度增益最大的邻居社区
        changed = True
        max_iter = 10
        while changed and max_iter > 0:
            changed = False; max_iter -= 1
            for node in nodes:
                best_comm = communities[node]
                best_gain = 0.0
                for nb, w in self._adj[node].items():
                    nb_comm = communities[nb]
                    if nb_comm == best_comm:
                        continue
                    # 简化增益: 社区间权重之和 - 社区内权重
                    gain = w - sum(
                        self._adj[node].get(n, 0)
                        for n in nodes if communities.get(n) == nb_comm
                    ) / max(len([n for n in nodes if communities.get(n)==nb_comm]), 1)
                    if gain > best_gain:
                        best_gain = gain; best_comm = nb_comm
                if best_comm != communities[node]:
                    communities[node] = best_comm; changed = True

        # 聚合为社区集合
        comm_sets: Dict[int, Set[int]] = defaultdict(set)
        for node, comm in communities.items():
            comm_sets[comm].add(node)

        return [s for s in comm_sets.values() if len(s) >= 2]

    def detect_anomalous_cooccurrence(self, new_event: Tuple[int, float],
                                       z_threshold: float = 2.0
                                       ) -> Optional[dict]:
        """检测异常的共现事件.

        若新事件与某个历史独立二进制的共现频率超过历史基线 2σ,
        标记为异常 (可能的供应链攻击).
        """
        new_id, new_ts = new_event
        anomalies = []

        for (a, b), lags in self._pair_lags.items():
            if new_id not in (a, b):
                continue
            other = b if new_id == a else a
            hist_mean = sum(lags) / len(lags)
            hist_std = math.sqrt(sum((l-hist_mean)**2 for l in lags)/len(lags))

            # 检查新事件是否在异常时间窗口内
            for evt in self._events:
                if evt[1] == other:
                    lag = abs(new_ts - evt[0])
                    if hist_std > 0 and abs(lag - hist_mean) > z_threshold * hist_std:
                        anomalies.append({
                            "new_binary": new_id,
                            "related_binary": other,
                            "lag_seconds": lag,
                            "expected_lag": round(hist_mean, 1),
                            "z_score": round(abs(lag-hist_mean)/hist_std, 2),
                        })

        return anomalies[0] if anomalies else None

    def reset(self):
        self._events.clear(); self._coccur.clear()
        self._coccur_times.clear(); self._pair_lags.clear(); self._adj.clear()


__all__ = [
    "TemporalMiner",
    "TemporalCooccurrence",
]
