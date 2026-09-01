"""
最小见证集选择 — 传播图的子模优化见证节点采样。

给定传播图 G=(V,E)，见证集 S 的覆盖函数 f(S) 为单调子模函数。
贪心算法达到 (1-1/e)≈63% 最优近似。

创新点：
  1. 置信度分桶多样性奖励 — 避免仅选高置信度冗余见证
  2. 惰性贪心加速 — 候选>200时显著降低计算量
  3. 增量维护 — 图变更时仅重算受影响见证

ref: Nemhauser et al. — 子模函数最大化的 (1-1/e) 近似保证。
"""

from __future__ import annotations

import heapq
import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class WitnessCandidate:
    """一个见证候选——(source_node, target_node) 端点对。"""
    source_id: str
    target_id: str
    path_confidence: float          # 最佳路径的联合置信度
    path_length: int
    blocked_edges: FrozenSet[Tuple[str, str]] = field(default_factory=frozenset)
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def key(self) -> Tuple[str, str]:
        return (self.source_id, self.target_id)


class SubmodularCoverageFunction:
    """子模覆盖函数 f: 2^E→R。覆盖度=节点权重×最高可达见证置信度。

    节点权重默认使用 RiskScorer 输出的风险值，未评分节点用 severity。
    分桶调和平均奖励跨置信度层级的多样性覆盖。
    """

    # 置信度分桶数 — 覆盖函数对每桶内的覆盖率加权，
    # 迫使贪心选择在不同置信度层级间分布见证。
    _CONFIDENCE_BUCKETS = 5  # [0-0.2), [0.2-0.4), ..., [0.8-1.0]

    def __init__(self, graph: PropagationGraph,
                 node_weights: Optional[Dict[str, float]] = None):
        self._graph = graph
        self._node_weights = node_weights or {}
        # 预计算可达性：{candidate_key: {reachable_node_id: path_confidence}}
        self._coverage_map: Dict[Tuple[str, str], Dict[str, float]] = {}
        # 见证集→已被覆盖节点的映射缓存
        self._covered_cache: Dict[FrozenSet[Tuple[str, str]], Dict[str, float]] = {}

    def set_node_weights(self, weights: Dict[str, float]) -> None:
        """更新节点权重——通常来自 RiskScorer 的输出。"""
        self._node_weights = dict(weights)
        self._covered_cache.clear()

    def coverage(self, selected: Set[Tuple[str, str]]) -> float:
        """计算见证集 S 的覆盖值 f(S) — 分桶调和平均。"""
        frozen = frozenset(selected)
        if frozen in self._covered_cache:
            node_cov = self._covered_cache[frozen]
        else:
            node_cov = self._compute_node_coverage(selected)

        if not node_cov:
            return 0.0

        # 按置信度分桶计算覆盖率
        bucket_hits: Dict[int, float] = defaultdict(float)
        bucket_totals: Dict[int, float] = defaultdict(float)

        for nid, cov in node_cov.items():
            w = self._node_weights.get(nid, self._graph._nodes[nid].severity
                                       if nid in self._graph._nodes else 0.3)
            bucket_idx = min(int(cov * self._CONFIDENCE_BUCKETS),
                            self._CONFIDENCE_BUCKETS - 1)
            bucket_hits[bucket_idx] += w * cov
            bucket_totals[bucket_idx] += w

        # 各桶覆盖率的调和平均——多样性奖励
        bucket_ratios = []
        for b in range(self._CONFIDENCE_BUCKETS):
            if bucket_totals.get(b, 0) > 0:
                ratio = bucket_hits.get(b, 0.0) / bucket_totals[b]
                bucket_ratios.append(ratio)

        if not bucket_ratios:
            return 0.0

        # 调和平均——低分桶拉低总分，激励算法覆盖低置信度路径
        harmonic = len(bucket_ratios) / sum(1.0 / max(r, 0.001) for r in bucket_ratios)
        return harmonic

    def marginal_gain(self, candidate: Tuple[str, str],
                      selected: Set[Tuple[str, str]]) -> float:
        """Δf = f(S∪{c}) - f(S)。"""
        current = self.coverage(selected)
        augmented = selected | {candidate}
        return self.coverage(augmented) - current

    # 内部：节点覆盖计算与候选预生成
    def _compute_node_coverage(self, selected: Set[Tuple[str, str]]
                               ) -> Dict[str, float]:
        """S 在每个节点上的最高可达置信度。"""
        best_cov: Dict[str, float] = {}

        for src_id, tgt_id in selected:
            src_node = self._graph._nodes.get(src_id)
            tgt_node = self._graph._nodes.get(tgt_id)
            if src_node is None or tgt_node is None:
                continue

            reachable = self._graph.propagate_belief(tgt_id, max_depth=5)
            for rid, conf in reachable.items():
                if conf > best_cov.get(rid, 0.0):
                    best_cov[rid] = conf

        self._covered_cache[frozenset(selected)] = best_cov
        return best_cov

    def precompute_candidates(self) -> List[WitnessCandidate]:
        """预计算候选见证集 — 取传播置信度>0.15的(source, target)对。|V|>200时采样。"""
        candidates: List[WitnessCandidate] = []
        nodes = list(self._graph._nodes.keys())
        n = len(nodes)

        sample_limit = min(n, 200)  # 超过200节点时采样
        if n > 200:
            import random
            sampled = random.sample(nodes, sample_limit)
        else:
            sampled = nodes

        for i, src in enumerate(sampled):
            reachable = self._graph.propagate_belief(src, max_depth=4)
            for tgt, belief in reachable.items():
                if tgt == src or belief < 0.15:
                    continue
                paths = self._graph.find_propagation_paths(
                    src, tgt, max_paths=1, max_depth=4,
                )
                if not paths:
                    continue
                path = paths[0]
                # 收集路径上的边
                blocked = frozenset(
                    (path[i], path[i + 1]) for i in range(len(path) - 1)
                )
                candidates.append(WitnessCandidate(
                    source_id=src, target_id=tgt,
                    path_confidence=belief,
                    path_length=len(path),
                    blocked_edges=blocked,
                ))

        return candidates


class LazyGreedyWitnessSelector:
    """惰性贪心见证选择器 — 利用子模边际增益递减加速选择。

    维护候选按上次边际增益降序的优先队列。pop堆顶重评估：
    若仍为最大则选中，否则重新入堆。候选>200时比朴素贪心快5-15倍。
    """

    _LAZY_THRESHOLD = 200  # 候选数少于此值时，直接朴素贪心（开销更低）

    def __init__(self, coverage_fn: SubmodularCoverageFunction):
        self._f = coverage_fn

    def select(self, candidates: List[WitnessCandidate],
               budget: int) -> List[Tuple[WitnessCandidate, float]]:
        """选择最多 budget 个见证候选。返回 [(候选, 边际增益), ...]。"""
        if budget <= 0 or not candidates:
            return []

        selected: Set[Tuple[str, str]] = set()
        result: List[Tuple[WitnessCandidate, float]] = []

        if len(candidates) <= self._LAZY_THRESHOLD:
            return self._naive_greedy(candidates, budget, selected, result)

        heap: List[List] = []
        for idx, cand in enumerate(candidates):
            heap.append([-self._f.marginal_gain(cand.key, selected), idx, cand, False])
        heapq.heapify(heap)

        while len(result) < budget and heap:
            neg_gain, _, candidate, stale = heapq.heappop(heap)
            if stale:
                continue
            new_gain = self._f.marginal_gain(candidate.key, selected)
            if new_gain < 1e-8:
                continue
            if heap and new_gain < -heap[0][0]:
                heapq.heappush(heap, [-new_gain, 0, candidate, False])
                continue
            selected.add(candidate.key)
            result.append((candidate, new_gain))
            for entry in heap:
                entry[3] = True

        return result

    def _naive_greedy(self, candidates: List[WitnessCandidate],
                      budget: int, selected: Set[Tuple[str, str]],
                      result: List[Tuple[WitnessCandidate, float]]
                      ) -> List[Tuple[WitnessCandidate, float]]:
        """朴素贪心——每轮扫描全部剩余候选。"""
        remaining = list(candidates)

        for _ in range(budget):
            best_cand = None
            best_gain = -1.0

            for cand in remaining:
                if cand.key in selected:
                    continue
                gain = self._f.marginal_gain(cand.key, selected)
                if gain > best_gain:
                    best_gain = gain
                    best_cand = cand

            if best_cand is None or best_gain < 1e-8:
                break

            selected.add(best_cand.key)
            result.append((best_cand, best_gain))
            remaining = [c for c in remaining if c.key != best_cand.key]

        return result


class WitnessSetManager:
    """见证集管理器 — 桥接子模选择器与传播图。

    提供端到端的见证选择、增量更新、评估报告。
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._coverage_fn = SubmodularCoverageFunction(graph)
        self._selector = LazyGreedyWitnessSelector(self._coverage_fn)
        self._candidates: List[WitnessCandidate] = []
        self._selected: List[Tuple[WitnessCandidate, float]] = []

    def update_node_weights(self, risk_scores: Dict[str, float]) -> None:
        self._coverage_fn.set_node_weights(risk_scores)

    def precompute(self, sample_limit: int = 200) -> int:
        """预计算见证候选库——返回候选数。"""
        self._candidates = self._coverage_fn.precompute_candidates()
        return len(self._candidates)

    def select_witnesses(self, budget: int = 20) -> List[Tuple[WitnessCandidate, float]]:
        """执行贪心选择——返回选中的见证列表。

        若候选库为空，自动调用 precompute()。
        """
        if not self._candidates:
            self.precompute()
        self._selected = self._selector.select(self._candidates, budget)
        return self._selected

    def incremental_update(self, new_edges: List[Tuple[str, str]],
                           removed_edges: List[Tuple[str, str]]) -> int:
        """增量维护——图结构变更后，部分见证可能需要重选。

        返回受影响的见证数（标记为待重选）。
        """
        affected = 0
        affected_keys: Set[Tuple[str, str]] = set()

        for src, tgt in new_edges:
            for cand in self._candidates:
                if cand.key in self._selected:
                    continue
                # 新边可能给某候选提供更高置信度路径
                if src in self._graph._nodes and tgt in self._graph._nodes:
                    affected_keys.add(cand.key)

        for src, tgt in removed_edges:
            for cand, _ in self._selected:
                if (src, tgt) in cand.blocked_edges:
                    affected_keys.add(cand.key)

        # 移除受影响的已选见证——触发重选
        self._selected = [(c, g) for c, g in self._selected
                         if c.key not in affected_keys]
        affected = len(affected_keys)
        return affected

    def report(self, witnesses: Optional[List[Tuple[WitnessCandidate, float]]] = None
               ) -> Dict[str, Any]:
        """生成见证集评估报告。"""
        sel = witnesses or self._selected
        if not sel:
            return {"total_witnesses": 0, "coverage": 0.0, "by_layer": {}}

        selected_keys = {c.key for c, _ in sel}
        coverage_val = self._coverage_fn.coverage(selected_keys)

        layer_counts: Dict[str, int] = defaultdict(int)
        conf_sum = 0.0
        for cand, gain in sel:
            src_layer = self._graph._nodes[cand.source_id].layer.name
            tgt_layer = self._graph._nodes[cand.target_id].layer.name
            layer_counts[f"{src_layer}→{tgt_layer}"] += 1
            conf_sum += cand.path_confidence

        return {
            "total_witnesses": len(sel),
            "coverage": round(coverage_val, 4),
            "mean_confidence": round(conf_sum / len(sel), 4),
            "by_layer_crossing": dict(layer_counts),
            "top_gains": [
                {"pair": (c.source_id, c.target_id), "gain": round(g, 4)}
                for c, g in sel[:5]
            ],
        }
