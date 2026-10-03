# 增加跨层衰减因子，避免深层传播路径的置信度虚高
# 风险分位数归一化改用经验CDF，替代min-max

"""
跨层风险评分引擎。

对PropagationGraph中的节点和路径做统一风险量化：
  (a) 节点基础风险 = 自身严重度 + 入边加权传播风险
  (b) 跨层传播风险随层跨度衰减，固件→智能合约经5层跳跃，累积不确定性
      远大于固件→内核单跳
  (c) 最终风险分位数以经验CDF归一化至[0,1]，便于跨项目比较

与CVSS的区别：CVSS为静态单漏洞评分，此处评分为图拓扑敏感，
同一漏洞在不同固件中的风险取决于传播图中位置和可达节点数。

ref: VPSS — 动态漏洞传播评分，此处扩展至跨层图结构。
"""

from __future__ import annotations

import math
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


def _layer_distance(layer_a: PlatformLayer, layer_b: PlatformLayer) -> int:
    """两个平台层间的跳跃数。"""
    return abs(int(layer_b) - int(layer_a))


class RiskScorer:
    """跨层传播风险评分器。

    用法::

        graph = PropagationGraph()
        # ... 填充节点和边 ...
        scorer = RiskScorer(graph)
        scores = scorer.score_all()
        for node_id, risk in scores.items():
            print(f"{node_id}: {risk:.3f}")
    """

    # 跨层衰减系数，每跨一层，传播风险乘此因子
    _LAYER_DECAY = 0.72
    # 入度阻尼，入边多时边际风险递减（log阻尼）
    _INDEGREE_LOG_BASE = 2.0

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._scores: Dict[str, float] = {}

    def score_all(self, max_iterations: int = 20,
                  convergence_threshold: float = 0.001) -> Dict[str, float]:
        """迭代式PageRank风格风险传播计算。

        每节点基础风险为自身严重度，入边贡献传播风险。
        迭代至收敛或达最大迭代次数。
        """
        nodes = self._graph._nodes
        if not nodes:
            return {}

        # 初始化，仅基于自身严重度
        scores: Dict[str, float] = {}
        for nid, node in nodes.items():
            scores[nid] = node.severity

        for iteration in range(max_iterations):
            new_scores: Dict[str, float] = {}
            max_delta = 0.0

            for nid, node in nodes.items():
                incoming_risk = 0.0
                in_edges = []
                for src_id in self._graph._rev_adj.get(nid, []):
                    edge = self._graph._edges.get((src_id, nid))
                    if edge:
                        in_edges.append((src_id, edge))

                if in_edges:
                    # 入度阻尼，入边多时使用log阻尼
                    damp = 1.0 / math.log(len(in_edges) + self._INDEGREE_LOG_BASE,
                                          self._INDEGREE_LOG_BASE)
                    for src_id, edge in in_edges:
                        src_layer = nodes[src_id].layer if src_id in nodes else node.layer
                        layer_jump = _layer_distance(src_layer, node.layer)
                        layer_discount = self._LAYER_DECAY ** layer_jump
                        incoming_risk += scores.get(src_id, 0.0) * edge.confidence * layer_discount
                    incoming_risk *= damp

                # 自身严重度40% + 传播风险60%
                new_score = 0.4 * node.severity + 0.6 * incoming_risk
                new_scores[nid] = new_score
                max_delta = max(max_delta, abs(new_score - scores.get(nid, 0.0)))

            scores = new_scores
            if max_delta < convergence_threshold:
                break

        # 经验CDF归一化
        self._scores = self._empirical_cdf_normalize(scores)
        return dict(self._scores)

    def layer_aggregate(self) -> Dict[PlatformLayer, float]:
        """按平台层聚合风险，每层平均归一化风险。"""
        if not self._scores:
            self.score_all()

        layer_sums: Dict[PlatformLayer, List[float]] = defaultdict(list)
        for nid, score in self._scores.items():
            node = self._graph._nodes.get(nid)
            if node:
                layer_sums[node.layer].append(score)

        return {
            layer: sum(vals) / len(vals)
            for layer, vals in sorted(layer_sums.items(), key=lambda x: x[0].value)
        }

    def top_risk_paths(self, k: int = 5) -> List[Tuple[List[str], float]]:
        """找风险最高的传播路径，适合可解释风险报告。

        对每对(source, target)节点，路径联合风险 =
        Σ(边置信度 × 层衰减) / 路径长度。
        """
        if not self._scores:
            self.score_all()

        candidates: List[Tuple[List[str], float]] = []
        nodes = list(self._graph._nodes.keys())

        for src in nodes:
            reachable = self._graph.propagate_belief(src, max_depth=5)
            for tgt, belief in reachable.items():
                if tgt == src:
                    continue
                paths = self._graph.find_propagation_paths(src, tgt, max_paths=2, max_depth=5)
                for path in paths:
                    risk = (self._scores.get(src, 0) + self._scores.get(tgt, 0)) * belief / len(path)
                    candidates.append((path, risk))

        candidates.sort(key=lambda x: x[1], reverse=True)
        return candidates[:k]

    @staticmethod
    def _empirical_cdf_normalize(scores: Dict[str, float]) -> Dict[str, float]:
        """经验CDF归一化，比min-max鲁棒，不受极端值影响。"""
        if not scores:
            return {}
        sorted_vals = sorted(scores.values())
        n = len(sorted_vals)
        if n <= 1:
            return {k: 0.5 for k in scores}

        result = {}
        for nid, val in scores.items():
            # 二分查找val在排序数组中的位置
            lo, hi = 0, n
            while lo < hi:
                mid = (lo + hi) // 2
                if sorted_vals[mid] < val:
                    lo = mid + 1
                else:
                    hi = mid
            result[nid] = lo / (n - 1)
        return result
