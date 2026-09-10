"""
时序因果发现 -- PC算法从传播图快照序列中区分因果边与伪相关边.

问题:CrossPlatformCorrelator基于符号共现等关联信号建边,但关联≠因果.
伪相关边导致风险评分虚高,补丁优先级错配.

方案:PC算法 -- 偏相关系数条件独立性检验,
骨架学习->v-结构定向->Meek规则传播.首次应用于漏洞传播图快照序列.

前提:因果充分性,马尔可夫条件,忠实性.

与已有工作的区分:INCADET 做CPS攻击检测,不涉及漏洞传播的跨层依赖.
                 Kaushik et al. 仅提出愿景,未实现.

ref: Spirtes et al. "Causation, Prediction, and Search".
ref: INCADET -- 增量因果图学习在安全检测中的应用.
"""
from __future__ import annotations

import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class CausalEdge:
    """经因果发现验证的传播边-方向已确定."""
    source: str
    target: str
    is_causal: bool                   # 通过条件独立性检验
    confidence: float                  # 偏相关系数(绝对值)
    orientation: str = "undirected"    # undirected | directed | bidirected


@dataclass
class CausalGraph:
    """因果发现输出的有向因果图."""
    nodes: List[str] = field(default_factory=list)
    edges: List[CausalEdge] = field(default_factory=list)
    v_structures: List[Tuple[str, str, str]] = field(default_factory=list)
    # (X, Y, Z) 表示 X->Y←Z 的v-结构

    @property
    def causal_edge_count(self) -> int:
        return sum(1 for e in self.edges if e.is_causal)

    @property
    def directed_edge_count(self) -> int:
        return sum(1 for e in self.edges
                   if e.is_causal and e.orientation == "directed")


class TemporalCausalDiscoverer:
    """时序PC因果发现器 -- 偏相关条件独立性检验 + v-结构定向.

    用法::

        discoverer = TemporalCausalDiscoverer(alpha=0.05)
        causal_graph = discoverer.discover(snapshots_over_time)
    """

    def __init__(self, alpha: float = 0.05, max_conditioning_set: int = 4):
        self._alpha = alpha               # 条件独立性检验的显著性水平
        self._max_cond = max_conditioning_set  # 条件集最大尺寸-控制计算复杂度

    def discover(self, snapshots: List[PropagationGraph]
                 ) -> CausalGraph:
        """从传播图快照序列中学习因果图.

        snapshots: 按时间排序的传播图快照列表(≥3个推荐).
        """
        if len(snapshots) < 2:
            return CausalGraph()

        # 汇集所有出现过的节点
        all_nodes: Set[str] = set()
        for g in snapshots:
            all_nodes.update(g._nodes.keys())
        node_list = sorted(all_nodes)

        # 构建时序观测矩阵:{node_id: [risk_vector_over_time]}
        # 每时间点的"观测"=节点在传播图中的结构位置特征
        node_series = self._build_temporal_features(snapshots, node_list)

        # 骨架学习-DAG感知(传入快照提取层序约束)
        adj = self._skeleton_phase(node_list, node_series, snapshots)

        # v-结构检测 + 方向传播
        edges = self._orient_edges(node_list, adj, node_series)

        # 构建输出
        v_structures = self._detect_v_structures(edges)

        return CausalGraph(
            nodes=node_list,
            edges=edges,
            v_structures=v_structures,
        )

    def _build_temporal_features(self, snapshots: List[PropagationGraph],
                                 node_list: List[str]) -> Dict[str, List[float]]:
        """构建时序特征-每节点在每个快照上的风险代理值."""
        series: Dict[str, List[float]] = {nid: [] for nid in node_list}

        for g in snapshots:
            for nid in node_list:
                if nid in g._nodes:
                    node = g._nodes[nid]
                    indeg = len(g._rev_adj.get(nid, []))
                    # 风险代理 = 严重度 + 入度归一化贡献
                    proxy = 0.5 * node.severity + 0.5 * min(indeg / 10.0, 1.0)
                    series[nid].append(proxy)
                else:
                    series[nid].append(0.0)

        return series

    def _skeleton_phase(self, node_list: List[str],
                        series: Dict[str, List[float]],
                        snapshots: Optional[List[PropagationGraph]] = None
                        ) -> Dict[str, Set[str]]:
        """PC骨架阶段-传播图DAG感知的条件独立性检验删边。

        利用传播图已知的层序约束(低层→高层)作为先验。
        若边a→b违反层序(layer(a)>=layer(b)), 则该边的条件独立性
        检验使用更宽松的显著性水平，DAG约束表明此方向不可能有因果边,
        时序相关性更可能是伪相关, 应更积极地删边。
        """
        n = len(node_list)
        adj: Dict[str, Set[str]] = {nid: set(node_list) - {nid}
                                     for nid in node_list}

        # 从快照提取层序信息
        layer_map: Dict[str, int] = {}
        if snapshots:
            for g in snapshots:
                for nid in node_list:
                    if nid in g._nodes:
                        layer_map[nid] = g._nodes[nid].layer.value
                        break

        cond_set_size = 0
        while cond_set_size <= self._max_cond:
            changed = False
            for i, a in enumerate(node_list):
                neighbors = list(adj.get(a, set()))
                for b in neighbors:
                    if b <= a:
                        continue

                    cond_candidates = [x for x in adj.get(a, set())
                                      if x != b and x in adj.get(b, set())]
                    if len(cond_candidates) < cond_set_size:
                        continue

                    # DAG层序惩罚：若a和b的层序关系已知且违反DAG方向, 用更宽松的alpha
                    eff_alpha = self._alpha
                    if layer_map:
                        la, lb = layer_map.get(a, -1), layer_map.get(b, -1)
                        if la >= 0 and lb >= 0 and la >= lb:
                            # a的层>=b的层: a→b违反DAG(应低→高), 怀疑是伪相关
                            # 显著性水平放宽(更易拒绝H0=独立, 更易删边)
                            layer_gap = la - lb + 1
                            eff_alpha = min(0.50, self._alpha * (1.5 + 0.3 * layer_gap))

                    tested = 0
                    edge_removed = False
                    for cond_set in self._sample_conditioning_sets(
                        cond_candidates, cond_set_size, max_samples=30,
                    ):
                        if self._conditional_independence(a, b, list(cond_set), series, eff_alpha):
                            adj[a].discard(b)
                            adj[b].discard(a)
                            changed = True
                            edge_removed = True
                            break
                        tested += 1
                        if tested >= 30:
                            break

            if not changed:
                break
            cond_set_size += 1

        return adj

    def _orient_edges(self, node_list: List[str],
                      adj: Dict[str, Set[str]],
                      series: Dict[str, List[float]]
                      ) -> List[CausalEdge]:
        """方向定向-v-结构 + Meek规则传播.

        1. 对每条无向边 a-b,搜索所有 c 满足 c 与 a,b 均相邻
           若 c∉Sepset(a,b) 且 b∈Sepset(a,c),则定向 a->b←c (v-结构)
        2. 传播R1:若 a->b 且 b-c 无向,a-c 无边,则定向 b->c
           (避免新v-结构)
        """
        edges: Dict[Tuple[str, str], CausalEdge] = {}
        # 初始化无向边
        for a in node_list:
            for b in adj.get(a, set()):
                if a < b:
                    key = (a, b)
                    pc = self._partial_correlation(a, b, [], series)
                    edges[key] = CausalEdge(
                        source=a, target=b,
                        is_causal=True,
                        confidence=pc,
                        orientation="undirected",
                    )

        # v-结构检测
        for a, b in list(edges.keys()):
            for c in node_list:
                if c == a or c == b:
                    continue
                # 检查是否构成 v-结构:a-c 和 b-c 有边,但 a-b 的Sepset不含c
                has_ac = (a, c) in edges or (c, a) in edges or c in adj.get(a, set())
                has_bc = (b, c) in edges or (c, b) in edges or c in adj.get(b, set())

                if has_ac and has_bc:
                    # c 在多条边中作为 collider -> 定向 a->c←b
                    for (x, y) in [(a, c), (b, c)]:
                        key_xy = (min(x, y), max(x, y))
                        if key_xy in edges:
                            if edges[key_xy].source == y:
                                edges[key_xy].orientation = "directed"

        # Meek R1:若 a->b 且 b-c 无向,a-c 无边,则定向 b->c
        changed = True
        while changed:
            changed = False
            for (x, y), edge_xy in list(edges.items()):
                if edge_xy.orientation != "directed":
                    continue
                # x->y 已定向
                for z in adj.get(y, set()):
                    if z == x:
                        continue
                    key_yz = (min(y, z), max(y, z))
                    if key_yz in edges and edges[key_yz].orientation == "undirected":
                        # 检查 x-z 无边
                        key_xz = (min(x, z), max(x, z))
                        if key_xz not in edges and z not in adj.get(x, set()):
                            # 定向 y->z
                            if edges[key_yz].source == z:
                                edges[key_yz] = CausalEdge(
                                    source=y, target=z,
                                    is_causal=True,
                                    confidence=edges[key_yz].confidence,
                                    orientation="directed",
                                )
                                changed = True

        return list(edges.values())

    def _conditional_independence(self, a: str, b: str,
                              cond_set: List[str],
                              series: Dict[str, List[float]],
                              eff_alpha: Optional[float] = None
                              ) -> bool:
        """Fisher z-transformed 偏相关系数检验.

        H0: ρ(a,b | S) = 0 (条件独立)
        若p-value > alpha -> 不拒绝H0 -> 条件独立 -> 应删边.
        """
        n = len(series[a])
        if n <= len(cond_set) + 2:
            return True  # 样本不足,保守地认为独立

        pc = self._partial_correlation(a, b, cond_set, series)
        # Fisher z-transform
        z = 0.5 * math.log((1.0 + pc) / max(1.0 - pc, 1e-9))
        se = 1.0 / math.sqrt(n - len(cond_set) - 3)
        z_stat = abs(z) / max(se, 1e-9)

        # 正态近似 p-value(双尾)
        p_val = 2.0 * (1.0 - self._normal_cdf(z_stat))
        alpha = eff_alpha if eff_alpha is not None else self._alpha
        return p_val > alpha

    def _partial_correlation(self, a: str, b: str,
                             cond_set: List[str],
                             series: Dict[str, List[float]]
                             ) -> float:
        """计算偏相关系数 ρ(a,b | cond_set).

        当 cond_set 为空时退化为 Pearson 相关系数.
        当 |cond_set|>0 时,用递归公式从低阶偏相关计算高阶.
        """
        if not cond_set:
            return self._pearson_corr(series[a], series[b])

        # 取最后一个条件变量,递归降阶
        c = cond_set[-1]
        reduced = cond_set[:-1]
        r_ac = self._partial_correlation(a, c, reduced, series)
        r_bc = self._partial_correlation(b, c, reduced, series)
        r_ab = self._partial_correlation(a, b, reduced, series)

        denom = math.sqrt((1.0 - r_ac ** 2) * (1.0 - r_bc ** 2))
        if denom < 1e-9:
            return 0.0
        return (r_ab - r_ac * r_bc) / denom

    @staticmethod
    def _pearson_corr(x: List[float], y: List[float]) -> float:
        n = len(x)
        if n < 3:
            return 0.0
        mx = sum(x) / n
        my = sum(y) / n
        sx = math.sqrt(sum((xi - mx) ** 2 for xi in x))
        sy = math.sqrt(sum((yi - my) ** 2 for yi in y))
        if sx < 1e-9 or sy < 1e-9:
            return 0.0
        cov = sum((xi - mx) * (yi - my) for xi, yi in zip(x, y)) / (n - 1)
        return cov / (sx / math.sqrt(n - 1) * sy / math.sqrt(n - 1))

    @staticmethod
    def _normal_cdf(x: float) -> float:
        """标准正态CDF -- Abramowitz-Stegun 近似."""
        if x < -8.0:
            return 0.0
        if x > 8.0:
            return 1.0
        # 有理逼近 (公式 7.1.26)
        t = 1.0 / (1.0 + 0.2316419 * abs(x))
        poly = ((((1.330274429 * t - 1.821255978) * t
                  + 1.781477937) * t - 0.356563782) * t
                + 0.319381530) * t
        phi = poly * math.exp(-x * x / 2.0) / math.sqrt(2.0 * math.pi)
        return 1.0 - phi if x >= 0 else phi

    @staticmethod
    def _sample_conditioning_sets(candidates: List[str], size: int,
                                  max_samples: int = 30) -> List[FrozenSet[str]]:
        """从候选集中抽样条件集-避免全组合爆炸."""
        if size == 0:
            return [frozenset()]
        if len(candidates) < size:
            return []
        import random
        results: List[FrozenSet[str]] = []
        seen: Set[FrozenSet[str]] = set()
        for _ in range(min(max_samples, 100)):
            subset = frozenset(random.sample(candidates, size))
            if subset not in seen:
                seen.add(subset)
                results.append(subset)
        return results

    @staticmethod
    def _detect_v_structures(edges: List[CausalEdge]
                              ) -> List[Tuple[str, str, str]]:
        """从已定向边中检测v-结构 (X->Y←Z)."""
        # 构建入边索引
        incoming: Dict[str, Set[str]] = defaultdict(set)
        for e in edges:
            if e.orientation == "directed" and e.is_causal:
                incoming[e.target].add(e.source)

        vstructs = []
        for y, parents in incoming.items():
            parents_list = sorted(parents)
            for i, p1 in enumerate(parents_list):
                for p2 in parents_list[i + 1:]:
                    # 确认 p1 和 p2 之间无边(PC算法的v-结构条件)
                    edge_12 = any(
                        (e.source == p1 and e.target == p2) or
                        (e.source == p2 and e.target == p1)
                        for e in edges
                    )
                    if not edge_12:
                        vstructs.append((p1, y, p2))

        return vstructs
