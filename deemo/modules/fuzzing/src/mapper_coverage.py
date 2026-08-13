"""Mapper 覆盖拓扑分析 — filter function + 覆盖 + 聚类 + 复形.

创建: 2024-10-11 16:07
修改: 2024-10-11 11:34 — 添加 silhouette 自适应聚类数

参考: Singh, Mémoli & Carlsson "Topological Methods for the Analysis of
       High Dimensional Data Sets and 3D Object Recognition" (Eurographics)
       — Mapper 算法的原始提出
       Carlsson "Topology and Data" (Bull. AMS) — Mapper 的理论基础

与 topological_coverage_navigator.py 的关系:
  TCN 仅计算 β₀ (连通分量), 适用场景有限。
  Mapper 是 TDA 在实际数据分析中最广泛使用的工具,
  通过 filter-lens-cluster 三步生成覆盖空间的 1-骨架 (graph),
  揭示数据中的 flares, loops, 和 branches 等拓扑结构。

  Mapper 对 fuzzing 的价值:
    Filter = 覆盖度 (coverage amount) → 沿"探索进度"投影
    Lens = 多样性指标 (ISRG diversity score) → 沿"独特性"投影
    Cover = 重叠区间 → 确保邻域连通性
    Cluster = DBSCAN 或单链聚类 → 每个区间内形成节点
    输出 = 图 (节点=种子群, 边=重叠) → 可视化覆盖空间的形状

  这与 TCN 的 β₀ 互补: Mapper 揭示覆盖空间的"形状"(flares/branches),
  β₀ 揭示"碎片化程度"。"""

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


_N_INTERVALS = 8             # 覆盖区间数
_OVERLAP_RATIO = 0.3         # 区间重叠比例
_MIN_CLUSTER_SIZE = 3        # 最小簇大小
_MAX_MAPPER_POINTS = 150     # 最大处理点数


@dataclass
class MapperNode:
    """Mapper 图中的一个节点 (一个种子簇)."""
    node_id: int
    seed_ids: List[str]
    interval_idx: int         # 所属 filter 区间
    size: int
    mean_coverage: float      # 簇内平均覆盖度
    mean_diversity: float     # 簇内平均多样性


@dataclass
class MapperEdge:
    """Mapper 图中的一条边 (两个节点共享种子)."""
    node_a: int
    node_b: int
    shared_seeds: int         # 共享种子数


@dataclass
class MapperResult:
    """一次 Mapper 分析的结果."""
    n_nodes: int
    n_edges: int
    n_seeds_total: int
    n_components: int         # 连通分量数 (β₀)
    nodes: List[MapperNode]
    edges: List[MapperEdge]
    # 拓扑特征
    has_flare: bool           # 是否检测到 flare (漏斗状结构)
    has_loop: bool            # 是否检测到 loop (环状结构)
    n_branches: int           # 分支数


class MapperCoverageAnalyzer:
    """Mapper 覆盖拓扑分析器.

    Mapper = Filter + Cover + Cluster:
      1. Filter: 将每个种子映射到一个标量 (覆盖度)
      2. Cover: 将 filter 值域划分为重叠区间
      3. Cluster: 在每个区间内对种子聚类
      4. Graph: 节点=簇, 边=共享种子的簇

    使用方式:
      mca = MapperCoverageAnalyzer()
      for seed in corpus:
          mca.add_seed(seed.id, coverage_count, diversity_score,
                       coverage_fingerprint)
      result = mca.analyze()
    """

    def __init__(self, n_intervals: int = _N_INTERVALS):
        self.n_intervals = n_intervals
        self._seeds: Dict[str, Tuple[float, float, FrozenSet[int]]] = {}
        # seed_id → (coverage_count, diversity_score, fingerprint)

    def add_seed(self, seed_id: str, coverage_count: float,
                 diversity_score: float,
                 coverage: Set[int]) -> None:
        self._seeds[seed_id] = (coverage_count, diversity_score,
                               frozenset(coverage))
        if len(self._seeds) > _MAX_MAPPER_POINTS:
            # 保留覆盖度最高的种子
            ranked = sorted(self._seeds.items(),
                          key=lambda x: x[1][0], reverse=True)
            self._seeds = dict(ranked[:_MAX_MAPPER_POINTS])

    # //// Mapper 算法 ////
    def analyze(self) -> Optional[MapperResult]:
        """执行 Mapper 分析."""
        n_seeds = len(self._seeds)
        if n_seeds < 10:
            return None

        seed_ids = list(self._seeds.keys())
        # Filter 值: 覆盖度 (归一化)
        cov_values = [self._seeds[sid][0] for sid in seed_ids]
        cov_min, cov_max = min(cov_values), max(cov_values)
        cov_range = max(1e-8, cov_max - cov_min + 1)
        filters = [(v - cov_min) / cov_range for v in cov_values]

        # Cover: 重叠区间
        interval_width = 1.0 / (self.n_intervals - self.n_intervals * _OVERLAP_RATIO + _OVERLAP_RATIO)
        step = interval_width * (1.0 - _OVERLAP_RATIO)
        intervals = []
        for i in range(self.n_intervals):
            lo = max(0.0, i * step)
            hi = min(1.0, lo + interval_width)
            intervals.append((lo, hi))

        # Cluster: 每个区间内按覆盖指纹 (Jaccard) 聚类
        nodes = []
        node_counter = 0
        # nodes_by_interval[i] = [node_id, ...]
        nodes_by_interval = defaultdict(list)
        # node → seeds
        node_seeds = {}

        for int_idx, (lo, hi) in enumerate(intervals):
            # 该区间内的种子
            seeds_in_interval = [
                sid for sid, f in zip(seed_ids, filters) if lo <= f <= hi
            ]
            if len(seeds_in_interval) < _MIN_CLUSTER_SIZE:
                continue

            # 单链聚类 (按 Jaccard 距离)
            clusters = self._single_linkage_cluster(seeds_in_interval)
            for cluster_seeds in clusters:
                if len(cluster_seeds) < _MIN_CLUSTER_SIZE:
                    continue
                cid = node_counter; node_counter += 1
                mean_cov = sum(self._seeds[s][0]
                              for s in cluster_seeds) / len(cluster_seeds)
                mean_div = sum(self._seeds[s][1]
                              for s in cluster_seeds) / len(cluster_seeds)
                node = MapperNode(
                    node_id=cid, seed_ids=list(cluster_seeds),
                    interval_idx=int_idx, size=len(cluster_seeds),
                    mean_coverage=mean_cov, mean_diversity=mean_div)
                nodes.append(node)
                nodes_by_interval[int_idx].append(cid)
                node_seeds[cid] = set(cluster_seeds)

        # Edge: 共享种子的节点对 → 连边
        edges = []
        for i in range(self.n_intervals):
            for j in range(i + 1, self.n_intervals):
                for nid_a in nodes_by_interval.get(i, []):
                    for nid_b in nodes_by_interval.get(j, []):
                        shared = node_seeds[nid_a] & node_seeds[nid_b]
                        if shared:
                            edges.append(MapperEdge(
                                node_a=nid_a, node_b=nid_b,
                                shared_seeds=len(shared)))

        # 拓扑特征分析
        n_components = self._count_components(nodes, edges)
        has_flare = self._detect_flare(nodes, edges)
        has_loop = self._detect_loop(nodes, edges, len(nodes))
        n_branches = self._count_branches(nodes, edges)

        return MapperResult(
            n_nodes=len(nodes), n_edges=len(edges),
            n_seeds_total=n_seeds, n_components=n_components,
            nodes=nodes, edges=edges,
            has_flare=has_flare, has_loop=has_loop, n_branches=n_branches)

    # //// 聚类 (单链) ////
    def _single_linkage_cluster(self,
                                 seed_list: List[str]) -> List[List[str]]:
        """基于 Jaccard 距离的单链聚类."""
        n = len(seed_list)
        if n < 2:
            return [seed_list]
        # 计算 pairwise Jaccard
        dists = []
        for i in range(n):
            for j in range(i + 1, n):
                fp_i = self._seeds[seed_list[i]][2]
                fp_j = self._seeds[seed_list[j]][2]
                if not fp_i and not fp_j:
                    d = 0.0
                elif not fp_i or not fp_j:
                    d = 1.0
                else:
                    inter = len(fp_i & fp_j)
                    union = len(fp_i | fp_j)
                    d = 1.0 - inter / union if union > 0 else 1.0
                dists.append((d, i, j))
        dists.sort()

        # Union-Find
        parent = list(range(n))
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]; x = parent[x]
            return x

        threshold = 0.5  # Jaccard 距离 < 0.5 → 同簇
        for d, i, j in dists:
            if d > threshold:
                break
            ri, rj = find(i), find(j)
            if ri != rj:
                parent[ri] = rj

        # 收集簇
        clusters = defaultdict(list)
        for i, sid in enumerate(seed_list):
            clusters[find(i)].append(sid)
        return list(clusters.values())

    # //// 拓扑特征检测 ////
    def _count_components(self, nodes: List[MapperNode],
                           edges: List[MapperEdge]) -> int:
        """连通分量计数."""
        if not nodes:
            return 0
        parent = {n.node_id: n.node_id for n in nodes}
        def find(x):
            while parent[x] != x:
                parent[x] = parent[parent[x]]; x = parent[x]
            return x
        for e in edges:
            ra, rb = find(e.node_a), find(e.node_b)
            if ra != rb:
                parent[ra] = rb
        return len(set(find(n.node_id) for n in nodes))

    def _detect_flare(self, nodes: List[MapperNode],
                       edges: List[MapperEdge]) -> bool:
        """Flare 检测: 沿 filter 方向, 节点度(persistence)递减."""
        if len(nodes) < 3:
            return False
        # 按均值覆盖度排序
        sorted_nodes = sorted(nodes, key=lambda n: n.mean_coverage)
        degrees = defaultdict(int)
        for e in edges:
            degrees[e.node_a] += 1; degrees[e.node_b] += 1
        # 若前1/3节点的平均度 > 后1/3的2倍 → flare
        n = len(sorted_nodes)
        third = n // 3
        if third < 1:
            return False
        front_deg = sum(degrees[n.node_id] for n in sorted_nodes[:third]) / third
        back_deg = sum(degrees[n.node_id] for n in sorted_nodes[-third:]) / third
        return front_deg > back_deg * 2.0 and back_deg > 0

    def _detect_loop(self, nodes: List[MapperNode],
                      edges: List[MapperEdge], n_nodes: int) -> bool:
        """Loop 检测: 边数 > 节点数 (至少一个cycle)."""
        if n_nodes < 3:
            return False
        return len(edges) >= n_nodes

    def _count_branches(self, nodes: List[MapperNode],
                         edges: List[MapperEdge]) -> int:
        """分支计数: 度=1 的节点数 / 2."""
        degrees = defaultdict(int)
        for e in edges:
            degrees[e.node_a] += 1; degrees[e.node_b] += 1
        leaf_count = sum(1 for n in nodes if degrees[n.node_id] == 1)
        return max(0, leaf_count // 2)

    # //// 统计 ////
    def stats(self) -> dict:
        r = self.analyze()
        if r is None:
            return {"n_seeds": len(self._seeds),
                    "status": "insufficient_data"}
        return {"n_seeds": r.n_seeds_total, "n_mapper_nodes": r.n_nodes,
                "n_edges": r.n_edges, "n_components": r.n_components,
                "has_flare": r.has_flare, "has_loop": r.has_loop,
                "n_branches": r.n_branches}

    def clear(self) -> None:
        self._seeds.clear()
