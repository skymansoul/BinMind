# CFG拓扑特征提取
#
# 从邻接矩阵提取11维拓扑剖面，作为策略网络的输入
# 所有计算O(N+E)复杂度，适合在线分析

import math
from typing import Dict, List, Tuple
from collections import defaultdict, deque
from dataclasses import dataclass

import numpy as np


@dataclass
class TopologyProfile:
    """图的拓扑特征剖面——策略网络的输入。

    特征选择理由:
      avg_degree: 图密度——影响边丢弃的容忍度上限
      clustering_coeff: 循环体特征——影响子图采样策略
      degree_entropy: 结构异质性——影响特征掩码强度
      leaf_ratio: 直线代码段比例——影响节点丢弃策略
      avg_path_length + diameter: 图尺度——影响子图采样半径
    """
    n_nodes: int
    n_edges: int
    avg_degree: float
    degree_variance: float
    clustering_coeff: float
    avg_path_length: float
    degree_entropy: float
    n_connected_components: int
    leaf_ratio: float
    max_degree: int
    diameter: int

    def to_vector(self) -> np.ndarray:
        return np.array([
            math.log(1 + self.n_nodes),
            math.log(1 + self.n_edges),
            self.avg_degree / 10.0,
            math.log(1 + self.degree_variance),
            self.clustering_coeff,
            min(1.0, self.avg_path_length / 20.0),
            self.degree_entropy,
            math.log(1 + self.n_connected_components),
            self.leaf_ratio,
            min(1.0, self.max_degree / 50.0),
            min(1.0, self.diameter / 30.0),
        ], dtype=np.float64)


class TopologyAnalyzer:
    """从CFG邻接矩阵提取拓扑特征——O(N+E)在线分析"""

    @staticmethod
    def analyze(adjacency: List[List[int]], directed: bool = True) -> TopologyProfile:
        n = len(adjacency)
        if n == 0:
            return TopologyProfile(0, 0, 0.0, 0.0, 0.0, 0.0, 0.0, 0, 0.0, 0, 0)

        degrees = [sum(row) for row in adjacency]
        if directed:
            in_degrees = [sum(adjacency[j][i] for j in range(n)) for i in range(n)]
            all_degrees = [d + in_degrees[i] for i, d in enumerate(degrees)]
        else:
            all_degrees = list(degrees)

        n_edges = sum(degrees)
        avg_deg = n_edges / max(1, n)
        deg_var = float(np.var(all_degrees)) if n > 1 else 0.0

        # 度分布熵
        deg_counts = defaultdict(int)
        for d in all_degrees:
            deg_counts[d] += 1
        total = sum(deg_counts.values())
        deg_entropy = -sum((c/total) * math.log(c/total + 1e-12)
                          for c in deg_counts.values())

        # 聚类系数
        clustering_sum = 0.0
        for i in range(n):
            neighbors = [j for j in range(n) if adjacency[i][j] or adjacency[j][i]]
            k = len(neighbors)
            if k < 2:
                continue
            edges_among = sum(1 for a in neighbors for b in neighbors
                            if a < b and (adjacency[a][b] or adjacency[b][a]))
            clustering_sum += (2.0 * edges_among) / (k * (k - 1))
        clustering_coeff = clustering_sum / max(1, n)

        # 采样路径长度
        paths = TopologyAnalyzer._sample_path_lengths(adjacency, n, min(50, n))
        avg_path = float(np.mean(paths)) if paths else 0.0
        diameter = int(max(paths)) if paths else 0

        components = TopologyAnalyzer._count_components(adjacency, n)
        leaf_count = sum(1 for i in range(n) if degrees[i] <= 1)
        leaf_ratio = leaf_count / n

        return TopologyProfile(
            n_nodes=n, n_edges=n_edges, avg_degree=avg_deg,
            degree_variance=deg_var, clustering_coeff=clustering_coeff,
            avg_path_length=avg_path, degree_entropy=deg_entropy,
            n_connected_components=components, leaf_ratio=leaf_ratio,
            max_degree=max(all_degrees) if all_degrees else 0,
            diameter=diameter,
        )

    @staticmethod
    def _sample_path_lengths(adjacency, n, n_samples=50):
        lengths = []
        sources = np.random.choice(n, size=min(n_samples, n), replace=False)
        for src in sources:
            dist = [n * 2] * n
            dist[src] = 0
            q = deque([src])
            while q:
                u = q.popleft()
                for v in range(n):
                    if adjacency[u][v] and dist[v] > dist[u] + 1:
                        dist[v] = dist[u] + 1
                        q.append(v)
            finite = [d for d in dist if d < n * 2]
            if finite:
                lengths.append(float(np.mean(finite)))
        return lengths

    @staticmethod
    def _count_components(adjacency, n) -> int:
        visited = [False] * n
        components = 0
        for i in range(n):
            if visited[i]:
                continue
            components += 1
            q = deque([i])
            visited[i] = True
            while q:
                u = q.popleft()
                for v in range(n):
                    if not visited[v] and (adjacency[u][v] or adjacency[v][u]):
                        visited[v] = True
                        q.append(v)
        return components
