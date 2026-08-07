"""
谱聚类漏洞家族识别 -- 归一化拉普拉斯特征分解+无监督漏洞分组。

问题：传统CWE分类无法捕捉传播模式的结构差异。

方案：Ng-Jordan-Weiss归一化谱聚类。加权邻接矩阵(边置信度),
归一化拉普拉斯, 特征分解, K-Means在特征空间聚类。Eigengap自动选k。

ref: Ng, Jordan, Weiss. von Luxburg.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class VulnCluster:
    """一个漏洞家族——传播结构相似的节点群。"""
    cluster_id: int
    members: List[str]
    dominant_layer: str        # 该家族的主要平台层
    mean_severity: float
    intra_cluster_density: float  # 簇内边密度（越高越紧密）
    silhouette_score: float = 0.0


class SpectralVulnClusterer:
    """谱聚类漏洞家族识别器。

    用法::

        clusterer = SpectralVulnClusterer(graph)
        clusters = clusterer.cluster(k=3)  # 或 auto_k=True 自动选k
        for c in clusters:
            print(f"Family {c.cluster_id}: {c.members} ({c.dominant_layer})")
    """

    def __init__(self, graph: PropagationGraph):
        self._graph = graph
        self._nodes = list(graph._nodes.keys())
        self._n = len(self._nodes)
        self._idx = {nid: i for i, nid in enumerate(self._nodes)}

    def cluster(self, k: int = 3, auto_k: bool = True,
                max_k: int = 8) -> List[VulnCluster]:
        """执行谱聚类, 返回漏洞家族列表。

        auto_k=True时使用eigengap启发式自动选择k。
        """
        if self._n < 3:
            return [VulnCluster(0, self._nodes, "mixed", 0.5, 1.0)]

        # 1. 构建归一化拉普拉斯
        L_sym = self._build_laplacian()

        # 2. 特征分解 (幂迭代法求前max_k个特征向量)
        k_use = min(max_k, self._n - 1)
        eigenvecs = self._power_iteration(L_sym, k_use + 1)

        # 3. 自动选k (eigengap)
        if auto_k:
            k = self._eigengap_select(eigenvecs, max_k)
        k = max(2, min(k, k_use))

        # 4. 取前k个特征向量做K-Means
        embeddings = self._extract_embeddings(eigenvecs, k)
        labels = self._kmeans(embeddings, k)

        # 5. 构建聚类结果
        return self._build_clusters(labels, k)

    def _build_laplacian(self) -> List[List[float]]:
        """构建传播加权归一化拉普拉斯。

        创新：边权重=置信度×层跨度因子×下游影响力。
        纯置信度无法区分\"同层高置信边\"与\"跨层结构关键边\"。
        层跨度因子使跨越多层的边获得更高权重(结构上更显著)。
        下游影响力使连接高影响力节点的边在聚类中更重要。
        """
        n = self._n
        W = [[0.0] * n for _ in range(n)]
        deg = [0.0] * n

        # 预计算下游影响力：每节点的出度(对数尺度归一化)
        downstream_impact = {}
        for nid in self._nodes:
            outdeg = len(self._graph._adj.get(nid, []))
            downstream_impact[nid] = math.log1p(outdeg) / math.log1p(max(n, 1))

        for i, src in enumerate(self._nodes):
            src_node = self._graph._nodes.get(src)
            for j, tgt in enumerate(self._nodes):
                if i == j:
                    continue
                tgt_node = self._graph._nodes.get(tgt)
                edge_fwd = self._graph._edges.get((src, tgt))
                edge_rev = self._graph._edges.get((tgt, src))
                w = 0.0
                if edge_fwd:
                    w = max(w, edge_fwd.confidence)
                if edge_rev:
                    w = max(w, edge_rev.confidence)
                if w > 0 and src_node and tgt_node:
                    # 层跨度因子: |layer_diff|/5 + 0.2, 范围[0.2, 1.2]
                    layer_diff = abs(src_node.layer.value - tgt_node.layer.value)
                    layer_factor = 0.2 + layer_diff / 5.0
                    # 下游影响力: 目标节点的结构重要性
                    tgt_impact = downstream_impact.get(tgt, 0.5)
                    w = w * (0.5 + 0.25 * layer_factor + 0.25 * tgt_impact)
                    W[i][j] = w
                    deg[i] += w

        # L_sym = I - D^{-1/2}*W*D^{-1/2}
        L = [[0.0] * n for _ in range(n)]
        for i in range(n):
            for j in range(n):
                if i == j:
                    L[i][j] = 1.0
                    if deg[i] > 1e-9 and W[i][j] > 0:
                        L[i][j] -= W[i][j] / deg[i]
                elif deg[i] > 1e-9 and deg[j] > 1e-9 and W[i][j] > 0:
                    L[i][j] = -W[i][j] / math.sqrt(deg[i] * deg[j])

        return L

    def _power_iteration(self, A: List[List[float]],
                         k: int, n_iter: int = 100
                         ) -> List[Tuple[float, List[float]]]:
        """幂迭代+收缩法求A的k个最小特征值/特征向量。

        对 (2I - A) 做幂迭代: 最小特征值映射为最大特征值。
        """
        n = len(A)
        # 构造B = 2I - A, 使最小特征值变为最大
        B = [[-A[i][j] for j in range(n)] for i in range(n)]
        for i in range(n):
            B[i][i] += 2.0

        eigens = []
        for _ in range(k):
            # 随机初始化
            import random
            v = [random.random() for _ in range(n)]
            norm = math.sqrt(sum(x*x for x in v))
            v = [x / max(norm, 1e-9) for x in v]

            for _ in range(n_iter):
                # 收缩: 减去已找到的特征向量方向
                v_clean = list(v)
                for _, evec in eigens:
                    dot = sum(evec[i] * v_clean[i] for i in range(n))
                    v_clean = [v_clean[i] - dot * evec[i] for i in range(n)]

                # 矩阵乘: v = B * v_clean
                new_v = [sum(B[i][j] * v_clean[j] for j in range(n))
                        for i in range(n)]
                # 归一化
                nrm = math.sqrt(sum(x*x for x in new_v))
                if nrm < 1e-9:
                    break
                new_v = [x / nrm for x in new_v]
                # 收敛检查
                diff = sum(abs(new_v[i] - v[i]) for i in range(n))
                v = new_v
                if diff < 1e-6:
                    break

            # Rayleigh商求特征值
            v_clean = list(v)
            for _, evec in eigens:
                dot = sum(evec[i] * v_clean[i] for i in range(n))
                v_clean = [v_clean[i] - dot * evec[i] for i in range(n)]
            Av = [sum(A[i][j] * v_clean[j] for j in range(n)) for i in range(n)]
            lam = sum(v_clean[i] * Av[i] for i in range(n))
            eigens.append((lam, v))

        # 转换回A的原始特征值(从2I-A映射回去)
        # eig(A) = 2 - eig(2I-A)
        return [(2.0 - lam, evec) for lam, evec in eigens]

    def _eigengap_select(self, eigens: List[Tuple[float, List[float]]],
                         max_k: int) -> int:
        """Eigengap启发式选k: 找相邻特征值差最大的位置。"""
        vals = sorted([lam for lam, _ in eigens])
        best_k = 2
        best_gap = 0.0
        for i in range(1, min(len(vals) - 1, max_k)):
            gap = vals[i] - vals[i - 1]
            if gap > best_gap:
                best_gap = gap
                best_k = i + 1
        return best_k

    def _extract_embeddings(self, eigens: List[Tuple[float, List[float]]],
                            k: int) -> List[List[float]]:
        """取前k个特征向量构建节点嵌入。"""
        sorted_ev = sorted(eigens, key=lambda x: x[0])
        vecs = [evec for _, evec in sorted_ev[:k]]

        embeddings = []
        for i in range(self._n):
            emb = [vecs[j][i] for j in range(k)]
            norm = math.sqrt(sum(x*x for x in emb))
            if norm > 1e-9:
                emb = [x / norm for x in emb]
            embeddings.append(emb)
        return embeddings

    def _kmeans(self, points: List[List[float]], k: int,
                max_iter: int = 50) -> List[int]:
        """标准K-Means聚类。"""
        n = len(points)
        if n <= k:
            return list(range(n)) + [0] * (k - n)

        # K-Means++ 初始化
        import random
        centroids = [points[random.randint(0, n - 1)][:]]
        for _ in range(k - 1):
            dists = [min(sum((p[j] - c[j])**2 for j in range(len(p)))
                        for c in centroids) for p in points]
            total = sum(dists)
            r = random.random() * total
            cum = 0.0
            for i, d in enumerate(dists):
                cum += d
                if cum >= r:
                    centroids.append(points[i][:])
                    break

        labels = [0] * n
        for _ in range(max_iter):
            # 分配
            changed = False
            for i, p in enumerate(points):
                best_l = 0
                best_d = float('inf')
                for l, c in enumerate(centroids):
                    d = sum((p[j] - c[j])**2 for j in range(len(p)))
                    if d < best_d:
                        best_d = d
                        best_l = l
                if labels[i] != best_l:
                    changed = True
                    labels[i] = best_l
            if not changed:
                break
            # 更新质心
            counts = [0] * k
            new_c = [[0.0]*len(points[0]) for _ in range(k)]
            for i, l in enumerate(labels):
                counts[l] += 1
                for j in range(len(points[i])):
                    new_c[l][j] += points[i][j]
            for l in range(k):
                if counts[l] > 0:
                    centroids[l] = [x / counts[l] for x in new_c[l]]

        return labels

    def _build_clusters(self, labels: List[int], k: int) -> List[VulnCluster]:
        """从K-Means标签构建VulnCluster对象。"""
        groups = defaultdict(list)
        for i, nid in enumerate(self._nodes):
            groups[labels[i]].append(nid)

        clusters = []
        for cid, members in groups.items():
            layers = defaultdict(int)
            sevs = []
            for nid in members:
                node = self._graph._nodes.get(nid)
                if node:
                    layers[node.layer.name] += 1
                    sevs.append(node.severity)
            dominant = max(layers, key=layers.get) if layers else "mixed"
            mean_sev = sum(sevs) / max(len(sevs), 1)

            # 簇内密度
            intra_edges = 0
            for i, a in enumerate(members):
                for b in members[i+1:]:
                    if (a, b) in self._graph._edges or (b, a) in self._graph._edges:
                        intra_edges += 1
            max_edges = len(members) * (len(members) - 1) / 2.0
            density = intra_edges / max(max_edges, 1)

            clusters.append(VulnCluster(
                cluster_id=cid, members=members,
                dominant_layer=dominant, mean_severity=round(mean_sev, 3),
                intra_cluster_density=round(density, 3),
            ))

        clusters.sort(key=lambda c: len(c.members), reverse=True)
        return clusters
