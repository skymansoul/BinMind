"""
传播图持续同调指纹 — 用拓扑数据分析提取漏洞传播图的稳定结构签名。

核心思路：
  传播图上的每条边有置信度 c(e)∈[0,1]。以阈值 ε 从1.0递减至0.0
  逐条加入边，构成 Vietoris-Rips 风格的滤流（filtration）。
  在滤流过程中追踪：
    - 0维同调（连通分量）：分量何时合并（death of the younger component）
    - 1维同调（环）：环何时形成（birth）和填满（death）

持续同调的关键性质：
  持续图（persistence diagram）对边置信度的小扰动是稳定的（Bottleneck稳定性定理）。
  这意味着两个传播图的持续图之间的 bottleneck 距离是图结构差异的鲁棒度量。
  → 用于漏洞传播生态系统的指纹比对：同一固件家族的不同版本应有相似的持续图。

为何不用现成的 GUDHI/Ripser 库：
  1. 外部依赖对管线集成不友好
  2. 传播图是小型加权有向图（通常 <500 节点），自定义 O(N²) 算法可接受
  3. 需要对有向边做非对称处理——标准 Rips 复形假设对称距离

ref: Edelsbrunner & Harer (2010) "Computational Topology" — 持续同调理论。
ref: Snopov & Golubinskiy (arXiv:2410.03470) — 持续同调用于漏洞检测，
     但仅处理代码BERT注意力矩阵，不涉及传播图拓扑指纹。
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .propagation_graph import PlatformLayer, PropagationGraph


@dataclass
class PersistencePoint:
    """持续图中的一个点 (birth, death, dimension)。diagonal点满足 birth=death。"""
    birth: float
    death: float
    dimension: int

    @property
    def persistence(self) -> float:
        return abs(self.death - self.birth)

    @property
    def is_essential(self) -> bool:
        """death=inf 表示该特征在滤流终点仍存活（essential class）。"""
        return math.isinf(self.death)


@dataclass
class PersistenceDiagram:
    """持续图 — 一组 (birth, death) 点，按维数分组。"""
    points: List[PersistencePoint] = field(default_factory=list)
    graph_id: str = ""

    def points_by_dim(self, dim: int) -> List[PersistencePoint]:
        return [p for p in self.points if p.dimension == dim]

    @property
    def total_persistence(self) -> float:
        return sum(p.persistence for p in self.points if not p.is_essential)

    @property
    def essential_count(self) -> int:
        return sum(1 for p in self.points if p.is_essential)


def bottleneck_distance(diag_a: PersistenceDiagram,
                        diag_b: PersistenceDiagram,
                        dim: int = 0) -> float:
    """计算两个持续图在指定维数上的瓶颈距离。

    匹配算法：贪心最近邻（非精确——精确瓶颈距离需要二分图匹配，
    Hungarian算法 O(N³)，对小型持续图不划算）。
    实现 Wasserstein-∞ 距离的简化版本。
    """
    pts_a = [p for p in diag_a.points_by_dim(dim) if not p.is_essential]
    pts_b = [p for p in diag_b.points_by_dim(dim) if not p.is_essential]

    if not pts_a and not pts_b:
        return 0.0
    if not pts_a or not pts_b:
        return max((p.persistence for p in (pts_a or pts_b)), default=0.0)

    # 贪心匹配：每个A点匹配最近的B点（L∞距离）
    matched_b: Set[int] = set()
    max_dist = 0.0

    for pa in pts_a:
        best_j = -1
        best_d = float('inf')
        for j, pb in enumerate(pts_b):
            if j in matched_b:
                continue
            d = max(abs(pa.birth - pb.birth), abs(pa.death - pb.death))
            if d < best_d:
                best_d = d
                best_j = j
        if best_j >= 0:
            matched_b.add(best_j)
            max_dist = max(max_dist, best_d)
        else:
            max_dist = max(max_dist, pa.persistence / 2.0)

    # 未匹配的B点贡献半持久性
    for j, pb in enumerate(pts_b):
        if j not in matched_b:
            max_dist = max(max_dist, pb.persistence / 2.0)

    return max_dist


class PropagationHomologyAnalyzer:
    """传播图的持续同调分析器。

    用法::

        graph = PropagationGraph()
        # ... 填充 ...
        analyzer = PropagationHomologyAnalyzer()
        diagram = analyzer.compute_persistence(graph)
        print(f"Total persistence: {diagram.total_persistence:.4f}")
        # 比对两个图
        dist = bottleneck_distance(diagram1, diagram2)
    """

    def __init__(self):
        self._last_diagram: Optional[PersistenceDiagram] = None

    def compute_persistence(self, graph: PropagationGraph,
                            graph_id: str = "") -> PersistenceDiagram:
        """对传播图计算0维和1维持续同调。

        算法概要：
          0维：按置信度降序加入边，Union-Find追踪分量合并。
               合并时，低置信度的分量"死亡"（death=当前置信度）。
               最高置信度的分量存活至最后（death=inf）。
          1维：在0维滤流的生成树基础上，每条非树边产生一个环。
               环的birth=该边的置信度，death=环被更高置信度边填充时的置信度。
        """
        nodes = list(graph._nodes.keys())
        n = len(nodes)
        if n == 0:
            return PersistenceDiagram(points=[], graph_id=graph_id)

        # 边排序：按置信度降序（从高到低加入）
        edges: List[Tuple[str, str, float]] = []
        for (src, tgt), edge in graph._edges.items():
            edges.append((src, tgt, edge.confidence))
        edges.sort(key=lambda x: x[2], reverse=True)

        # 节点索引映射
        idx_map = {nid: i for i, nid in enumerate(nodes)}
        points: List[PersistencePoint] = []

        # --- 0维：Union-Find ---
        parent = list(range(n))
        birth_time = [0.0] * n  # 分量诞生时的置信度（最高边）
        active = [True] * n

        def find(x: int) -> int:
            while parent[x] != x:
                parent[x] = parent[parent[x]]
                x = parent[x]
            return x

        def union(x: int, y: int, conf: float) -> Optional[PersistencePoint]:
            rx, ry = find(x), find(y)
            if rx == ry:
                return None
            # 按birth_time大小决定谁存活（elder rule）
            if birth_time[rx] < birth_time[ry]:
                rx, ry = ry, rx
            parent[ry] = rx
            # 被合并的分量死亡
            dead_pt = PersistencePoint(birth=birth_time[ry], death=conf, dimension=0)
            birth_time[rx] = max(birth_time[rx], birth_time[ry])
            return dead_pt

        for src, tgt, conf in edges:
            si, ti = idx_map.get(src), idx_map.get(tgt)
            if si is None or ti is None:
                continue
            pt = union(si, ti, conf)
            if pt is not None:
                points.append(pt)

        # 存活分量的 death=inf
        roots = set(find(i) for i in range(n))
        for r in roots:
            points.append(PersistencePoint(birth=birth_time[r], death=float('inf'),
                                           dimension=0))

        # --- 1维：生成树 + 非树边 ---
        # 重新做一次 Union-Find，标记生成树边
        parent2 = list(range(n))
        tree_edges: Set[Tuple[int, int]] = set()

        def find2(x: int) -> int:
            while parent2[x] != x:
                parent2[x] = parent2[parent2[x]]
                x = parent2[x]
            return x

        for src, tgt, conf in edges:
            si, ti = idx_map.get(src), idx_map.get(tgt)
            if si is None or ti is None:
                continue
            ri, rj = find2(si), find2(ti)
            if ri != rj:
                parent2[ri] = rj
                tree_edges.add((min(si, ti), max(si, ti)))

        # 非树边产生1维特征——birth=边置信度，death由环中最低置信度决定
        # 此处使用简化近似：非树边的 death 取其对偶生成树边的最小置信度
        edge_conf_map: Dict[Tuple[int, int], float] = {}
        for src, tgt, conf in edges:
            si, ti = idx_map.get(src), idx_map.get(tgt)
            if si is not None and ti is not None:
                key = (min(si, ti), max(si, ti))
                edge_conf_map[key] = conf

        for src, tgt, conf in edges:
            si, ti = idx_map.get(src), idx_map.get(tgt)
            if si is None or ti is None:
                continue
            key = (min(si, ti), max(si, ti))
            if key not in tree_edges:
                # 非树边→环的birth=此边置信度
                # death简化为环上最小置信度（取生成树路径上最小置信度）
                # 简化处理：取0.0作为下界（完整实现需要路径追踪）
                points.append(PersistencePoint(
                    birth=conf, death=0.0, dimension=1,
                ))

        self._last_diagram = PersistenceDiagram(points=points, graph_id=graph_id)
        return self._last_diagram

    def fingerprint(self, graph: PropagationGraph,
                    graph_id: str = "",
                    n_bins: int = 20) -> List[float]:
        """将持续图向量化为固定长度的指纹向量——用于快速比对。

        将0维特征按 (birth, persistence) 分桶，生成直方图。
        持久性取对数——大幅差异压缩为小范围变化，小差异放大。
        """
        diagram = self.compute_persistence(graph, graph_id)
        pts_0 = [p for p in diagram.points_by_dim(0) if not p.is_essential]
        if not pts_0:
            return [0.0] * n_bins

        births = [p.birth for p in pts_0]
        persists = [math.log1p(p.persistence) for p in pts_0]

        birth_min, birth_max = min(births), max(births)
        birth_range = max(birth_max - birth_min, 0.01)
        pers_min, pers_max = min(persists), max(persists)
        pers_range = max(pers_max - pers_min, 0.01)

        # 2D 直方图展平
        side = int(math.sqrt(n_bins))
        if side * side < n_bins:
            side += 1
        hist = [0.0] * (side * side)
        for b, p in zip(births, persists):
            bi = min(int((b - birth_min) / birth_range * side), side - 1)
            pi = min(int((p - pers_min) / pers_range * side), side - 1)
            hist[bi * side + pi] += 1.0

        # L2 归一化
        norm = math.sqrt(sum(h * h for h in hist))
        if norm > 0:
            hist = [h / norm for h in hist]

        return hist[:n_bins]

    def compare_graphs(self, g1: PropagationGraph, g2: PropagationGraph,
                       id1: str = "A", id2: str = "B") -> Dict[str, float]:
        """比较两个传播图的拓扑相似性——返回多种距离度量。"""
        d1 = self.compute_persistence(g1, id1)
        d2 = self.compute_persistence(g2, id2)

        fp1 = self.fingerprint(g1, id1)
        fp2 = self.fingerprint(g2, id2)

        cos_sim = sum(a * b for a, b in zip(fp1, fp2))
        bneck_0 = bottleneck_distance(d1, d2, dim=0)
        tp_diff = abs(d1.total_persistence - d2.total_persistence)

        return {
            "bottleneck_dim0": round(bneck_0, 4),
            "cosine_similarity": round(cos_sim, 4),
            "total_persistence_diff": round(tp_diff, 4),
            "essential_diff": abs(d1.essential_count - d2.essential_count),
        }
