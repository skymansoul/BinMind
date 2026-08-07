# 图数据增强策略集 — 用于对比学习的图结构/节点特征扰动
# GraphCL 的四种增强 +
# GeoMix 的几何感知Mixup
# BEGA 的重力感知边丢弃
# 核心: 保留语义不变性的前提下生成同一图的不同视图

from __future__ import annotations
import random
import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)


class AugmentKind(Enum):
    NODE_DROP = 'node_drop'
    EDGE_PERTURB = 'edge_perturb'
    FEATURE_MASK = 'feature_mask'
    SUBGRAPH_SAMPLE = 'subgraph_sample'
    ATTR_SHUFFLE = 'attr_shuffle'
    GEOMIX = 'geomix'
    DEGREE_PRESERVING = 'degree_preserving'
    IDENTITY = 'identity'


@dataclass
class AugmentConfig:
    node_drop_p: float = 0.15
    edge_add_p: float = 0.05
    edge_del_p: float = 0.15
    feat_mask_p: float = 0.20
    subgraph_ratio: float = 0.70
    geomix_alpha: float = 0.40
    attr_shuffle_p: float = 0.10


@dataclass
class GraphView:
    """增强后的图视图"""
    node_features: List[List[float]]
    adjacency: List[List[int]]
    edge_types: Optional[List[Tuple[int, int, str]]] = None
    augmented_by: List[AugmentKind] = None
    node_mapping: Optional[Dict[int, int]] = None  # 原始->新索引映射

    def __post_init__(self):
        if self.augmented_by is None:
            self.augmented_by = []


# 增强策略实现

class GraphAugmenter:

    def __init__(self, cfg: AugmentConfig = None):
        self.cfg = cfg or AugmentConfig()
        self._rng = random.Random(hash('graph_aug') & 0x7FFFFFFF)

    def augment(self, graph: GraphView,
                kind: AugmentKind = AugmentKind.IDENTITY) -> GraphView:
        """应用单一增强策略"""
        dispatcher = {
            AugmentKind.NODE_DROP: self._aug_node_drop,
            AugmentKind.EDGE_PERTURB: self._aug_edge_perturb,
            AugmentKind.FEATURE_MASK: self._aug_feature_mask,
            AugmentKind.SUBGRAPH_SAMPLE: self._aug_subgraph,
            AugmentKind.GEOMIX: self._aug_geomix,
            AugmentKind.ATTR_SHUFFLE: self._aug_attr_shuffle,
            AugmentKind.DEGREE_PRESERVING: self._aug_degree_preserving,
            AugmentKind.IDENTITY: lambda g: g,
        }
        func = dispatcher.get(kind, lambda g: g)
        result = func(graph)
        result.augmented_by = (graph.augmented_by or []) + [kind]
        return result

    def augment_pair(self, graph: GraphView) -> Tuple[GraphView, GraphView]:
        """生成一对增强视图 (用于对比学习)

        GraphCL风格: 随机选择两种增强策略组合
        """
        # 随机选择2种不同的增强 (不含IDENTITY)
        candidates = [AugmentKind.NODE_DROP, AugmentKind.EDGE_PERTURB,
                      AugmentKind.FEATURE_MASK, AugmentKind.SUBGRAPH_SAMPLE,
                      AugmentKind.ATTR_SHUFFLE]
        k1, k2 = random.sample(candidates, 2)
        view1 = self.augment(graph, k1)
        view2 = self.augment(graph, k2)
        return view1, view2

    def _aug_node_drop(self, g: GraphView) -> GraphView:
        """节点丢弃 (保留桥节点以避免图断裂)

        GraphCL的方法: 随机丢弃节点及其关联边。
        额外保护: degree >= 3的节点不丢弃 (避免破坏图连通性)
        """
        N = len(g.node_features)
        adj = g.adjacency

        # 计算每个节点的度
        degrees = [len(adj[i]) if i < len(adj) else 0 for i in range(N)]

        # 标记保留的节点 (度>=3 或 随机保留)
        keep = [False] * N
        for i in range(N):
            if degrees[i] >= 3:
                keep[i] = True
            elif random.random() > self.cfg.node_drop_p:
                keep[i] = True

        # 确保至少保留一个节点
        if not any(keep):
            keep[random.randint(0, N - 1)] = True

        # 重映射索引
        old_to_new = {}
        new_idx = 0
        for i in range(N):
            if keep[i]:
                old_to_new[i] = new_idx
                new_idx += 1

        # 重建特征和邻接表
        new_features = [g.node_features[i] for i in range(N) if keep[i]]
        new_adj: List[List[int]] = [[] for _ in range(len(new_features))]

        for i in range(N):
            if not keep[i]:
                continue
            ni = old_to_new[i]
            for j in adj[i]:
                if keep[j]:
                    new_adj[ni].append(old_to_new[j])

        return GraphView(
            node_features=new_features,
            adjacency=new_adj,
            node_mapping=old_to_new,
        )

    def _aug_edge_perturb(self, g: GraphView) -> GraphView:
        """边扰动 (BEGA风格重力感知)

        BEGA [Rong et al.]: w_uv = 1/max(deg(u), deg(v))
        高权重边(低度节点间的边)更容易被保留
        """
        N = len(g.node_features)
        adj = g.adjacency
        degrees = [len(adj[i]) if i < len(adj) else 0 for i in range(N)]

        new_adj: List[Set[int]] = [set() for _ in range(N)]

        for i in range(N):
            for j in adj[i]:
                if j >= N:
                    continue
                # 重力权重: 低度节点间的边更重要
                gravity = 1.0 / max(max(degrees[i], degrees[j]), 1)
                # 删除概率与重力成反比
                del_prob = self.cfg.edge_del_p * (1.0 - gravity)
                if random.random() > del_prob:
                    new_adj[i].add(j)

            # 添加随机边
            if self.cfg.edge_add_p > 0:
                n_add = max(1, int(N * self.cfg.edge_add_p))
                candidates = [k for k in range(N) if k != i and k not in new_adj[i]]
                for k in random.sample(candidates, min(n_add, len(candidates))):
                    new_adj[i].add(k)

        return GraphView(
            node_features=[f[:] for f in g.node_features],
            adjacency=[list(s) for s in new_adj],
        )

    def _aug_feature_mask(self, g: GraphView) -> GraphView:
        """节点特征掩码 — 随机置零部分特征维度"""
        new_features = []
        for feat in g.node_features:
            d = len(feat)
            new_feat = feat[:]
            for j in range(d):
                if random.random() < self.cfg.feat_mask_p:
                    new_feat[j] = 0.0
            new_features.append(new_feat)
        return GraphView(
            node_features=new_features,
            adjacency=g.adjacency,
        )

    def _aug_subgraph(self, g: GraphView) -> GraphView:
        """子图采样 — 从种子节点开始的随机游走

        GraphCL子图采样: 随机选择种子, BFS扩展至subgraph_ratio * |V|个节点
        """
        N = len(g.node_features)
        target_size = max(2, int(N * self.cfg.subgraph_ratio))
        if N <= target_size:
            return GraphView(
                node_features=[f[:] for f in g.node_features],
                adjacency=g.adjacency,
            )

        # 随机种子
        seed = random.randint(0, N - 1)
        visited = {seed}
        frontier = [seed]

        # BFS扩展
        while frontier and len(visited) < target_size:
            node = frontier.pop(0)
            for nb in g.adjacency[node]:
                if nb not in visited and len(visited) < target_size:
                    visited.add(nb)
                    frontier.append(nb)

        # 映射
        old_to_new = {}
        for new_idx, old_idx in enumerate(sorted(visited)):
            old_to_new[old_idx] = new_idx

        new_features = [g.node_features[i] for i in sorted(visited)]
        new_adj: List[List[int]] = [[] for _ in range(len(new_features))]

        for old_i in sorted(visited):
            ni = old_to_new[old_i]
            for old_j in g.adjacency[old_i]:
                if old_j in visited:
                    new_adj[ni].append(old_to_new[old_j])

        return GraphView(
            node_features=new_features,
            adjacency=new_adj,
            node_mapping=old_to_new,
        )

    def _aug_geomix(self, g: GraphView) -> GraphView:
        """GeoMix [KDD 2024] — 几何感知特征混合

        对于每个节点, 将其特征与邻域特征的凸组合混合:
          x'_i = (1 - alpha_i) * x_i + alpha_i * sum(w_j * x_j) for j in N(i)
        其中 alpha_i ~ Beta(α, α) (GeoMix的alpha超参)
        """
        N = len(g.node_features)
        if N == 0:
            return g

        alpha_param = self.cfg.geomix_alpha
        new_features = []

        for i in range(N):
            feat = g.node_features[i][:]
            neighbors = g.adjacency[i]
            if not neighbors:
                new_features.append(feat)
                continue

            # 邻居平均
            dim = len(feat)
            neighbor_avg = [0.0] * dim
            for nb in neighbors:
                nb_feat = g.node_features[nb]
                for d in range(dim):
                    neighbor_avg[d] += nb_feat[d]
            for d in range(dim):
                neighbor_avg[d] /= len(neighbors)

            # Beta采样的mixup系数 (用简单均匀近似)
            mix_ratio = self._rng.uniform(0.0, alpha_param * 2.0)
            mix_ratio = min(mix_ratio, 1.0)

            # 凸组合
            for d in range(dim):
                feat[d] = (1.0 - mix_ratio) * feat[d] + mix_ratio * neighbor_avg[d]

            new_features.append(feat)

        return GraphView(
            node_features=new_features,
            adjacency=g.adjacency,
        )

    def _aug_attr_shuffle(self, g: GraphView) -> GraphView:
        """属性洗牌 — 在部分节点间交换特征向量

        保留图结构不变, 仅扰动节点—特征的对应关系。
        这强制模型依赖图结构而非节点特征记忆。
        """
        N = len(g.node_features)
        if N < 2:
            return g

        new_features = [f[:] for f in g.node_features]
        n_shuffle = max(1, int(N * self.cfg.attr_shuffle_p))

        indices = list(range(N))
        random.shuffle(indices)

        for i in range(0, min(n_shuffle * 2, N) - 1, 2):
            if i + 1 < N:
                a, b = indices[i], indices[i + 1]
                new_features[a], new_features[b] = new_features[b][:], new_features[a][:]

        return GraphView(
            node_features=new_features,
            adjacency=g.adjacency,
        )

    def _aug_degree_preserving(self, g: GraphView) -> GraphView:
        """度保持边重连 — 交换边以保持每个节点的度分布不变

        这样改变的只是连接模式, 不改变度属性。
        用于测试模型是否过拟合到特定的度模式
        """
        N = len(g.node_features)
        adj = g.adjacency

        # 收集所有边
        edges = []
        for i in range(N):
            for j in adj[i]:
                if i < j:  # 去重
                    edges.append((i, j))

        if len(edges) < 4:
            return GraphView(
                node_features=[f[:] for f in g.node_features],
                adjacency=adj,
            )

        # 随机选择两条边进行交换: (a,b)+(c,d) -> (a,d)+(c,b)
        n_swaps = max(1, len(edges) // 4)
        new_adj: List[Set[int]] = [set(adj[i]) for i in range(N)]

        for _ in range(n_swaps):
            e1, e2 = random.sample(edges, 2)
            a, b = e1
            c, d = e2

            # 避免自环和重复边
            if a != d and c != b and d not in new_adj[a] and b not in new_adj[c]:
                # 执行交换
                new_adj[a].discard(b)
                new_adj[b].discard(a)
                new_adj[c].discard(d)
                new_adj[d].discard(c)
                new_adj[a].add(d)
                new_adj[d].add(a)
                new_adj[c].add(b)
                new_adj[b].add(c)

        return GraphView(
            node_features=[f[:] for f in g.node_features],
            adjacency=[list(s) for s in new_adj],
        )


def create_graph_augmenter(node_drop=0.15, edge_del=0.15,
                            edge_add=0.05, feat_mask=0.20) -> GraphAugmenter:
    cfg = AugmentConfig(
        node_drop_p=node_drop, edge_del_p=edge_del,
        edge_add_p=edge_add, feat_mask_p=feat_mask,
    )
    return GraphAugmenter(cfg)


def augment_graph_pair(node_features, adjacency):
    """便捷函数: 为对比学习生成图对"""
    aug = create_graph_augmenter()
    gv = GraphView(node_features=node_features, adjacency=adjacency)
    return aug.augment_pair(gv)
