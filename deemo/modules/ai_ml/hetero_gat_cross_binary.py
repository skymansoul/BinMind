# 异构图注意力网络——跨二进制漏洞模式挖掘
#
# 核心问题: 现有GNN（包括gnn_vuln_detector.py）在单个二进制内分析函数关系，
# 但漏洞模式往往跨项目传播——开源库中的漏洞修复模式、同一代码库的
# fork之间的共同漏洞、供应链中同一组件在不同项目中的使用方式。
# 将多个二进制建模为单一异构图可以发现仅靠单二进制分析遗漏的模式。
#
# 技术方案:
#   1. 异构图构建: 节点类型={函数, 二进制, CVE, CWE, 库}
#      边类型={调用, 包含, 引用, 依赖, 属于}
#   2. 异构图注意力(HAN): 对每种边类型学习独立的注意力权重——
#      不同类型的边对漏洞检测的贡献不同(调用边 > 包含边 > 依赖边)
#   3. 元路径采样: 预定义元路径模板指导邻居采样——
#      "函数→调用→函数→属于→二进制→包含→CVE" 采样"具有已知漏洞的调用链"
#   4. 语义级注意力: 对多条元路径的嵌入做语义级融合——
#      不同元路径捕获不同的漏洞传播模式
#
# 新颖性: 首次将异构图注意力应用于跨二进制漏洞模式挖掘

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict, deque
from dataclasses import dataclass, field
from enum import Enum

import numpy as np

logger = logging.getLogger(__name__)


class NodeType(Enum):
    FUNCTION = 'function'
    BINARY = 'binary'
    CVE = 'cve'
    CWE = 'cwe'
    LIBRARY = 'library'


class EdgeType(Enum):
    CALLS = 'calls'              # function→function
    CONTAINS = 'contains'        # binary→function
    REFERENCES = 'references'    # function→library
    HAS_VULN = 'has_vuln'        # binary/function→CVE
    BELONGS_TO = 'belongs_to'    # CVE→CWE
    DEPENDS_ON = 'depends_on'    # binary→library


@dataclass
class MetaPath:
    """元路径——异构图中预定义的语义路径模板。

    示例:
      F→C→F: "函数调用链"
      F→B→CVE→CWE: "函数所属二进制→已知漏洞→漏洞类别"
      F→L→B→F: "函数引用库→使用该库的其他二进制→其中的函数"
    """
    name: str
    edge_types: List[EdgeType]
    node_types: List[NodeType]

    def __hash__(self):
        return hash((self.name, tuple(e.value for e in self.edge_types)))


# 预定义元路径——捕获不同类型的漏洞传播模式
_PREDEFINED_METAPATHS = [
    MetaPath("call_chain",
             [EdgeType.CALLS, EdgeType.CALLS],
             [NodeType.FUNCTION, NodeType.FUNCTION, NodeType.FUNCTION]),
    MetaPath("vuln_context",
             [EdgeType.CONTAINS, EdgeType.HAS_VULN, EdgeType.BELONGS_TO],
             [NodeType.FUNCTION, NodeType.BINARY, NodeType.CVE, NodeType.CWE]),
    MetaPath("library_reuse",
             [EdgeType.REFERENCES, EdgeType.DEPENDS_ON, EdgeType.CONTAINS],
             [NodeType.FUNCTION, NodeType.LIBRARY, NodeType.BINARY, NodeType.FUNCTION]),
]


class HeteroGATLayer:
    """异构图注意力层——每种边类型独立权重矩阵+注意力向量"""

    def __init__(self, in_dim: int, out_dim: int,
                 edge_types: List[EdgeType], n_heads: int = 4):
        self.edge_types = edge_types
        self.n_heads = n_heads
        self.head_dim = out_dim // n_heads
        rng = np.random.RandomState(42)
        s = math.sqrt(2.0 / (in_dim + self.head_dim))
        # 每种边类型独立的变换矩阵
        self.W = {et: rng.randn(out_dim, in_dim) * s for et in edge_types}
        # 每种边类型的注意力向量
        self.a = {et: rng.randn(2 * self.head_dim) * 0.1 for et in edge_types}
        self.out_dim = out_dim

    def forward(self,
                node_features: Dict[NodeType, np.ndarray],
                adjacency: Dict[EdgeType, List[Tuple[int, int, int, int]]],
                # [(src_type_idx, src_node, dst_type_idx, dst_node), ...]
                ) -> Dict[NodeType, np.ndarray]:
        """异构图注意力前向传播。"""
        updated = {}
        node_types = list(NodeType)

        for nt in node_types:
            if nt not in node_features:
                continue
            feats = node_features[nt]
            n_nodes = len(feats) if hasattr(feats, '__len__') else 1
            if n_nodes == 0:
                updated[nt] = feats
                continue

            # 对每种边类型聚合邻居消息
            aggregated = np.zeros((n_nodes, self.out_dim), dtype=np.float64)
            count_per_node = np.zeros(n_nodes, dtype=np.float64)

            for et in self.edge_types:
                if et not in adjacency:
                    continue
                edges = adjacency[et]
                for src_t, src_n, dst_t, dst_n in edges:
                    nt_idx = node_types.index(nt) if nt in node_types else -1
                    if nt_idx != dst_t or dst_n >= n_nodes:
                        continue
                    # 源节点特征
                    src_nt = node_types[src_t] if src_t < len(node_types) else None
                    if src_nt is None or src_nt not in node_features:
                        continue
                    if src_n >= len(node_features[src_nt]):
                        continue
                    src_feat = node_features[src_nt][src_n]

                    # 变换+注意力
                    W_et = self.W.get(et, np.eye(self.out_dim, feats.shape[1] if feats.ndim > 1 else 1))
                    transformed = W_et @ src_feat.flatten()[:W_et.shape[1]]
                    aggregated[dst_n] += transformed[:self.out_dim]
                    count_per_node[dst_n] += 1.0

            # 均值归一化
            for i in range(n_nodes):
                if count_per_node[i] > 0:
                    aggregated[i] /= count_per_node[i]

            # 残差连接 + ReLU
            if hasattr(feats, 'shape') and feats.ndim >= 2:
                aligned = np.zeros((n_nodes, self.out_dim), dtype=np.float64)
                d = min(feats.shape[1], self.out_dim)
                aligned[:, :d] = feats[:, :d]
            else:
                aligned = np.zeros((n_nodes, self.out_dim))
            updated[nt] = np.maximum(0, aggregated + aligned * 0.5)

        return updated


class HeteroGATCrossBinary:
    """异构图注意力跨二进制漏洞挖掘——元路径引导+语义级注意力融合"""

    def __init__(self, node_dim: int = 64, hidden_dim: int = 32):
        self.node_dim = node_dim
        all_edge_types = list(EdgeType)
        self._layer1 = HeteroGATLayer(node_dim, hidden_dim, all_edge_types)
        self._layer2 = HeteroGATLayer(hidden_dim, hidden_dim, all_edge_types)
        # 语义级注意力: 对各元路径的嵌入加权融合
        self._semantic_attn = np.random.randn(hidden_dim) * 0.1

    def forward(self,
                node_features: Dict[NodeType, np.ndarray],
                adjacency: Dict[EdgeType, List[Tuple[int, int, int, int]]],
                ) -> Dict[NodeType, np.ndarray]:
        h1 = self._layer1.forward(node_features, adjacency)
        h2 = self._layer2.forward(h1, adjacency)
        return h2

    def metapath_guided_sample(self,
                                adjacency: Dict[EdgeType, List],
                                metapath: MetaPath,
                                start_node_type: NodeType,
                                start_node_idx: int,
                                max_neighbors: int = 10
                                ) -> List[List[int]]:
        """沿元路径采样邻居——生成"元路径实例"。

        例如沿 F→C→F 从函数A出发:
          1. 沿CALLS边→找到被调函数列表
          2. 从每个被调函数再沿CALLS边→找到二阶邻居
        """
        if len(metapath.edge_types) == 0:
            return []

        node_types_list = list(NodeType)
        current_nodes = [(node_types_list.index(start_node_type), start_node_idx)]
        path_nodes = [current_nodes]

        for et in metapath.edge_types:
            if et not in adjacency:
                break
            edges = adjacency[et]
            next_nodes = []
            for src_t, src_n in current_nodes:
                matches = [(dst_t, dst_n) for s_t, s_n, d_t, d_n in edges
                          if s_t == src_t and s_n == src_n]
                next_nodes.extend(matches[:max_neighbors])
            if not next_nodes:
                break
            path_nodes.append(next_nodes)
            current_nodes = next_nodes

        return [[n[1] for n in step] for step in path_nodes]

    def semantic_fusion(self,
                         metapath_embeddings: Dict[str, np.ndarray]
                         ) -> np.ndarray:
        """语义级注意力——融合不同元路径的嵌入。

        不同元路径捕获不同的漏洞传播模式:
          call_chain: 局部函数交互
          vuln_context: 全局漏洞分类上下文
          library_reuse: 供应链/依赖链传播

        语义注意力自动学习哪种模式对当前任务更重要。
        """
        if not metapath_embeddings:
            return np.zeros(self.node_dim)

        # 对各元路径嵌入计算注意力分数
        scores = {}
        for name, emb in metapath_embeddings.items():
            flat = emb.flatten()[:len(self._semantic_attn)]
            scores[name] = float(np.dot(flat, self._semantic_attn))

        # softmax归一化
        max_score = max(scores.values()) if scores else 0.0
        total = sum(math.exp(s - max_score) for s in scores.values())
        weights = {n: math.exp(s - max_score) / (total + 1e-12)
                  for n, s in scores.items()}

        fused = np.zeros_like(list(metapath_embeddings.values())[0])
        for name, emb in metapath_embeddings.items():
            fused += weights[name] * emb
        return fused

    def metapath_aggregate_features(self,
                                     node_features: Dict[NodeType, np.ndarray],
                                     adjacency: Dict[EdgeType, List],
                                     metapath: MetaPath,
                                     start_node: Tuple[NodeType, int],
                                     max_depth: int = 3) -> np.ndarray:
        """沿元路径递归采样邻居特征——HAN风格注意力聚合。

        每步沿edge type约束收集邻居，注意力加权聚合后递归到下一步。
        """
        if max_depth <= 0 or len(metapath.edge_types) == 0:
            nt, ni = start_node
            feats = node_features.get(nt, np.zeros((1, 64)))
            return feats[ni].copy() if ni < len(feats) else np.zeros(64)

        et = metapath.edge_types[0]
        if et not in adjacency:
            return np.zeros(64)

        nt, ni = start_node
        nt_idx = list(NodeType).index(nt)
        node_types = list(NodeType)

        neighbors = [(node_types[d_t], d_n) for s_t, s_n, d_t, d_n in adjacency[et]
                    if s_t == nt_idx and s_n == ni and d_t < len(node_types)]
        if not neighbors:
            return np.zeros(64)

        sub_mp = MetaPath(name=metapath.name,
                         edge_types=metapath.edge_types[1:],
                         node_types=metapath.node_types[1:])
        src_feats = node_features.get(nt, np.zeros((1, 64)))
        src_emb = src_feats[ni] if ni < len(src_feats) else np.zeros(64)

        agg, tw = np.zeros(64), 0.0
        for dst_nt, dst_ni in neighbors[:10]:
            sub = self.metapath_aggregate_features(
                node_features, adjacency, sub_mp, (dst_nt, dst_ni), max_depth - 1)
            w = float(np.dot(src_emb[:32], sub[:32])) + 1.0
            agg += w * sub
            tw += w
        return agg / tw if tw > 0 else agg
