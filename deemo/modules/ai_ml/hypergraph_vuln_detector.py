# 基于超图卷积的多函数联合漏洞检测
#
# 核心问题: 现有GNN将每个函数建模为独立图，函数间关系仅通过调用边
# 表示为一阶成对关系。无法表达"三个函数联合构成漏洞模式"的高阶交互。
#
# 技术方案:
#   1. 超图构建: 节点=函数，超边=跨函数数据流/共享内存/间接调用聚类
#   2. 超图卷积: H' = D_v^{-1/2}·H·W·D_e^{-1}·H^T·D_v^{-1/2}·X·Θ
#   3. 双尺度融合: 成对图（GGNN）+超图（HGNN）→交叉注意力融合
#
# IFMA-VD在源码级使用超图，本工作在二进制级实现——
# 二进制无类型信息，超边构建策略完全不同。
#
# 核心模型实现在 src/hypergraph/hg_convolution.py

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any
from collections import defaultdict

import numpy as np

from .src.hypergraph.hg_convolution import (
    Hyperedge, HyperGraph, HyperGraphConvolution, DualScaleHyperGNN,
)

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


class HyperGraphBuilder:
    """从二进制函数的CFG+调用图构建超图。

    超边构建策略（二进制级——与源码级IFMA-VD的区别）:
      1. 调用边超边: 最小超边（2节点caller-callee）
      2. 共享数据超边: 多个函数访问同一数据地址→高阶超边
      3. 间接调用超边: 同一函数指针的不同可能目标→聚类超边
    """

    def __init__(self, node_feature_dim: int = 64):
        self.node_dim = node_feature_dim

    def build_from_call_graph(self,
                              func_embeddings: List[np.ndarray],
                              call_edges: List[Tuple[int, int]],
                              data_refs: Optional[Dict[int, List[int]]] = None,
                              indirect_calls: Optional[Dict[int, List[int]]] = None
                              ) -> HyperGraph:
        n_funcs = len(func_embeddings)
        node_feats = np.array(func_embeddings, dtype=np.float64)
        if node_feats.ndim == 1:
            node_feats = node_feats.reshape(-1, 1)

        hyperedges = []
        inc_rows = []

        # 超边类型1: 调用边（2节点）
        for caller, callee in call_edges:
            if caller < n_funcs and callee < n_funcs:
                row = np.zeros(n_funcs, dtype=np.float64)
                row[caller] = 1.0
                row[callee] = 1.0
                inc_rows.append(row)
                edge_feat = np.concatenate([
                    node_feats[caller], node_feats[callee]
                ])[:self.node_dim]
                hyperedges.append(Hyperedge(
                    edge_id=f"call_{caller}_{callee}",
                    node_indices=[caller, callee],
                    edge_type="call_edge", weight=1.0, features=edge_feat))

        # 超边类型2: 共享数据引用
        if data_refs:
            addr_to_funcs = defaultdict(list)
            for func_id, addrs in data_refs.items():
                for addr in addrs:
                    addr_to_funcs[addr].append(func_id)
            for addr, funcs in addr_to_funcs.items():
                if len(funcs) >= 2:
                    row = np.zeros(n_funcs, dtype=np.float64)
                    for f in funcs:
                        if f < n_funcs:
                            row[f] = 1.0
                    inc_rows.append(row)
                    member_embs = [node_feats[f] for f in funcs if f < n_funcs]
                    edge_feat = np.mean(member_embs, axis=0) if member_embs else np.zeros(self.node_dim)
                    hyperedges.append(Hyperedge(
                        edge_id=f"data_{addr:08x}",
                        node_indices=[f for f in funcs if f < n_funcs],
                        edge_type="shared_data", weight=1.5, features=edge_feat))

        # 超边类型3: 间接调用聚类
        if indirect_calls:
            for call_site, targets in indirect_calls.items():
                valid = [t for t in targets if t < n_funcs]
                if len(valid) >= 2:
                    row = np.zeros(n_funcs, dtype=np.float64)
                    for t in valid:
                        row[t] = 1.0
                    inc_rows.append(row)
                    member_embs = [node_feats[t] for t in valid]
                    edge_feat = np.mean(member_embs, axis=0)
                    hyperedges.append(Hyperedge(
                        edge_id=f"indirect_{call_site}",
                        node_indices=valid, edge_type="indirect_call_cluster",
                        weight=1.2, features=edge_feat))

        if not inc_rows:
            return HyperGraph(n_nodes=n_funcs, n_edges=0, node_features=node_feats,
                            incidence=np.zeros((n_funcs, 0)),
                            hyperedges=[], edge_weights=np.zeros(0))

        incidence = np.stack(inc_rows, axis=1)
        edge_weights = np.array([he.weight for he in hyperedges], dtype=np.float64)
        return HyperGraph(n_nodes=n_funcs, n_edges=len(hyperedges),
                         node_features=node_feats, incidence=incidence,
                         hyperedges=hyperedges, edge_weights=edge_weights)


class HyperGraphVulnDetector:
    """多函数超图漏洞检测器的便捷入口。"""

    def __init__(self, node_dim: int = 64):
        self._builder = HyperGraphBuilder(node_feature_dim=node_dim)
        self._model = DualScaleHyperGNN(node_dim=node_dim,
                                        hidden_dim=32, n_classes=2)
        self.node_dim = node_dim

    def build_hypergraph(self,
                         func_embeddings: List[np.ndarray],
                         call_edges: List[Tuple[int, int]],
                         data_refs: Optional[Dict[int, List[int]]] = None,
                         indirect_calls: Optional[Dict[int, List[int]]] = None
                         ) -> HyperGraph:
        return self._builder.build_from_call_graph(
            func_embeddings, call_edges, data_refs, indirect_calls)

    def detect(self, hyper_graph: HyperGraph) -> np.ndarray:
        # 从超图中提取成对图（仅2节点调用边）
        pair_idx = []
        for i, he in enumerate(hyper_graph.hyperedges):
            if len(he.node_indices) == 2 and he.edge_type == "call_edge":
                pair_idx.append(i)
        if not pair_idx:
            pair_idx = [0] if hyper_graph.n_edges > 0 else []
        pair_inc = hyper_graph.incidence[:, pair_idx] if pair_idx else np.zeros((hyper_graph.n_nodes, 1))
        pair_w = (hyper_graph.edge_weights[pair_idx] if pair_idx
                 else np.ones(max(1, pair_inc.shape[1])))

        pair_graph = HyperGraph(
            n_nodes=hyper_graph.n_nodes, n_edges=len(pair_idx),
            node_features=hyper_graph.node_features,
            incidence=pair_inc, hyperedges=[], edge_weights=pair_w)

        logits = self._model.forward(pair_graph, hyper_graph)
        logits -= logits.max(axis=1, keepdims=True)
        return np.exp(logits) / np.exp(logits).sum(axis=1, keepdims=True)
