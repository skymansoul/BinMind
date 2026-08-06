# 超图卷积 + 双尺度GNN模型
# 用于 hypergraph_vuln_detector.py 的多函数联合漏洞检测

import math
import logging
from typing import Dict, List, Optional, Tuple, Any
from dataclasses import dataclass, field

import numpy as np

logger = logging.getLogger(__name__)


@dataclass
class Hyperedge:
    """超边——连接≥2个节点的高阶关系"""
    edge_id: str
    node_indices: List[int]
    edge_type: str = "generic"
    weight: float = 1.0
    features: Optional[np.ndarray] = None


@dataclass
class HyperGraph:
    """超图: 节点 + 超边 + 关联矩阵H"""
    n_nodes: int
    n_edges: int
    node_features: np.ndarray
    incidence: np.ndarray       # (V, E) 关联矩阵
    hyperedges: List[Hyperedge]
    edge_weights: np.ndarray    # (E,) 超边权重


class HyperGraphConvolution:
    """超图卷积: H' = D_v^{-1/2}·H·W·D_e^{-1}·H^T·D_v^{-1/2}·X·Θ

    与GCN的差异:
      - GCN用邻接矩阵A（成对），超图用关联矩阵H（高阶）
      - 超边权重W门控信息流——重要超边传递更多信息
    """

    def __init__(self, in_dim: int, out_dim: int):
        rng = np.random.RandomState(42)
        s = math.sqrt(2.0 / (in_dim + out_dim))
        self.Theta = rng.randn(in_dim, out_dim) * s
        self.bias = np.zeros(out_dim)

    def forward(self, graph: HyperGraph) -> np.ndarray:
        H = graph.incidence
        X = graph.node_features
        n_edges = H.shape[1]
        W = np.diag(graph.edge_weights) if n_edges > 0 else np.eye(n_edges)
        eps = 1e-8

        d_v = H @ W @ np.ones(n_edges) + eps
        D_v_inv_sqrt = np.diag(1.0 / np.sqrt(d_v))
        d_e = H.T @ np.ones(H.shape[0]) + eps
        D_e_inv = np.diag(1.0 / d_e)

        H_norm = D_v_inv_sqrt @ H @ W @ D_e_inv @ H.T @ D_v_inv_sqrt
        out = H_norm @ X @ self.Theta + self.bias
        return np.maximum(0, out)


class DualScaleHyperGNN:
    """双尺度GNN: 成对卷积 + 超图卷积 → 交叉注意力融合。

    成对关系捕获局部函数交互（caller-callee），
    超图关系捕获全局高阶模式（多函数协同漏洞）。
    """

    def __init__(self, node_dim: int = 64, hidden_dim: int = 32,
                 n_classes: int = 2, attention_heads: int = 4):
        self._conv_pairwise = HyperGraphConvolution(node_dim, hidden_dim)
        self._conv_hyper = HyperGraphConvolution(node_dim, hidden_dim)
        rng = np.random.RandomState(42)
        s = math.sqrt(2.0 / (hidden_dim * 2))
        self._fusion_W = rng.randn(hidden_dim * 2, n_classes) * s
        self._fusion_b = np.zeros(n_classes)
        self._attn_a = rng.randn(hidden_dim) * 0.1

    def forward(self, pairwise_graph: HyperGraph,
                hyper_graph: HyperGraph) -> np.ndarray:
        h_pair = self._conv_pairwise.forward(pairwise_graph)
        h_hyper = self._conv_hyper.forward(hyper_graph)

        pair_score = h_pair @ self._attn_a
        hyper_score = h_hyper @ self._attn_a
        scores = np.stack([pair_score, hyper_score], axis=1)
        scores -= scores.max(axis=1, keepdims=True)
        attn = np.exp(scores) / (np.exp(scores).sum(axis=1, keepdims=True) + 1e-8)

        fused = np.concatenate([
            h_pair * attn[:, 0:1],
            h_hyper * attn[:, 1:2],
        ], axis=1)
        logits = fused @ self._fusion_W + self._fusion_b
        return logits
