#!/usr/bin/env python3
# 二进制函数相似度多视图 GNN — CFG/DFG/助记符三视图, GNN 编码器,
# 对比损失, 与 BaseAnalyzer 集成。
# 注意力视图融合; GraphAugmenter 增广; EdgeDrop 正则化。

import logging as _logging
import math as _math
import json as _json
import numpy as np
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)


@dataclass
class GraphNode:
    node_id: int = 0
    node_type: str = "basic_block"
    features: List[float] = field(default_factory=list)
    address: int = 0
    label: str = ""
    num_instructions: int = 0
    num_calls: int = 0
    string_refs: List[str] = field(default_factory=list)
    constants: List[int] = field(default_factory=list)
    in_degree: int = 0
    out_degree: int = 0


@dataclass
class GraphEdge:
    edge_id: int = 0
    source_id: int = 0
    target_id: int = 0
    edge_type: str = "control_flow"
    weight: float = 1.0
    features: List[float] = field(default_factory=list)


@dataclass
class FunctionGraph:
    function_name: str = ""
    function_address: int = 0
    nodes: List[GraphNode] = field(default_factory=list)
    cfg_edges: List[GraphEdge] = field(default_factory=list)
    dfg_edges: List[GraphEdge] = field(default_factory=list)
    call_edges: List[GraphEdge] = field(default_factory=list)
    memory_edges: List[GraphEdge] = field(default_factory=list)
    mnemonic_sequence: List[str] = field(default_factory=list)
    num_basic_blocks: int = 0
    num_instructions: int = 0
    # 图结构全局统计特征，用于图分类和快速过滤
    cyclomatic_complexity: int = 0  # E - N + 2 近似
    avg_degree: float = 0.0
    edge_density: float = 0.0

    def all_edges(self) -> List[GraphEdge]:
        all_e: List[GraphEdge] = []
        all_e.extend(self.cfg_edges)
        all_e.extend(self.dfg_edges)
        all_e.extend(self.call_edges)
        all_e.extend(self.memory_edges)
        return all_e

    def adjacency_matrix(self) -> List[List[float]]:
        n = len(self.nodes)
        adj: List[List[float]] = []
        i = 0
        while i < n:
            adj.append([0.0] * n)
            i += 1
        edges = self.all_edges()
        ei = 0
        while ei < len(edges):
            e = edges[ei]
            if e.source_id < n and e.target_id < n:
                adj[e.source_id][e.target_id] = e.weight
            ei += 1
        return adj

    def node_features_matrix(self) -> List[List[float]]:
        return [n.features for n in self.nodes]


@dataclass
class EmbeddingResult:
    graph: FunctionGraph
    embedding: List[float] = field(default_factory=list)
    view_embeddings: Dict[str, List[float]] = field(default_factory=dict)
    embedding_dim: int = 128
    compute_time_ms: float = 0.0
    # 注意力 scores 存储每个视图的重要性权重
    view_attention_scores: Dict[str, float] = field(default_factory=dict)


@dataclass
class SimilarityResult:
    function_a: str = ""
    function_b: str = ""
    embedding_a: List[float] = field(default_factory=list)
    embedding_b: List[float] = field(default_factory=list)
    cosine_similarity: float = 0.0
    euclidean_distance: float = 0.0
    view_similarities: Dict[str, float] = field(default_factory=dict)
    is_match: bool = False
    confidence: float = 0.0


# GNN 编码器 -- 消息传递 + 均值池化聚合 + EdgeDrop

class GNNEncoder:
    """消息传递 GNN 编码器 -- 用于函数图嵌入。"""

    __slots__ = ('m_input_dim', 'm_hidden_dim', 'm_output_dim', 'm_num_layers',
                 'm_weights', 'm_biases', 'm_trained', 'm_edge_dropout')

    def __init__(self, input_dim: int = 64, hidden_dim: int = 128,
                 output_dim: int = 128, num_layers: int = 3,
                 edge_dropout: float = 0.0):
        self.m_input_dim = input_dim
        self.m_hidden_dim = hidden_dim
        self.m_output_dim = output_dim
        self.m_num_layers = num_layers
        self.m_trained = False
        self.m_edge_dropout = edge_dropout  # EdgeDrop 比例 [0, 1)

        import random as _r
        _r.seed(42)

        self.m_weights: List[List[List[float]]] = []
        self.m_biases: List[List[float]] = []

        dims = [input_dim] + [hidden_dim] * (num_layers - 1) + [output_dim]
        layer = 0
        while layer < num_layers:
            d_in = dims[layer]
            d_out = dims[layer + 1]
            limit = _math.sqrt(6.0 / (d_in + d_out))
            w: List[List[float]] = []
            ri = 0
            while ri < d_in:
                row: List[float] = []
                ci = 0
                while ci < d_out:
                    row.append(_r.uniform(-limit, limit))
                    ci += 1
                w.append(row)
                ri += 1
            self.m_weights.append(w)
            self.m_biases.append([0.0] * d_out)
            layer += 1

    def set_edge_dropout(self, rate: float):
        """动态设置EdgeDrop比率（训练时0.1-0.2，推理时0.0）"""
        self.m_edge_dropout = max(0.0, min(rate, 0.5))

    def forward(self, node_features: List[List[float]],
                adjacency: List[List[float]]) -> List[List[float]]:
        if not node_features or not adjacency:
            return [[0.0] * self.m_output_dim]

        import random as _rnd
        n = len(node_features)
        h = [list(row) for row in node_features]

        if h and len(h[0]) < self.m_input_dim:
            pad_len = self.m_input_dim - len(h[0])
            i = 0
            while i < n:
                h[i].extend([0.0] * pad_len)
                i += 1

        # EdgeDrop mask，每层独立采样
        layer = 0
        while layer < self.m_num_layers:
            w = self.m_weights[layer]
            b = self.m_biases[layer]
            d_out = len(b)
            h_new: List[List[float]] = []

            i = 0
            while i < n:
                msg = [0.0] * len(h[i])
                agg_count = 0
                j = 0
                while j < n:
                    if adjacency[i][j] > 0:
                        # EdgeDrop: 随机丢弃边 (推理时 dropout=0 直接跳过)
                        if self.m_edge_dropout > 0.0 and _rnd.random() < self.m_edge_dropout:
                            j += 1
                            continue
                        wgt = adjacency[i][j]
                        ki = 0
                        while ki < len(msg) and ki < len(h[j]):
                            msg[ki] += h[j][ki] * wgt
                            ki += 1
                        agg_count += 1
                    j += 1

                si = 0
                while si < len(msg) and si < len(h[i]):
                    msg[si] += h[i][si]
                    si += 1
                agg_count += 1

                combined: List[float] = []
                ci = 0
                while ci < len(msg):
                    combined.append(msg[ci] / max(agg_count, 1))
                    ci += 1

                while len(combined) < len(w):
                    combined.append(0.0)

                out: List[float] = []
                di = 0
                while di < d_out:
                    val = b[di]
                    ci = 0
                    while ci < len(combined) and ci < len(w):
                        val += combined[ci] * w[ci][di]
                        ci += 1
                    out.append(max(0.0, val))
                    di += 1

                h_new.append(out)
                i += 1

            h = h_new
            layer += 1

        return h

    def readout(self, node_embeddings: List[List[float]]) -> List[float]:
        if not node_embeddings:
            return [0.0] * self.m_output_dim

        n = len(node_embeddings)
        dim = len(node_embeddings[0])
        pooled = [0.0] * dim
        i = 0
        while i < n:
            j = 0
            while j < dim and j < len(node_embeddings[i]):
                pooled[j] += node_embeddings[i][j]
                j += 1
            i += 1

        j = 0
        while j < dim:
            pooled[j] /= n
            j += 1

        return pooled

    def embed(self, node_features: List[List[float]],
              adjacency: List[List[float]]) -> List[float]:
        node_embs = self.forward(node_features, adjacency)
        return self.readout(node_embs)


# 多视图 GNN -- 注意力融合

class MultiViewGNN:
    """多视图 GNN -- 融合 CFG/DFG/call/助记符四视图。"""

    __slots__ = ('m_cfg_encoder', 'm_dfg_encoder', 'm_call_encoder',
                 'm_mnemonic_encoder', 'm_fusion_weights', 'm_output_dim',
                 'm_attn_query', 'm_attn_key', 'm_training')

    def __init__(self, input_dim: int = 64, hidden_dim: int = 128,
                 output_dim: int = 128):
        self.m_cfg_encoder = GNNEncoder(input_dim, hidden_dim, output_dim)
        self.m_dfg_encoder = GNNEncoder(input_dim, hidden_dim, output_dim)
        self.m_call_encoder = GNNEncoder(input_dim, hidden_dim, output_dim)
        self.m_mnemonic_encoder = GNNEncoder(input_dim, hidden_dim, output_dim // 2)
        self.m_output_dim = output_dim
        self.m_fusion_weights = [0.3, 0.25, 0.2, 0.25]  # 保留作为 回退
        self.m_training = False

        # 可学习的注意力投影向量 (查询/key 维度 = output_dim)
        import random as _r
        _r.seed(42)
        self.m_attn_query: List[float] = []
        di = 0
        while di < output_dim:
            self.m_attn_query.append(_r.uniform(-0.1, 0.1))
            di += 1

    def set_training(self, flag: bool):
        """切换训练/推理模式 -- 同时传播到子编码器"""
        self.m_training = flag
        for enc in [self.m_cfg_encoder, self.m_dfg_encoder, self.m_call_encoder, self.m_mnemonic_encoder]:
            enc.set_edge_dropout(0.15 if flag else 0.0)

    def _attention_fusion(self, view_embs: Dict[str, List[float]]) -> Tuple[List[float], Dict[str, float]]:
        view_keys = list(view_embs.keys())
        dim = self.m_output_dim

        # 计算每个视图的原始得分
        raw_scores: List[float] = []
        vi = 0
        while vi < len(view_keys):
            emb = view_embs[view_keys[vi]]
            dot = 0.0
            d = 0
            while d < min(len(emb), dim):
                dot += emb[d] * self.m_attn_query[d]
                d += 1
            raw_scores.append(dot)
            vi += 1

        # Softmax 温度缩放 sqrt(dim)
        scale = _math.sqrt(max(dim, 1))
        max_score = max(raw_scores) if raw_scores else 0.0
        exp_sum = 0.0
        exps: List[float] = []
        si = 0
        while si < len(raw_scores):
            e = _math.exp((raw_scores[si] - max_score) / scale)
            exps.append(e)
            exp_sum += e
            si += 1

        attn_weights: Dict[str, float] = {}
        vi2 = 0
        while vi2 < len(view_keys):
            aw = exps[vi2] / max(exp_sum, 1e-8)
            attn_weights[view_keys[vi2]] = aw
            vi2 += 1

        # 加权融合
        fused: List[float] = [0.0] * dim
        vi3 = 0
        while vi3 < len(view_keys):
            emb = view_embs[view_keys[vi3]]
            w = attn_weights[view_keys[vi3]]
            j = 0
            while j < min(len(emb), dim):
                fused[j] += emb[j] * w
                j += 1
            vi3 += 1

        return fused, attn_weights

    def embed(self, graph: FunctionGraph) -> EmbeddingResult:
        import time as _time
        start = _time.time()

        result = EmbeddingResult(graph=graph, embedding_dim=self.m_output_dim)
        view_embs: Dict[str, List[float]] = {}
        node_feats = graph.node_features_matrix()

        # CFG 视图
        cfg_adj = self._edge_list_to_adj(graph.cfg_edges, len(graph.nodes))
        cfg_node_embs = self.m_cfg_encoder.forward(node_feats, cfg_adj)
        view_embs["cfg"] = self.m_cfg_encoder.readout(cfg_node_embs)

        # DFG 视图
        dfg_adj = self._edge_list_to_adj(graph.dfg_edges, len(graph.nodes))
        dfg_node_embs = self.m_dfg_encoder.forward(node_feats, dfg_adj)
        view_embs["dfg"] = self.m_dfg_encoder.readout(dfg_node_embs)

        # Call 视图
        call_adj = self._edge_list_to_adj(graph.call_edges, len(graph.nodes))
        call_node_embs = self.m_call_encoder.forward(node_feats, call_adj)
        view_embs["call"] = self.m_call_encoder.readout(call_node_embs)

        # 助记符视图
        mem_adj = self._identity_adj(len(graph.mnemonic_sequence))
        mem_feats = self._mnemonic_features(graph.mnemonic_sequence,
                                            len(node_feats[0]) if node_feats else 64)
        if mem_feats:
            mem_node_embs = self.m_mnemonic_encoder.forward(mem_feats, mem_adj)
            mem_emb = self.m_mnemonic_encoder.readout(mem_node_embs)
            while len(mem_emb) < self.m_output_dim:
                mem_emb.append(0.0)
            view_embs["mnemonic"] = mem_emb[:self.m_output_dim]
        else:
            view_embs["mnemonic"] = [0.0] * self.m_output_dim

        result.view_embeddings = dict(view_embs)

        fused, attn_scores = self._attention_fusion(view_embs)
        result.view_attention_scores = attn_scores

        # L2 归一化
        norm = _math.sqrt(sum(v * v for v in fused))
        if norm > 0:
            j = 0
            while j < len(fused):
                fused[j] /= norm
                j += 1

        result.embedding = fused
        result.compute_time_ms = (_time.time() - start) * 1000
        return result

    def _edge_list_to_adj(self, edges: List[GraphEdge], num_nodes: int) -> List[List[float]]:
        adj: List[List[float]] = []
        i = 0
        while i < num_nodes:
            adj.append([0.0] * num_nodes)
            i += 1
        ei = 0
        while ei < len(edges):
            e = edges[ei]
            if e.source_id < num_nodes and e.target_id < num_nodes:
                adj[e.source_id][e.target_id] = e.weight
            ei += 1
        return adj

    def _identity_adj(self, n: int) -> List[List[float]]:
        adj: List[List[float]] = []
        i = 0
        while i < n:
            row = [0.0] * n
            row[i] = 1.0
            adj.append(row)
            i += 1
        return adj

    def _mnemonic_features(self, mnemonics: List[str], dim: int) -> List[List[float]]:
        if not mnemonics:
            return []
        features: List[List[float]] = []
        mi = 0
        while mi < len(mnemonics):
            m = mnemonics[mi]
            feat = [0.0] * dim
            h = hash(m) & 0xFFFFFFFF
            di = 0
            while di < min(dim, 8):
                feat[di] = ((h >> (di * 8)) & 0xFF) / 255.0
                di += 1
            features.append(feat)
            mi += 1
        return features


# 对比损失

class ContrastiveLoss:
    """对比学习损失 -- InfoNCE / NT-Xent。"""

    __slots__ = ('m_temperature', 'm_margin')

    def __init__(self, temperature: float = 0.07, margin: float = 0.5):
        self.m_temperature = temperature
        self.m_margin = margin

    def compute(self, embeddings_a: List[List[float]],
                embeddings_b: List[List[float]],
                labels: List[int]) -> float:
        n = len(embeddings_a)
        if n == 0:
            return 0.0

        total_loss = 0.0
        i = 0
        while i < n:
            sim = self._cosine_similarity(embeddings_a[i], embeddings_b[i])
            if labels[i] > 0:
                total_loss += -_math.log(max(sim, 1e-8))
            else:
                total_loss += max(0.0, self.m_margin - sim)
            i += 1

        return total_loss / n

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        if len(a) != len(b) or len(a) == 0:
            return 0.0
        dot = 0.0
        na = 0.0
        nb = 0.0
        i = 0
        while i < len(a):
            dot += a[i] * b[i]
            na += a[i] * a[i]
            nb += b[i] * b[i]
            i += 1
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (_math.sqrt(na) * _math.sqrt(nb))


# 图数据增强器 -- 边扰动与节点特征噪声，用于对比学习自监督预训练

class GraphAugmenter:
    """图数据增强 -- 生成图的两个增强视图用于对比预训练。"""

    __slots__ = ('m_edge_drop_rate', 'm_feature_mask_rate', 'm_seed')

    def __init__(self, edge_drop_rate: float = 0.1, feature_mask_rate: float = 0.1, seed: int = 42):
        self.m_edge_drop_rate = max(0.0, min(edge_drop_rate, 0.5))
        self.m_feature_mask_rate = max(0.0, min(feature_mask_rate, 0.5))
        self.m_seed = seed
        import random as _rnd
        _rnd.seed(seed)

    def augment(self, graph: FunctionGraph) -> Tuple[FunctionGraph, FunctionGraph]:
        """返回 graph 的两个增强视图 (view1, view2)"""
        import random as _rnd
        import copy as _cp

        g1 = _cp.deepcopy(graph)
        g2 = _cp.deepcopy(graph)

        self._perturb_edges(g1)
        self._mask_features(g1)

        self._perturb_edges(g2)
        self._mask_features(g2)

        return g1, g2

    def _perturb_edges(self, graph: FunctionGraph):
        import random as _rnd
        for edge_list in [graph.cfg_edges, graph.dfg_edges, graph.call_edges, graph.memory_edges]:
            kept: List[GraphEdge] = []
            ei = 0
            while ei < len(edge_list):
                if _rnd.random() >= self.m_edge_drop_rate:
                    kept.append(edge_list[ei])
                ei += 1
            edge_list.clear()
            edge_list.extend(kept)

    def _mask_features(self, graph: FunctionGraph):
        import random as _rnd
        ni = 0
        while ni < len(graph.nodes):
            feat = graph.nodes[ni].features
            fi = 0
            while fi < len(feat):
                if _rnd.random() < self.m_feature_mask_rate:
                    feat[fi] = 0.0
                fi += 1
            ni += 1


# 多视图 GNN 嵌入器

@dataclass
class FunctionEmbedding:
    """函数嵌入结果，兼容字典接口与属性访问。"""
    function_name: str = ""
    function_address: int = 0
    embedding: Any = None
    confidence: float = 0.0
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SearchResult:
    """相似函数搜索结果。"""
    top_k: int = 10
    similar_functions: List[Tuple[str, float]] = field(default_factory=list)


class MultiViewGNNEmbedder:
    """函数图嵌入与相似度计算的高层接口。
    兼容 dict 输入（测试接口）与 FunctionGraph 输入（原接口）。"""

    def __init__(self, input_dim: int = 64, hidden_dim: int = 128, output_dim: int = 512):
        self.m_model = MultiViewGNN(input_dim, hidden_dim, output_dim)
        self.m_loss = ContrastiveLoss()
        self.m_cache: Dict[str, EmbeddingResult] = {}
        self.m_augmenter: Optional[GraphAugmenter] = None
        self.embedding_cache: Dict[str, Any] = {}
        self.output_dim = output_dim

    def enable_augmentation(self, edge_drop: float = 0.1, feat_mask: float = 0.1):
        """启用图增强器 -- 用于对比预训练阶段"""
        self.m_augmenter = GraphAugmenter(edge_drop_rate=edge_drop, feature_mask_rate=feat_mask)

    def _function_info_to_graph(self, info: Dict[str, Any]) -> FunctionGraph:
        """从字典格式函数信息构建 FunctionGraph。"""
        name = info.get("name", "")
        address = info.get("address", 0)
        cfg_nodes = info.get("cfg_nodes", [])
        cfg_edges = info.get("cfg_edges", [])
        variables = info.get("variables", [])
        call_graph = info.get("call_graph", [])

        graph = FunctionGraph(
            function_name=name,
            function_address=address,
            num_basic_blocks=len(cfg_nodes),
            num_instructions=sum(len(n.get("instructions", [])) for n in cfg_nodes),
        )

        bi = 0
        while bi < len(cfg_nodes):
            node_data = cfg_nodes[bi]
            features: List[float] = [
                float(len(node_data.get("instructions", []))),
                float(len(node_data.get("instructions", []))),
                0.0, 0.0, 0.0, 0.0,
            ]
            ci = 0
            while ci < 64 - len(features):
                features.append(0.0)
                ci += 1
            node = GraphNode(
                node_id=bi,
                features=features[:64],
                label=node_data.get("label", f"block_{bi}"),
                num_instructions=len(node_data.get("instructions", [])),
            )
            graph.nodes.append(node)
            bi += 1

        ei = 0
        while ei < len(cfg_edges):
            e = cfg_edges[ei]
            graph.cfg_edges.append(GraphEdge(
                edge_id=ei, source_id=e.get("source", 0), target_id=e.get("target", 0)
            ))
            ei += 1

        ci = 0
        while ci < len(call_graph):
            graph.call_edges.append(GraphEdge(
                edge_id=ci, source_id=0, target_id=0,
                edge_type="call"
            ))
            ci += 1

        return graph

    def embed_function(self, function_info: Dict[str, Any]) -> FunctionEmbedding:
        """从函数信息字典生成嵌入向量。"""
        name = function_info.get("name", "")
        address = function_info.get("address", 0)
        cache_key = f"{name}_{address}"

        if cache_key in self.embedding_cache:
            emb = self.embedding_cache[cache_key]
        else:
            graph = self._function_info_to_graph(function_info)
            result = self.m_model.embed(graph)
            emb = np.array(result.embedding[:self.output_dim])
            pad_len = self.output_dim - len(emb)
            if pad_len > 0:
                emb = np.pad(emb, (0, pad_len))
            self.embedding_cache[cache_key] = emb

        cfg_nodes = function_info.get("cfg_nodes", [])
        metadata = {
            "num_cfg_nodes": len(cfg_nodes),
            "num_cfg_edges": len(function_info.get("cfg_edges", [])),
            "num_variables": len(function_info.get("variables", [])),
            "num_call_targets": len(function_info.get("call_graph", [])),
        }

        return FunctionEmbedding(
            function_name=name,
            function_address=address,
            embedding=emb,
            confidence=1.0,
            metadata=metadata,
        )

    def batch_embed(self, functions_info: List[Dict[str, Any]]) -> List[FunctionEmbedding]:
        results: List[FunctionEmbedding] = []
        i = 0
        while i < len(functions_info):
            results.append(self.embed_function(functions_info[i]))
            i += 1
        return results

    def compute_similarity(self, embedding_a: Any, embedding_b: Any) -> float:
        """计算两个嵌入向量的余弦相似度。"""
        a = np.asarray(embedding_a, dtype=float)
        b = np.asarray(embedding_b, dtype=float)
        if a.shape != b.shape:
            min_len = min(len(a), len(b))
            a = a[:min_len]
            b = b[:min_len]
        na = np.linalg.norm(a)
        nb = np.linalg.norm(b)
        if na == 0.0 or nb == 0.0:
            return 0.0
        return float(np.dot(a, b) / (na * nb))

    def search_graph_database(self, query: FunctionGraph,
                              database: List[FunctionGraph],
                              top_k: int = 10) -> List[SimilarityResult]:
        """在图数据库中搜索与查询图最相似的函数。"""
        query_result = self.embed(query)
        query_emb = query_result.embedding

        scored: List[SimilarityResult] = []
        gi = 0
        while gi < len(database):
            graph = database[gi]
            result = self.embed(graph)
            sim = self._cosine_similarity(query_emb, result.embedding)
            dist = self._euclidean_distance(query_emb, result.embedding)
            scored.append(SimilarityResult(
                function_a=query.function_name,
                function_b=graph.function_name,
                embedding_a=list(query_emb),
                embedding_b=list(result.embedding),
                cosine_similarity=sim,
                euclidean_distance=dist,
                is_match=sim > 0.85,
                confidence=sim,
            ))
            gi += 1

        scored.sort(key=lambda x: x.cosine_similarity, reverse=True)
        return scored[:top_k]

    def search_similar(self, query_embedding: Any, top_k: int = 10) -> SearchResult:
        """在缓存中搜索与查询向量最相似的函数。"""
        query = np.asarray(query_embedding, dtype=float)
        scored: List[Tuple[str, float]] = []
        for name, emb in self.embedding_cache.items():
            sim = self.compute_similarity(query, emb)
            scored.append((name, sim))
        scored.sort(key=lambda x: x[1], reverse=True)
        return SearchResult(top_k=top_k, similar_functions=scored[:top_k])

    def save_embeddings(self, filepath: str) -> bool:
        """保存嵌入缓存到文件。"""
        try:
            import pickle as _pk
            data = {k: np.asarray(v) for k, v in self.embedding_cache.items()}
            with open(filepath, 'wb') as f:
                _pk.dump(data, f)
            return True
        except Exception as e:
            __dbg.error(f"保存嵌入失败: {e}")
            return False

    def load_embeddings(self, filepath: str) -> bool:
        """从文件加载嵌入缓存。"""
        try:
            import pickle as _pk
            with open(filepath, 'rb') as f:
                data = _pk.load(f)
            self.embedding_cache = {k: np.asarray(v) for k, v in data.items()}
            return True
        except Exception as e:
            __dbg.error(f"加载嵌入失败: {e}")
            return False

    def embed(self, graph: FunctionGraph) -> EmbeddingResult:
        cache_key = f"{graph.function_name}_{graph.function_address}"
        if cache_key in self.m_cache:
            return self.m_cache[cache_key]
        result = self.m_model.embed(graph)
        self.m_cache[cache_key] = result
        return result

    def embed_batch(self, graphs: List[FunctionGraph]) -> List[EmbeddingResult]:
        results: List[EmbeddingResult] = []
        gi = 0
        while gi < len(graphs):
            results.append(self.embed(graphs[gi]))
            gi += 1
        return results

    def _cosine_similarity(self, a: List[float], b: List[float]) -> float:
        if len(a) != len(b) or len(a) == 0:
            return 0.0
        dot = 0.0
        na = 0.0
        nb = 0.0
        i = 0
        while i < len(a):
            dot += a[i] * b[i]
            na += a[i] * a[i]
            nb += b[i] * b[i]
            i += 1
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (_math.sqrt(na) * _math.sqrt(nb))

    def _euclidean_distance(self, a: List[float], b: List[float]) -> float:
        if len(a) != len(b):
            return float('inf')
        s = 0.0
        i = 0
        while i < len(a):
            d = a[i] - b[i]
            s += d * d
            i += 1
        return _math.sqrt(s)

    def clear_cache(self):
        self.m_cache.clear()
        self.embedding_cache.clear()


# 多视图 GNN Embedder Analyzer

class MultiViewGNNEmbedderAnalyzer:
    """函数图嵌入与比较的 Analyzer。
    兼容 functions/search_query 接口与 graphs/query_graphs 接口。"""

    def __init__(self, input_dim=64, hidden_dim=128, output_dim=512):
        self.embedder = MultiViewGNNEmbedder(input_dim, hidden_dim, output_dim)
        self.m_embedder = self.embedder
        self.m_database: List[FunctionGraph] = []
        self.m_results: Dict[str, Any] = {}

    def get_name(self) -> str:
        return "MultiViewGNNEmbedderAnalyzer"

    def get_version(self) -> str:
        return "1.0.0"

    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """校验分析输入参数。"""
        functions = kwargs.get("functions")
        if functions is not None:
            if not isinstance(functions, list):
                return False, "functions 必须是列表类型"
        return True, None

    def analyze(self, **kwargs) -> Dict[str, Any]:
        """执行分析任务，支持函数嵌入与相似度搜索两种模式。"""
        functions = kwargs.get("functions")
        search_query = kwargs.get("search_query")
        graphs = kwargs.get("graphs", [])
        query_graphs = kwargs.get("query_graphs", [])
        top_k = kwargs.get("top_k", 10)

        is_valid, error = self.validate_input(functions=functions if functions is not None else [])
        if not is_valid:
            return {"success": False, "error": error}

        if functions is not None:
            embeddings = self.embedder.batch_embed(functions)
            self.m_results = {
                "success": True,
                "embeddings": [
                    {
                        "function_name": e.function_name,
                        "function_address": e.function_address,
                        "embedding": e.embedding,
                        "confidence": e.confidence,
                        "metadata": e.metadata,
                    }
                    for e in embeddings
                ],
            }
            return self.m_results

        if search_query is not None:
            query = np.asarray(search_query, dtype=float)
            result = self.embedder.search_similar(query, top_k=top_k)
            self.m_results = {
                "success": True,
                "search_result": {
                    "top_k": result.top_k,
                    "similar_functions": result.similar_functions,
                },
            }
            return self.m_results

        self.m_database = []
        gi = 0
        while gi < len(graphs):
            if isinstance(graphs[gi], FunctionGraph):
                self.m_database.append(graphs[gi])
            gi += 1

        results = {}
        if query_graphs and self.m_database:
            qi = 0
            while qi < len(query_graphs):
                qg = query_graphs[qi]
                if isinstance(qg, FunctionGraph):
                    sims = self.embedder.search_graph_database(qg, self.m_database, top_k)
                    results[qg.function_name] = sims
                qi += 1

        self.m_results = {
            "database_size": len(self.m_database),
            "query_count": len(query_graphs) if query_graphs else 0,
            "results": results,
        }
        return dict(self.m_results)

    def cleanup(self) -> None:
        """释放嵌入器资源。"""
        self.embedder = None
        self.m_embedder = None

    def add_to_database(self, graph: FunctionGraph):
        self.m_database.append(graph)

    def embed_and_store(self, graph: FunctionGraph) -> EmbeddingResult:
        self.m_database.append(graph)
        return self.embedder.embed(graph)

    def search(self, query: FunctionGraph, top_k: int = 10) -> List[SimilarityResult]:
        return self.embedder.search_graph_database(query, self.m_database, top_k)


# 图构建工具 -- 增强版，自动计算图结构全局特征

def build_function_graph_from_blocks(function_name: str, function_address: int,
                                     blocks: List[Dict[str, Any]],
                                      edges: List[Tuple[int, int, str]] = None) -> FunctionGraph:

    graph = FunctionGraph(
        function_name=function_name,
        function_address=function_address,
        num_basic_blocks=len(blocks),
        num_instructions=sum(b.get("num_instructions", 0) for b in blocks),
    )

    bi = 0
    while bi < len(blocks):
        block = blocks[bi]
        features: List[float] = []
        features.append(float(block.get("num_instructions", 1)))
        features.append(float(block.get("num_calls", 0)))
        features.append(float(len(block.get("string_refs", []))))
        features.append(float(len(block.get("constants", []))))
        features.append(float(block.get("in_degree", 0)))
        features.append(float(block.get("out_degree", 0)))

        while len(features) < 64:
            features.append(0.0)

        node = GraphNode(
            node_id=bi,
            node_type=block.get("type", "basic_block"),
            features=features[:64],
            address=block.get("address", 0),
            label=block.get("label", f"block_{bi}"),
            num_instructions=block.get("num_instructions", 0),
            num_calls=block.get("num_calls", 0),
            string_refs=block.get("string_refs", []),
            constants=block.get("constants", []),
            in_degree=block.get("in_degree", 0),
            out_degree=block.get("out_degree", 0),
        )
        graph.nodes.append(node)
        bi += 1

    total_edges = 0
    if edges:
        ei = 0
        while ei < len(edges):
            src, dst, etype = edges[ei]
            edge = GraphEdge(edge_id=ei, source_id=src, target_id=dst, edge_type=etype)
            if etype == "data_flow":
                graph.dfg_edges.append(edge)
            elif etype == "call":
                graph.call_edges.append(edge)
            elif etype == "memory":
                graph.memory_edges.append(edge)
            else:
                graph.cfg_edges.append(edge)
            total_edges += 1
            ei += 1

    # 计算图结构全局特征
    n = len(graph.nodes)
    if n > 0:
        # 圈复杂度近似: E - N + 2
        graph.cyclomatic_complexity = max(1, total_edges - n + 2)
        # 平均度数
        graph.avg_degree = (2.0 * total_edges) / n
        # 边密度: E / (N*(N-1)) 有向图
        max_possible = n * (n - 1) if n > 1 else 1
        graph.edge_density = total_edges / max_possible
    else:
        graph.cyclomatic_complexity = 1
        graph.avg_degree = 0.0
        graph.edge_density = 0.0

    return graph
