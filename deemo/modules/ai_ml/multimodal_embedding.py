#!/usr/bin/env python3
# Multimodal 嵌入 — CFG 图, instruction text, and structural feature fusion
# with confidence-weighted blending and signal-richness 归一化.
# confidence-weighted fusion with softmax-normalized weights
# derived from signal richness metrics.
# 单轮消息传递 GNN 邻域聚合；注意力池化替代均值池化；
# FusionResult 序列化/反序列化支持缓存与跨服务传输。

import logging as _logging
import math as _math
import json as _json
import hashlib as _hashlib
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple


__dbg = _logging.getLogger(__name__)


# Data classes

@dataclass
class GraphEmbedding:
    """Embedding produced from a CFG graph structure."""
    vector: List[float] = field(default_factory=list)
    dimension: int = 128
    method: str = "GCN"
    graph_size: int = 0
    edge_count: int = 0
    signal_richness: float = 0.0

    def norm(self) -> float:
        return _math.sqrt(sum(v * v for v in self.vector)) if self.vector else 0.0


@dataclass
class TextEmbedding:
    """Embedding produced from instruction text / mnemonics."""
    vector: List[float] = field(default_factory=list)
    dimension: int = 256
    method: str = "BERT"
    sequence_length: int = 0
    vocabulary_coverage: float = 0.0
    signal_richness: float = 0.0

    def norm(self) -> float:
        return _math.sqrt(sum(v * v for v in self.vector)) if self.vector else 0.0


@dataclass
class StructuralFeatures:
    """Hand-crafted structural features of a function."""
    num_instructions: int = 0
    num_basic_blocks: int = 0
    num_calls: int = 0
    num_loops: int = 0
    num_conditional_branches: int = 0
    cyclomatic_complexity: int = 0
    num_local_variables: int = 0
    stack_frame_size: int = 0
    num_arguments: int = 0
    nesting_depth: int = 0
    instruction_density: float = 0.0
    vector: List[float] = field(default_factory=list)
    signal_richness: float = 0.0

    def to_vector(self) -> List[float]:
        v = [
            float(self.num_instructions),
            float(self.num_basic_blocks),
            float(self.num_calls),
            float(self.num_loops),
            float(self.num_conditional_branches),
            float(self.cyclomatic_complexity),
            float(self.num_local_variables),
            float(self.stack_frame_size),
            float(self.num_arguments),
            float(self.nesting_depth),
            self.instruction_density,
        ]
        self.vector = v
        return v


@dataclass
class FusionResult:
    """Result of fusing graph, text, and structural embeddings."""
    fused_vector: List[float] = field(default_factory=list)
    dimension: int = 512
    graph_weight: float = 0.0
    text_weight: float = 0.0
    structural_weight: float = 0.0
    confidence: float = 0.0
    graph_embedding: Optional[GraphEmbedding] = None
    text_embedding: Optional[TextEmbedding] = None
    structural_features: Optional[StructuralFeatures] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    # 序列化 — 缓存落盘 & 跨服务 payload 编解码用
    def to_dict(self) -> Dict[str, Any]:
        """Serialize to a JSON-friendly dictionary."""
        d: Dict[str, Any] = {
            "fused_vector": self.fused_vector,
            "dimension": self.dimension,
            "graph_weight": self.graph_weight,
            "text_weight": self.text_weight,
            "structural_weight": self.structural_weight,
            "confidence": self.confidence,
            "metadata": self.metadata,
        }
        if self.graph_embedding is not None:
            d["graph_embedding"] = {
                "vector": self.graph_embedding.vector,
                "dimension": self.graph_embedding.dimension,
                "method": self.graph_embedding.method,
                "graph_size": self.graph_embedding.graph_size,
                "edge_count": self.graph_embedding.edge_count,
                "signal_richness": self.graph_embedding.signal_richness,
            }
        if self.text_embedding is not None:
            d["text_embedding"] = {
                "vector": self.text_embedding.vector,
                "dimension": self.text_embedding.dimension,
                "method": self.text_embedding.method,
                "sequence_length": self.text_embedding.sequence_length,
                "vocabulary_coverage": self.text_embedding.vocabulary_coverage,
                "signal_richness": self.text_embedding.signal_richness,
            }
        if self.structural_features is not None:
            sf = self.structural_features
            d["structural_features"] = {
                "num_instructions": sf.num_instructions,
                "num_basic_blocks": sf.num_basic_blocks,
                "num_calls": sf.num_calls,
                "num_loops": sf.num_loops,
                "num_conditional_branches": sf.num_conditional_branches,
                "cyclomatic_complexity": sf.cyclomatic_complexity,
                "num_local_variables": sf.num_local_variables,
                "stack_frame_size": sf.stack_frame_size,
                "num_arguments": sf.num_arguments,
                "nesting_depth": sf.nesting_depth,
                "instruction_density": sf.instruction_density,
                "vector": sf.vector,
                "signal_richness": sf.signal_richness,
            }
        return d

    # 反序列化 — 从缓存或 RPC 回包重建对象
    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "FusionResult":
        """Deserialize from a dictionary back to a FusionResult."""
        ge = None
        if "graph_embedding" in d and d["graph_embedding"] is not None:
            gd = d["graph_embedding"]
            ge = GraphEmbedding(
                vector=gd.get("vector", []),
                dimension=gd.get("dimension", 128),
                method=gd.get("method", "GCN"),
                graph_size=gd.get("graph_size", 0),
                edge_count=gd.get("edge_count", 0),
                signal_richness=gd.get("signal_richness", 0.0),
            )
        te = None
        if "text_embedding" in d and d["text_embedding"] is not None:
            td = d["text_embedding"]
            te = TextEmbedding(
                vector=td.get("vector", []),
                dimension=td.get("dimension", 256),
                method=td.get("method", "BERT"),
                sequence_length=td.get("sequence_length", 0),
                vocabulary_coverage=td.get("vocabulary_coverage", 0.0),
                signal_richness=td.get("signal_richness", 0.0),
            )
        sf = None
        if "structural_features" in d and d["structural_features"] is not None:
            sd = d["structural_features"]
            sf = StructuralFeatures(
                num_instructions=sd.get("num_instructions", 0),
                num_basic_blocks=sd.get("num_basic_blocks", 0),
                num_calls=sd.get("num_calls", 0),
                num_loops=sd.get("num_loops", 0),
                num_conditional_branches=sd.get("num_conditional_branches", 0),
                cyclomatic_complexity=sd.get("cyclomatic_complexity", 0),
                num_local_variables=sd.get("num_local_variables", 0),
                stack_frame_size=sd.get("stack_frame_size", 0),
                num_arguments=sd.get("num_arguments", 0),
                nesting_depth=sd.get("nesting_depth", 0),
                instruction_density=sd.get("instruction_density", 0.0),
                vector=sd.get("vector", []),
                signal_richness=sd.get("signal_richness", 0.0),
            )
        return FusionResult(
            fused_vector=d.get("fused_vector", []),
            dimension=d.get("dimension", 512),
            graph_weight=d.get("graph_weight", 0.0),
            text_weight=d.get("text_weight", 0.0),
            structural_weight=d.get("structural_weight", 0.0),
            confidence=d.get("confidence", 0.0),
            graph_embedding=ge,
            text_embedding=te,
            structural_features=sf,
            metadata=d.get("metadata", {}),
        )


# CFG Graph Embedder

class CFGGraphEmbedder:
    """Embeds a function's control-flow graph into a fixed-size vector."""

    __slots__ = ('m_dim', 'm_method', 'm_weights')

    def __init__(self, dim: int = 128, method: str = "GCN"):
        self.m_dim = dim
        self.m_method = method
        self.m_weights: List[List[float]] = self._init_weights(64, dim)

    def _init_weights(self, in_dim: int, out_dim: int) -> List[List[float]]:
        import random as _r
        _r.seed(42)
        limit = _math.sqrt(6.0 / (in_dim + out_dim))
        w: List[List[float]] = []
        ri = 0
        while ri < in_dim:
            row: List[float] = []
            ci = 0
            while ci < out_dim:
                row.append(_r.uniform(-limit, limit))
                ci += 1
            w.append(row)
            ri += 1
        return w

    def _build_adjacency(self, n: int,
                         edges: List[Tuple[int, int, float]]) -> List[List[int]]:
        """构建邻接表用于单跳消息传递。INTJ 直觉：控制流边天然有向，
        但这里做对称化（入边+出边）以捕获双向结构上下文。"""
        adj: List[List[int]] = [[] for _ in range(n)]
        ei = 0
        while ei < len(edges):
            src, dst, _ = edges[ei]
            if 0 <= src < n and 0 <= dst < n:
                adj[src].append(dst)
                adj[dst].append(src)  # 对称化捕获双向结构上下文
            ei += 1
        return adj

    def embed(self, nodes: List[Dict[str, Any]],
              edges: List[Tuple[int, int, float]] = None) -> GraphEmbedding:
        n = len(nodes)
        e = len(edges) if edges else 0

        # 原始特征抽取
        node_features: List[List[float]] = []
        ni = 0
        while ni < n:
            nd = nodes[ni]
            feats: List[float] = []
            feats.append(float(nd.get("num_instructions", 0)))
            feats.append(float(nd.get("num_calls", 0)))
            feats.append(float(nd.get("out_degree", 0)))
            feats.append(float(nd.get("in_degree", 0)))
            feats.append(float(nd.get("is_loop_header", 0)))
            feats.append(float(nd.get("is_loop_exit", 0)))
            feats.append(float(len(nd.get("string_refs", []))))
            feats.append(float(len(nd.get("constants", []))))
            while len(feats) < 64:
                feats.append(0.0)
            node_features.append(feats[:64])
            ni += 1

        if n == 0:
            return GraphEmbedding(
                vector=[0.0] * self.m_dim,
                dimension=self.m_dim,
                method=self.m_method,
                graph_size=n,
                edge_count=e,
                signal_richness=0.0,
            )

        # 单轮消息传递 — 邻域均值聚合，残差连接保留自身信息
        # 原本 edges 只用于 richness 计数，现在真正参与图卷积。
        propagated: List[List[float]] = []
        if edges and len(edges) > 0:
            adj = self._build_adjacency(n, edges)
            ni = 0
            while ni < n:
                neighbors = adj[ni]
                feat = list(node_features[ni])  # 自身特征
                if neighbors:
                    # 邻域均值聚合
                    agg = [0.0] * 64
                    nbi = 0
                    while nbi < len(neighbors):
                        j = 0
                        while j < 64:
                            agg[j] += node_features[neighbors[nbi]][j]
                            j += 1
                        nbi += 1
                    deg = len(neighbors)
                    j = 0
                    while j < 64:
                        agg[j] /= deg
                        j += 1
                    # 残差融合: h' = 0.5 * h_self + 0.5 * h_neighbors
                    j = 0
                    while j < 64:
                        feat[j] = feat[j] * 0.5 + agg[j] * 0.5
                        j += 1
                propagated.append(feat)
                ni += 1
        else:
            propagated = node_features

        pooled = [0.0] * 64
        ni = 0
        while ni < n:
            j = 0
            while j < 64:
                pooled[j] += propagated[ni][j]
                j += 1
            ni += 1

        j = 0
        while j < 64:
            pooled[j] /= n
            j += 1

        vec: List[float] = []
        di = 0
        while di < self.m_dim:
            val = 0.0
            j = 0
            while j < 64:
                val += pooled[j] * self.m_weights[j][di]
                j += 1
            vec.append(max(0.0, val))
            di += 1

        norm = _math.sqrt(sum(v * v for v in vec))
        if norm > 0:
            di = 0
            while di < len(vec):
                vec[di] /= norm
                di += 1

        richness = min(1.0, (n * 0.05 + e * 0.01))

        return GraphEmbedding(
            vector=vec,
            dimension=self.m_dim,
            method=self.m_method,
            graph_size=n,
            edge_count=e,
            signal_richness=richness,
        )


# Instruction Text Embedder

class InstructionTextEmbedder:
    """Embeds assembly instruction sequences into vector space."""

    __slots__ = ('m_dim', 'm_method', 'm_vocabulary', 'm_unk_vector',
                 'm_attn_query', 'm_attn_key', 'm_attn_value')

    INSTRUCTION_SET = [
        "mov", "push", "pop", "call", "ret", "jmp", "je", "jne", "jg", "jl",
        "jge", "jle", "ja", "jb", "jae", "jbe", "cmp", "test", "add", "sub",
        "mul", "imul", "div", "idiv", "xor", "or", "and", "not", "neg",
        "shl", "shr", "sar", "rol", "ror", "lea", "nop", "int", "syscall",
        "inc", "dec", "xchg", "cmpxchg", "pushf", "popf",
        "enter", "leave", "retn", "loop", "loope", "loopne",
        "movsx", "movzx", "cdq", "cqo", "cwd", "cbw", "cwde", "cdqe",
        "sete", "setne", "setg", "setl", "setge", "setle",
        "vmovdqa", "vmovdqu", "vpaddd", "vpsubd", "vpxor",
    ]

    def __init__(self, dim: int = 256, method: str = "BERT"):
        self.m_dim = dim
        self.m_method = method
        self.m_vocabulary: Dict[str, int] = {}
        self.m_unk_vector: List[float] = []

        ii = 0
        while ii < len(self.INSTRUCTION_SET):
            self.m_vocabulary[self.INSTRUCTION_SET[ii]] = ii
            ii += 1

        import random as _r
        _r.seed(99)
        self.m_unk_vector = [_r.uniform(-0.1, 0.1) for _ in range(dim)]

        # 注意力参数 — 可学习的 Q/K/V 投影 + 全局上下文向量
        # INTJ 设计决策：用浅层加性注意力而非缩放点积，
        # 理由是汇编序列短（<512 条指令），计算开销可忽略，
        # 且加性注意力在小维度上稳定性更好。
        self.m_attn_query: List[List[float]] = self._init_weights(dim, dim // 4)
        self.m_attn_key: List[List[float]] = self._init_weights(dim, dim // 4)
        self.m_attn_value: List[List[float]] = self._init_weights(dim, dim)
        # 全局上下文向量（可学习）— 与投影后的 查询 做内积得到注意力分数
        _r.seed(101)
        self.m_context: List[float] = [_r.uniform(-0.2, 0.2) for _ in range(dim // 4)]

    def _init_weights(self, in_dim: int, out_dim: int) -> List[List[float]]:
        import random as _r
        limit = _math.sqrt(6.0 / (in_dim + out_dim))
        w: List[List[float]] = []
        ri = 0
        while ri < in_dim:
            row: List[float] = []
            ci = 0
            while ci < out_dim:
                row.append(_r.uniform(-limit, limit))
                ci += 1
            w.append(row)
            ri += 1
        return w

    def _matvec(self, mat: List[List[float]], vec: List[float]) -> List[float]:
        """矩阵乘向量 — 内部工具，不暴露。"""
        out: List[float] = []
        ri = 0
        while ri < len(mat):
            val = 0.0
            c = 0
            while c < len(mat[ri]) and c < len(vec):
                val += mat[ri][c] * vec[c]
                c += 1
            out.append(val)
            ri += 1
        return out

    def embed(self, instructions: List[str]) -> TextEmbedding:
        seq_len = len(instructions)
        tokens_known = 0

        instr_embs: List[List[float]] = []
        ii = 0
        while ii < len(instructions):
            instr = instructions[ii].strip()
            parts = instr.split()
            opcode = parts[0].lower() if parts else ""

            emb = self._token_embedding(opcode)
            instr_embs.append(emb)

            if opcode in self.m_vocabulary:
                tokens_known += 1

            ii += 1

        if not instr_embs:
            return TextEmbedding(
                vector=[0.0] * self.m_dim,
                dimension=self.m_dim,
                method=self.m_method,
                sequence_length=seq_len,
                vocabulary_coverage=0.0,
                signal_richness=0.0,
            )

        # 注意力加权池化替代朴素均值池化
        # 流程: 每个 token → Q/K/V 投影 → 与全局上下文向量做内积得原始分数
        # → softmax → 加权求和 V → 序列表示
        scores: List[float] = []
        values: List[List[float]] = []
        ei = 0
        while ei < len(instr_embs):
            emb = instr_embs[ei]
            q = self._matvec(self.m_attn_query, emb)     # dim//4
            v = self._matvec(self.m_attn_value, emb)     # dim
            # 加性注意力: score = context^T * q
            score = 0.0
            j = 0
            while j < len(q) and j < len(self.m_context):
                score += q[j] * self.m_context[j]
                j += 1
            scores.append(score)
            values.append(v)
            ei += 1

        # Softmax 归一化注意力权重
        max_score = scores[0]
        ei = 1
        while ei < len(scores):
            if scores[ei] > max_score:
                max_score = scores[ei]
            ei += 1
        exp_scores: List[float] = []
        ei = 0
        while ei < len(scores):
            exp_scores.append(_math.exp(scores[ei] - max_score))
            ei += 1
        sum_exp = sum(exp_scores)
        if sum_exp == 0:
            sum_exp = 1.0
        attn_weights: List[float] = []
        ei = 0
        while ei < len(exp_scores):
            attn_weights.append(exp_scores[ei] / sum_exp)
            ei += 1

        # 加权求和
        pooled = [0.0] * self.m_dim
        ei = 0
        while ei < len(values):
            wt = attn_weights[ei]
            j = 0
            while j < self.m_dim and j < len(values[ei]):
                pooled[j] += values[ei][j] * wt
                j += 1
            ei += 1

        norm = _math.sqrt(sum(v * v for v in pooled))
        if norm > 0:
            j = 0
            while j < len(pooled):
                pooled[j] /= norm
                j += 1

        vocab_coverage = tokens_known / max(seq_len, 1)
        richness = min(1.0, seq_len * 0.01 + vocab_coverage * 0.5)

        return TextEmbedding(
            vector=pooled,
            dimension=self.m_dim,
            method=self.m_method,
            sequence_length=seq_len,
            vocabulary_coverage=vocab_coverage,
            signal_richness=richness,
        )

    def _token_embedding(self, opcode: str) -> List[float]:
        import random as _r
        if opcode in self.m_vocabulary:
            idx = self.m_vocabulary[opcode]
            _r.seed(idx + 1000)
            return [_r.uniform(-0.5, 0.5) for _ in range(self.m_dim)]
        return list(self.m_unk_vector)

    # 导出注意力权重 — 诊断/可视化用，看哪些指令被模型"看重"
    def attention_weights(self, instructions: List[str]) -> List[Tuple[str, float]]:
        """Returns (opcode, attention_weight) sorted by weight descending."""
        if not instructions:
            return []
        instr_embs: List[List[float]] = []
        for instr in instructions:
            parts = instr.strip().split()
            opcode = parts[0].lower() if parts else ""
            instr_embs.append(self._token_embedding(opcode))

        scores: List[float] = []
        for emb in instr_embs:
            q = self._matvec(self.m_attn_query, emb)
            score = 0.0
            j = 0
            while j < len(q) and j < len(self.m_context):
                score += q[j] * self.m_context[j]
                j += 1
            scores.append(score)

        max_score = max(scores) if scores else 0.0
        exp_scores = [_math.exp(s - max_score) for s in scores]
        sum_exp = sum(exp_scores) or 1.0
        attn_weights = [es / sum_exp for es in exp_scores]

        pairs: List[Tuple[str, float]] = []
        for i, instr in enumerate(instructions):
            parts = instr.strip().split()
            op = parts[0].lower() if parts else "?"
            pairs.append((op, attn_weights[i]))
        # 按权重降序排列
        pairs.sort(key=lambda x: x[1], reverse=True)
        return pairs


# Structural Feature Extractor

class StructuralFeatureExtractor:
    """Extracts hand-crafted structural features from a function."""

    __slots__ = ()

    def extract(self, function_info: Dict[str, Any]) -> StructuralFeatures:
        sf = StructuralFeatures(
            num_instructions=function_info.get("num_instructions", 0),
            num_basic_blocks=function_info.get("num_basic_blocks", 0),
            num_calls=function_info.get("num_calls", 0),
            num_loops=function_info.get("num_loops", 0),
            num_conditional_branches=function_info.get("num_conditional_branches", 0),
            cyclomatic_complexity=function_info.get("cyclomatic_complexity", 0),
            num_local_variables=function_info.get("num_local_variables", 0),
            stack_frame_size=function_info.get("stack_frame_size", 0),
            num_arguments=function_info.get("num_arguments", 0),
            nesting_depth=function_info.get("nesting_depth", 0),
        )

        if sf.num_basic_blocks > 0:
            sf.instruction_density = sf.num_instructions / sf.num_basic_blocks

        sf.to_vector()

        non_zero = 0
        total = len(sf.vector) if sf.vector else 1
        vi = 0
        while vi < len(sf.vector):
            if sf.vector[vi] > 0:
                non_zero += 1
            vi += 1
        sf.signal_richness = non_zero / total

        return sf


# Multi-Modal Embedder

class MultiModalEmbedder:
    """Fuses graph, text, and structural embeddings using confidence-weighted fusion.

    The embed() method uses softmax-normalized weights derived from
    signal richness metrics for each modality.
    """

    __slots__ = ('m_graph_embedder', 'm_text_embedder', 'm_structural_extractor',
                 'm_output_dim')

    def __init__(self, graph_dim: int = 128, text_dim: int = 256, output_dim: int = 512):
        self.m_graph_embedder = CFGGraphEmbedder(dim=graph_dim)
        self.m_text_embedder = InstructionTextEmbedder(dim=text_dim)
        self.m_structural_extractor = StructuralFeatureExtractor()
        self.m_output_dim = output_dim

    def embed(self, nodes: List[Dict[str, Any]],
              edges: Optional[List[Tuple[int, int, float]]] = None,
              instructions: Optional[List[str]] = None,
              function_info: Optional[Dict[str, Any]] = None) -> FusionResult:
        """Fuse embeddings from all three modalities using confidence-weighted blending.

        Graph, text, and structural vectors are blended with softmax-normalized
        weights derived from signal richness metrics.
        """
        # Graph 嵌入
        graph_emb = self.m_graph_embedder.embed(nodes, edges)

        # Text 嵌入
        if instructions is None:
            instructions = []
        text_emb = self.m_text_embedder.embed(instructions)

        # Structural features
        if function_info is None:
            function_info = {}
        struct_feat = self.m_structural_extractor.extract(function_info)

        # Signal richness metrics
        g_richness = max(graph_emb.signal_richness, 1e-6)
        t_richness = max(text_emb.signal_richness, 1e-6)
        s_richness = max(struct_feat.signal_richness, 1e-6)

        # Softmax-normalized fusion weights
        exp_g = _math.exp(g_richness)
        exp_t = _math.exp(t_richness)
        exp_s = _math.exp(s_richness)
        total_exp = exp_g + exp_t + exp_s

        w_graph = exp_g / total_exp
        w_text = exp_t / total_exp
        w_struct = exp_s / total_exp

        # Pad/truncate each modality to output_dim
        g_vec = self._pad_to_dim(graph_emb.vector, self.m_output_dim)
        t_vec = self._pad_to_dim(text_emb.vector, self.m_output_dim)
        s_vec = self._pad_to_dim(struct_feat.vector, self.m_output_dim)

        # Weighted fusion
        fused: List[float] = []
        di = 0
        while di < self.m_output_dim:
            val = g_vec[di] * w_graph + t_vec[di] * w_text + s_vec[di] * w_struct
            fused.append(val)
            di += 1

        # L2 normalize fused 向量
        norm = _math.sqrt(sum(v * v for v in fused))
        if norm > 0:
            di = 0
            while di < len(fused):
                fused[di] /= norm
                di += 1

        # Overall confidence
        confidence = (w_graph * graph_emb.signal_richness +
                      w_text * text_emb.signal_richness +
                      w_struct * struct_feat.signal_richness)

        return FusionResult(
            fused_vector=fused,
            dimension=self.m_output_dim,
            graph_weight=w_graph,
            text_weight=w_text,
            structural_weight=w_struct,
            confidence=confidence,
            graph_embedding=graph_emb,
            text_embedding=text_emb,
            structural_features=struct_feat,
            metadata={
                "graph_signal": graph_emb.signal_richness,
                "text_signal": text_emb.signal_richness,
                "structural_signal": struct_feat.signal_richness,
            },
        )

    def _pad_to_dim(self, vec: List[float], target_dim: int) -> List[float]:
        if len(vec) >= target_dim:
            return vec[:target_dim]
        padded = list(vec)
        while len(padded) < target_dim:
            padded.append(0.0)
        return padded

    def embed_batch(self, batch: List[Dict[str, Any]]) -> List[FusionResult]:
        results: List[FusionResult] = []
        bi = 0
        while bi < len(batch):
            item = batch[bi]
            result = self.embed(
                nodes=item.get("nodes", []),
                edges=item.get("edges"),
                instructions=item.get("instructions"),
                function_info=item.get("function_info"),
            )
            results.append(result)
            bi += 1
        return results

    def cosine_similarity(self, a: FusionResult, b: FusionResult) -> float:
        if len(a.fused_vector) != len(b.fused_vector) or len(a.fused_vector) == 0:
            return 0.0
        dot = 0.0
        na = 0.0
        nb = 0.0
        i = 0
        while i < len(a.fused_vector):
            dot += a.fused_vector[i] * b.fused_vector[i]
            na += a.fused_vector[i] * a.fused_vector[i]
            nb += b.fused_vector[i] * b.fused_vector[i]
            i += 1
        if na == 0.0 or nb == 0.0:
            return 0.0
        return dot / (_math.sqrt(na) * _math.sqrt(nb))


# Convenience

def create_multimodal_embedder(graph_dim=128, text_dim=256, output_dim=512) -> MultiModalEmbedder:
    return MultiModalEmbedder(graph_dim=graph_dim, text_dim=text_dim, output_dim=output_dim)
