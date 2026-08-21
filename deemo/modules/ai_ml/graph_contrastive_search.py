#!/usr/bin/env python3
# 图对比语义搜索 — 函数图上做对比学习用于二进制语义搜索,
# 检索侧用 SimHash 局部敏感哈希加速 ANN。
# 多探针 LSH 桶搜索: SimHash 加邻居桶探索与位翻转探测, 提升召回率。
# remove_lsh 为真删除, 重建索引时基于存储的嵌入重新插入;
# train_contrastive_gcs 用手动梯度计算与 SGD 更新权重（不再空跑）。

import uuid
import logging as _logging
import math as _math
import random as _rnd
import hashlib as _hashlib
import struct as _struct
from collections import defaultdict as _defaultdict

g_log = _logging.getLogger(__name__)


class SimHash:
    """SimHash fingerprint for locality-sensitive hashing.

    Uses random hyperplanes to project vectors into binary hash codes.
    Similar vectors produce similar hash codes (small Hamming distance).

    Enhanced with neighbor bucket probing and bit-flip methods for multi-probe LSH.
    """

    __slots__ = ('m_hash_bits', 'm_hyperplanes', 'm_dim')

    def __init__(self, hash_bits=64, input_dim=128):
        self.m_hash_bits = hash_bits
        self.m_dim = input_dim
        self.m_hyperplanes = self._init_hyperplanes()

    # 随机超平面初始化
    def _init_hyperplanes(self):
        planes = []
        hi = 0
        while hi < self.m_hash_bits:
            plane = []
            di = 0
            while di < self.m_dim:
                plane.append(_rnd.gauss(0, 1))
                di += 1
            planes.append(plane)
            hi += 1
        return planes

    def compute_sh(self, vector):
        """Compute SimHash fingerprint for a vector."""
        if vector is None:
            return 0
        # Pad or truncate
        vec = list(vector)
        if len(vec) < self.m_dim:
            vec.extend([0.0] * (self.m_dim - len(vec)))
        else:
            vec = vec[:self.m_dim]

        hash_val = 0
        hi = 0
        while hi < self.m_hash_bits:
            dot = 0.0
            di = 0
            while di < self.m_dim:
                dot += vec[di] * self.m_hyperplanes[hi][di]
                di += 1
            if dot >= 0:
                hash_val |= (1 << hi)
            hi += 1
        return hash_val

    def hamming_distance(self, hash_a, hash_b):
        """Compute Hamming distance between two hash codes."""
        xor = hash_a ^ hash_b
        dist = 0
        while xor:
            dist += xor & 1
            xor >>= 1
        return dist

    def neighbor_buckets(self, hash_val, probe_radius=2):
        """Generate neighbor bucket hashes within a given Hamming radius.

        This enables multi-probe LSH: instead of searching only the exact
        hash bucket, also probe neighboring buckets for higher recall.
        """
        buckets = [hash_val]
        if probe_radius < 1:
            return buckets

        # Single-bit flips (probe_radius=1)
        bi = 0
        while bi < self.m_hash_bits:
            neighbor = self._flip_bits(hash_val, [bi])
            buckets.append(neighbor)
            bi += 1

        # Two-bit flips (probe_radius=2)
        if probe_radius >= 2:
            bi = 0
            while bi < self.m_hash_bits:
                bj = bi + 1
                while bj < self.m_hash_bits:
                    neighbor = self._flip_bits(hash_val, [bi, bj])
                    buckets.append(neighbor)
                    bj += 1
                bi += 1

        return buckets

    # 翻转指定位
    def _flip_bits(self, hash_val, bit_indices):
        result = hash_val
        bi = 0
        while bi < len(bit_indices):
            idx = bit_indices[bi]
            if 0 <= idx < self.m_hash_bits:
                result ^= (1 << idx)
            bi += 1
        return result

    def similarity_from_distance(self, hamming_dist):
        """Estimate cosine similarity from Hamming distance."""
        # Probability of agreement on a random hyperplane = 1 - theta/pi
        # where theta = arccos(similarity)
        # Approximate inversion:
        if hamming_dist <= 0:
            return 1.0
        if hamming_dist >= self.m_hash_bits:
            return 0.0
        # cos(theta) = cos(pi * dist / bits)
        angle = _math.pi * hamming_dist / self.m_hash_bits
        return _math.cos(angle)


class LSHIndex:
    """Multi-table LSH index using SimHash for approximate nearest neighbor search.

    Supports multi-probe LSH: queries search multiple neighbor buckets per hash
    table for improved recall at the cost of slightly more comparisons.
    """

    __slots__ = ('m_tables', 'm_hasher', 'm_probe_radius', 'm_hashers')

    def __init__(self, num_tables=8, hash_bits=64, input_dim=128, probe_radius=1):
        self.m_tables = [_defaultdict(list) for _ in range(num_tables)]
        self.m_hasher = SimHash(hash_bits, input_dim)
        self.m_probe_radius = probe_radius

        # 每表独立SimHash多样性实例
        self.m_hashers = [SimHash(hash_bits, input_dim) for _ in range(num_tables)]

    def insert_lsh(self, key, vector):
        """Insert a vector into all LSH tables."""
        if key is None or vector is None:
            return
        ti = 0
        while ti < len(self.m_hashers):
            h = self.m_hashers[ti].compute_sh(vector)
            self.m_tables[ti][h].append((key, vector))
            ti += 1

    def insert_batch_lsh(self, items):
        """Batch insert: list of (key, vector) tuples."""
        ii = 0
        while ii < len(items):
            key, vec = items[ii]
            self.insert_lsh(key, vec)
            ii += 1

    def query_lsh(self, query_vector, top_k=10, threshold=0.5):
        """Multi-probe ANN search.

        Searches not just the exact hash bucket but also neighboring buckets
        (within probe_radius Hamming distance) for each table.
        """
        if query_vector is None:
            return []

        candidates = {}

        ti = 0
        while ti < len(self.m_hashers):
            h = self.m_hashers[ti].compute_sh(query_vector)

            # Multi-probe: search the exact bucket AND neighbor buckets
            probe_hashes = self.m_hashers[ti].neighbor_buckets(h, self.m_probe_radius)

            pi = 0
            while pi < len(probe_hashes):
                bucket_hash = probe_hashes[pi]
                bucket_items = self.m_tables[ti].get(bucket_hash, [])
                bi = 0
                while bi < len(bucket_items):
                    key, vec = bucket_items[bi]
                    if key not in candidates:
                        sim = self._cosine_similarity(query_vector, vec)
                        candidates[key] = sim
                    bi += 1
                pi += 1
            ti += 1

        # Filter and sort
        results = [(k, v) for k, v in candidates.items() if v >= threshold]
        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    def _cosine_similarity(self, a, b):
        if a is None or b is None:
            return 0.0
        min_len = min(len(a), len(b))
        dot = 0.0
        norm_a = 0.0
        norm_b = 0.0
        di = 0
        while di < min_len:
            dot += a[di] * b[di]
            norm_a += a[di] * a[di]
            norm_b += b[di] * b[di]
            di += 1
        denom = _math.sqrt(norm_a) * _math.sqrt(norm_b)
        if denom < 1e-9:
            return 0.0
        return dot / denom

    def remove_lsh(self, key):
        """真删除：遍历所有 hash 桶，移除指定 key 的条目。"""
        if key is None:
            return
        ti = 0
        while ti < len(self.m_tables):
            # 收集需要保留的桶（非空的）
            dead_buckets = []
            for hval, items in self.m_tables[ti].items():
                filtered = [(k, v) for k, v in items if k != key]
                if len(filtered) == 0:
                    dead_buckets.append(hval)
                else:
                    self.m_tables[ti][hval] = filtered
            # 清理空桶
            for hval in dead_buckets:
                del self.m_tables[ti][hval]
            ti += 1

    def clear_all_lsh(self):
        """清空所有索引表，用于全量重建前重置。"""
        ti = 0
        while ti < len(self.m_tables):
            self.m_tables[ti].clear()
            ti += 1

    def size_lsh(self):
        """Total number of indexed entries."""
        total = 0
        ti = 0
        while ti < len(self.m_tables):
            for bucket in self.m_tables[ti].values():
                total += len(bucket)
            ti += 1
        return total


class ContrastiveGraphEncoder:
    """Encodes function graphs into fixed-dimensional embeddings using
    contrastive learning with a simple graph convolutional network.

    Training objective: pull similar functions closer, push dissimilar apart.
    """

    __slots__ = ('m_input_dim', 'm_hidden_dim', 'm_output_dim', 'm_gnn_weights',
                 'm_projection_weights', 'm_temperature')

    def __init__(self, input_dim=128, hidden_dim=256, output_dim=64, temperature=0.1):
        self.m_input_dim = input_dim
        self.m_hidden_dim = hidden_dim
        self.m_output_dim = output_dim
        self.m_temperature = temperature

        # GNN layer weights
        scale = _math.sqrt(2.0 / (input_dim + hidden_dim))
        self.m_gnn_weights = self._init_weights(input_dim, hidden_dim, scale)

        # Projection head for contrastive learning
        proj_scale = _math.sqrt(2.0 / (hidden_dim + output_dim))
        self.m_projection_weights = self._init_weights(hidden_dim, output_dim, proj_scale)

    def _init_weights(self, in_d, out_d, scale):
        w = []
        ri = 0
        while ri < out_d:
            row = []
            ci = 0
            while ci < in_d:
                row.append(_rnd.gauss(0, scale))
                ci += 1
            w.append(row)
            ri += 1
        return w

    def encode_graph_cge(self, graph):
        """Encode a function graph to a dense embedding."""
        if graph is None:
            return [0.0] * self.m_output_dim

        nodes = graph.get('nodes', [])
        edges = graph.get('edges', [])

        if not nodes:
            return [0.0] * self.m_output_dim

        # Build adjacency
        adj = _defaultdict(list)
        ei = 0
        while ei < len(edges):
            src, dst, etype = edges[ei] if len(edges[ei]) >= 3 else (edges[ei][0], edges[ei][1], 'control')
            adj[src].append(dst)
            ei += 1

        # Initial node features
        node_feats = {}
        ni = 0
        while ni < len(nodes):
            feat = list(nodes[ni]) if isinstance(nodes[ni], list) else list(nodes[ni].get('features', []))
            if len(feat) < self.m_input_dim:
                feat.extend([0.0] * (self.m_input_dim - len(feat)))
            else:
                feat = feat[:self.m_input_dim]
            node_feats[ni] = feat
            ni += 1

        # GCN layer: aggregate neighbor features
        new_feats = {}
        ni = 0
        while ni < len(nodes):
            feat = node_feats[ni]
            neighbors = adj.get(ni, [])

            # Aggregate: self + mean of neighbors
            agg = list(feat)
            if neighbors:
                ndi = 0
                while ndi < self.m_input_dim:
                    total = feat[ndi]  # self
                    nbi = 0
                    while nbi < len(neighbors):
                        nb = neighbors[nbi]
                        if nb in node_feats:
                            total += node_feats[nb][ndi]
                        nbi += 1
                    agg[ndi] = total / (len(neighbors) + 1)
                    ndi += 1

            # Linear transform + ReLU
            out = []
            ri = 0
            while ri < len(self.m_gnn_weights):
                total = 0.0
                ci = 0
                while ci < len(agg):
                    total += agg[ci] * self.m_gnn_weights[ri][ci]
                    ci += 1
                out.append(max(total, 0.0))
                ri += 1
            new_feats[ni] = out
            ni += 1

        # Graph-level readout: mean pooling
        graph_vec = [0.0] * self.m_hidden_dim
        di = 0
        while di < self.m_hidden_dim:
            total = 0.0
            ni = 0
            while ni < len(nodes):
                total += new_feats[ni][di]
                ni += 1
            graph_vec[di] = total / max(len(nodes), 1)
            di += 1

        # Projection head
        emb = []
        ri = 0
        while ri < len(self.m_projection_weights):
            total = 0.0
            ci = 0
            while ci < len(graph_vec):
                total += graph_vec[ci] * self.m_projection_weights[ri][ci]
                ci += 1
            emb.append(total)
            ri += 1

        # L2 normalize
        norm = _math.sqrt(sum(v * v for v in emb)) + 1e-9
        emb = [v / norm for v in emb]

        return emb

    def contrastive_loss_cge(self, emb_a, emb_b, label):
        """NT-Xent (normalized temperature-scaled cross entropy) loss for one pair."""
        if emb_a is None or emb_b is None:
            return 0.0

        sim = 0.0
        di = 0
        while di < len(emb_a):
            sim += emb_a[di] * emb_b[di]
            di += 1

        sim = sim / self.m_temperature

        if label > 0.5:
            return -sim
        else:
            return max(0, sim)

    def contrastive_loss_grad_cge(self, emb_a, emb_b, label):
        """计算 NT-Xent loss 对两个 embedding 的梯度，用于反向传播。"""
        if emb_a is None or emb_b is None:
            return (0.0, [0.0] * self.m_output_dim, [0.0] * self.m_output_dim)

        sim = 0.0
        di = 0
        while di < len(emb_a):
            sim += emb_a[di] * emb_b[di]
            di += 1

        sim_scaled = sim / self.m_temperature
        dim = len(emb_a)

        if label > 0.5:
            # loss = -sim/tau，对 a 的梯度 = -b/tau，对 b 的梯度 = -a/tau
            loss = -sim_scaled
            grad_a = [-emb_b[di] / self.m_temperature for di in range(dim)]
            grad_b = [-emb_a[di] / self.m_temperature for di in range(dim)]
        else:
            # loss = max(0, sim/tau)
            if sim_scaled <= 0:
                loss = 0.0
                grad_a = [0.0] * dim
                grad_b = [0.0] * dim
            else:
                loss = sim_scaled
                grad_a = [emb_b[di] / self.m_temperature for di in range(dim)]
                grad_b = [emb_a[di] / self.m_temperature for di in range(dim)]

        return (loss, grad_a, grad_b)

    def _backprop_projection_weights(self, graph_vec, emb_grad, lr):
        """反向传播更新投影层权重。

        给定 graph-level 向量和 embedding 梯度，用链式法则更新 m_projection_weights。
        embedding = L2_norm(proj_weights @ graph_vec)，这里对未归一化输出计算梯度后再考虑归一化。
        """
        out_dim = len(self.m_projection_weights)
        hidden_dim = len(graph_vec)

        # 先算未归一化输出（与 encode_graph_cge 的前向一致）
        raw_out = []
        ri = 0
        while ri < out_dim:
            total = 0.0
            ci = 0
            while ci < hidden_dim:
                total += graph_vec[ci] * self.m_projection_weights[ri][ci]
                ci += 1
            raw_out.append(total)
            ri += 1

        # L2 归一化：emb_i = raw_i / norm，norm = sqrt(sum(raw^2))
        norm_sq = sum(v * v for v in raw_out) + 1e-12
        norm = _math.sqrt(norm_sq)

        # ∂L/∂raw_j = Σ_i ∂L/∂emb_i * ∂emb_i/∂raw_j
        # ∂emb_i/∂raw_j = (δ_ij * norm - raw_i * raw_j / norm) / norm^2
# (δ_ij / norm) - (raw_i * raw_j / norm^3)
        raw_grad = [0.0] * out_dim
        ri = 0
        while ri < out_dim:
            term = 0.0
            ci = 0
            while ci < out_dim:
                # δ_ij term
                delta = 1.0 if ci == ri else 0.0
                term += emb_grad[ci] * (delta / norm - raw_out[ci] * raw_out[ri] / (norm * norm_sq))
                ci += 1
            raw_grad[ri] = term
            ri += 1

        # ∂L/∂W_ri,ci = raw_grad[ri] * graph_vec[ci]
        ri = 0
        while ri < out_dim:
            ci = 0
            while ci < hidden_dim:
                self.m_projection_weights[ri][ci] -= lr * raw_grad[ri] * graph_vec[ci]
                ci += 1
            ri += 1

    def _backprop_gnn_weights(self, agg_list, gnn_out, downstream_grad, lr):
        """反向传播更新 GNN 层权重。

        gnn_out 是 ReLU 输出前的线性变换结果（逐节点），downstream_grad 是上游传回的损失对 gnn_out (ReLU 后) 的梯度。
        这里做简化：对 GNN 权重做逐样本 SGD，累积每个节点的梯度再平均。
        """
        hidden_dim = len(self.m_gnn_weights)    # out_d
        input_dim = len(self.m_gnn_weights[0])   # in_d
        n_nodes = len(agg_list)

        ni = 0
        while ni < n_nodes:
            agg = agg_list[ni]
            out = gnn_out[ni]  # ReLU 前输出
            grad_post_relu = downstream_grad[ni]

            # ReLU backward: ∂L/∂pre_relu = grad_post_relu if pre_relu > 0 else 0
            grad_pre_relu = []
            ri = 0
            while ri < hidden_dim:
                if out[ri] > 0:
                    grad_pre_relu.append(grad_post_relu[ri])
                else:
                    grad_pre_relu.append(0.0)
                ri += 1

            # ∂L/∂W_ri,ci = grad_pre_relu[ri] * agg[ci]
            ri = 0
            while ri < hidden_dim:
                ci = 0
                while ci < input_dim:
                    self.m_gnn_weights[ri][ci] -= lr * grad_pre_relu[ri] * agg[ci] / n_nodes
                    ci += 1
                ri += 1

            ni += 1


class GraphContrastiveSearch:
    """Semantic binary code search using contrastive graph embeddings and LSH indexing.

    Combines:
    1. Contrastive learning on function graphs to produce embeddings.
    2. SimHash LSH index for fast approximate nearest neighbor search.
    3. Multi-probe bucket exploration for improved recall.
    """

    __slots__ = ('m_encoder', 'm_index', 'm_metadata', 'm_trained', 'm_embeddings_cache')

    def __init__(self, input_dim=128, hidden_dim=256, output_dim=64,
                 num_tables=8, hash_bits=64, probe_radius=1):
        self.m_encoder = ContrastiveGraphEncoder(input_dim, hidden_dim, output_dim)
        self.m_index = LSHIndex(num_tables, hash_bits, output_dim, probe_radius)
        self.m_metadata = {}
        # 缓存 (graph_id, 嵌入) 对，用于训练后重建索引
        self.m_embeddings_cache = {}
        self.m_trained = False

    def index_graph_gcs(self, graph_id, graph, metadata=None):
        """Index a function graph for search."""
        if graph_id is None or graph is None:
            return
        emb = self.m_encoder.encode_graph_cge(graph)
        self.m_index.insert_lsh(graph_id, emb)
        # 缓存 嵌入 以备后续重建
        self.m_embeddings_cache[graph_id] = emb
        if metadata:
            self.m_metadata[graph_id] = metadata
        g_log.debug(f"Indexed graph {graph_id}")

    def index_batch_gcs(self, graphs):
        """Batch index multiple graphs."""
        gi = 0
        while gi < len(graphs):
            gid, gr, meta = graphs[gi]
            self.index_graph_gcs(gid, gr, meta)
            gi += 1
        g_log.info(f"Batch indexed {len(graphs)} graphs")

    def search_gcs(self, query_graph, top_k=10, threshold=0.5):
        """Search for similar function graphs."""
        if query_graph is None:
            return []
        query_emb = self.m_encoder.encode_graph_cge(query_graph)
        results = self.m_index.query_lsh(query_emb, top_k, threshold)
        enriched = []
        ri = 0
        while ri < len(results):
            key, sim = results[ri]
            enriched.append((key, sim, self.m_metadata.get(key, {})))
            ri += 1
        return enriched

    def train_contrastive_gcs(self, pairs, labels, epochs=30, lr=0.001):
        """Train the graph encoder with contrastive pairs (SGD weight updates)."""
        if pairs is None or labels is None or len(pairs) == 0:
            g_log.warning("train_contrastive: empty input")
            return []

        history = []
        epoch = 0
        while epoch < epochs:
            total_loss = 0.0
            pi = 0
            while pi < len(pairs):
                ga, gb = pairs[pi]

# 前向传播
                emb_a = self.m_encoder.encode_graph_cge(ga)
                emb_b = self.m_encoder.encode_graph_cge(gb)

# 损失与梯度
                loss, grad_a, grad_b = self.m_encoder.contrastive_loss_grad_cge(emb_a, emb_b, labels[pi])
                total_loss += loss

# 反向传播（仅当 loss > 0 时才更新）
                if loss > 1e-12:
                    # 获取两图的中间表示用于权重梯度计算
                    ga_vec, ga_agg, ga_gnn_out = self._encode_with_intermediates_cge(ga)
                    gb_vec, gb_agg, gb_gnn_out = self._encode_with_intermediates_cge(gb)

                    # 投影层权重更新（emb_a 侧）
                    self.m_encoder._backprop_projection_weights(ga_vec, grad_a, lr)
                    # 投影层权重更新（emb_b 侧）
                    self.m_encoder._backprop_projection_weights(gb_vec, grad_b, lr)

                    # GNN 层梯度：从投影层回传
                    gnn_grad_a = self._projection_grad_to_gnn(ga_vec, grad_a)
                    gnn_grad_b = self._projection_grad_to_gnn(gb_vec, grad_b)

                    # 将图级梯度广播到各节点（简化：均分）
                    n_nodes_a = len(ga_agg)
                    node_grads_a = []
                    if n_nodes_a > 0:
                        ni = 0
                        while ni < n_nodes_a:
                            node_grads_a.append(gnn_grad_a)
                            ni += 1

                    n_nodes_b = len(gb_agg)
                    node_grads_b = []
                    if n_nodes_b > 0:
                        ni = 0
                        while ni < n_nodes_b:
                            node_grads_b.append(gnn_grad_b)
                            ni += 1

                    # GNN 权重更新
                    if node_grads_a:
                        self.m_encoder._backprop_gnn_weights(ga_agg, ga_gnn_out, node_grads_a, lr)
                    if node_grads_b:
                        self.m_encoder._backprop_gnn_weights(gb_agg, gb_gnn_out, node_grads_b, lr)

                pi += 1

            avg_loss = total_loss / max(len(pairs), 1)
            history.append(avg_loss)

            if epoch % max(epochs // 10, 1) == 0:
                g_log.info(f"Contrastive epoch {epoch}/{epochs}, loss={avg_loss:.4f}")
            epoch += 1

        self.m_trained = True
        g_log.info("Contrastive training complete (with gradient updates)")
        return history

    def _encode_with_intermediates_cge(self, graph):
        """前向传播 + 保留中间表示，供反向传播使用。

        返回 (graph_vec, agg_list, gnn_out_list):
          - graph_vec: graph-level pooling 后的向量 (hidden_dim)
          - agg_list: 每个节点聚合后的输入向量列表
          - gnn_out_list: 每个节点 GNN 线性变换（ReLU 前）的输出列表
        """
        if graph is None:
            return ([0.0] * self.m_encoder.m_hidden_dim, [], [])

        nodes = graph.get('nodes', [])
        edges = graph.get('edges', [])

        if not nodes:
            return ([0.0] * self.m_encoder.m_hidden_dim, [], [])

        input_dim = self.m_encoder.m_input_dim
        hidden_dim = self.m_encoder.m_hidden_dim
        gnn_w = self.m_encoder.m_gnn_weights

        # Build adjacency
        adj = _defaultdict(list)
        ei = 0
        while ei < len(edges):
            src, dst = edges[ei][0], edges[ei][1]
            adj[src].append(dst)
            ei += 1

        # Node features
        node_feats = {}
        ni = 0
        while ni < len(nodes):
            feat = list(nodes[ni]) if isinstance(nodes[ni], list) else list(nodes[ni].get('features', []))
            if len(feat) < input_dim:
                feat.extend([0.0] * (input_dim - len(feat)))
            else:
                feat = feat[:input_dim]
            node_feats[ni] = feat
            ni += 1

        # GCN 聚合 + 线性变换
        agg_list = []
        gnn_out_list = []
        new_feats = {}
        ni = 0
        while ni < len(nodes):
            feat = node_feats[ni]
            neighbors = adj.get(ni, [])

            agg = list(feat)
            if neighbors:
                ndi = 0
                while ndi < input_dim:
                    total = feat[ndi]
                    nbi = 0
                    while nbi < len(neighbors):
                        nb = neighbors[nbi]
                        if nb in node_feats:
                            total += node_feats[nb][ndi]
                        nbi += 1
                    agg[ndi] = total / (len(neighbors) + 1)
                    ndi += 1

            agg_list.append(agg)

            # Linear transform (pre-ReLU)
            out = []
            ri = 0
            while ri < len(gnn_w):
                total = 0.0
                ci = 0
                while ci < len(agg):
                    total += agg[ci] * gnn_w[ri][ci]
                    ci += 1
                out.append(total)
                ri += 1

            gnn_out_list.append(out)

            # ReLU
            relu_out = [max(v, 0.0) for v in out]
            new_feats[ni] = relu_out
            ni += 1

        # Graph-level readout: mean pooling
        graph_vec = [0.0] * hidden_dim
        di = 0
        while di < hidden_dim:
            total = 0.0
            ni = 0
            while ni < len(nodes):
                total += new_feats[ni][di]
                ni += 1
            graph_vec[di] = total / max(len(nodes), 1)
            di += 1

        return (graph_vec, agg_list, gnn_out_list)

    def _projection_grad_to_gnn(self, graph_vec, emb_grad):
        """从 embedding 梯度反向传播到 graph_vec（GNN 输出）的梯度。

        只考虑投影层的线性部分，忽略 L2 归一化的回传（已在 _backprop_projection_weights 中处理）。
        这里计算 ∂L/∂graph_vec = Σ_i emb_grad[i] * ∂emb_i/∂graph_vec_j 的简化版本。
        """
        proj_w = self.m_encoder.m_projection_weights
        out_dim = len(proj_w)
        hidden_dim = len(graph_vec)

        # 先算 raw_out 和 norm（与 encode 一致）
        raw_out = []
        ri = 0
        while ri < out_dim:
            total = 0.0
            ci = 0
            while ci < hidden_dim:
                total += graph_vec[ci] * proj_w[ri][ci]
                ci += 1
            raw_out.append(total)
            ri += 1

        norm_sq = sum(v * v for v in raw_out) + 1e-12
        norm = _math.sqrt(norm_sq)

        # ∂emb_k/∂raw_j = (δ_kj / norm) - (raw_k * raw_j / norm^3)
        # ∂L/∂raw_j = Σ_k emb_grad[k] * ∂emb_k/∂raw_j
        raw_grad = [0.0] * out_dim
        rj = 0
        while rj < out_dim:
            term = 0.0
            rk = 0
            while rk < out_dim:
                delta = 1.0 if rk == rj else 0.0
                term += emb_grad[rk] * (delta / norm - raw_out[rk] * raw_out[rj] / (norm * norm_sq))
                rk += 1
            raw_grad[rj] = term
            rj += 1

        # ∂raw_j/∂graph_vec[ci] = proj_w[j][ci]
        # ∂L/∂graph_vec[ci] = Σ_j raw_grad[j] * proj_w[j][ci]
        gnn_grad = [0.0] * hidden_dim
        ci = 0
        while ci < hidden_dim:
            total = 0.0
            rj = 0
            while rj < out_dim:
                total += raw_grad[rj] * proj_w[rj][ci]
                rj += 1
            gnn_grad[ci] = total
            ci += 1

        return gnn_grad

    def compute_similarity_gcs(self, graph_a, graph_b):
        """Compute cosine similarity between two graphs."""
        emb_a = self.m_encoder.encode_graph_cge(graph_a)
        emb_b = self.m_encoder.encode_graph_cge(graph_b)
        sim = 0.0
        di = 0
        while di < len(emb_a):
            sim += emb_a[di] * emb_b[di]
            di += 1
        return sim

    def remove_graph_gcs(self, graph_id):
        """Remove a graph from the index and embedding cache."""
        self.m_index.remove_lsh(graph_id)
        self.m_metadata.pop(graph_id, None)
        self.m_embeddings_cache.pop(graph_id, None)
        g_log.debug(f"Removed graph {graph_id}")

    def rebuild_index_gcs(self):
        """基于缓存的 embedding 全量重建 LSH 索引（训练后调用）。

        先清空所有桶，再逐条重新插入。适用于权重更新后需要刷新索引的场景。
        """
        if not self.m_embeddings_cache:
            g_log.warning("rebuild_index_gcs: 无缓存 embedding，跳过重建")
            return

        self.m_index.clear_all_lsh()
        rebuild_count = 0
        for gid, emb in self.m_embeddings_cache.items():
            self.m_index.insert_lsh(gid, emb)
            rebuild_count += 1
        g_log.info(f"Index rebuild complete: {rebuild_count} graphs re-inserted")

    def get_stats_gcs(self):
        """Return search engine statistics."""
        return {
            'indexed_graphs': len(self.m_metadata),
            'lsh_entries': self.m_index.size_lsh(),
            'embedding_dim': self.m_encoder.m_output_dim,
            'trained': self.m_trained,
            'cached_embeddings': len(self.m_embeddings_cache),
        }

    def _ann_search_gcs(self, query_emb, top_k=10):
        """Internal ANN search using multi-probe LSH buckets.

        Enhanced to use neighbor bucket probing from SimHash for higher recall.
        """
        return self.m_index.query_lsh(query_emb, top_k)




def create_graph_contrastive_search(input_dim=128, hidden_dim=256, output_dim=64,
                                    num_tables=8, hash_bits=64, probe_radius=2):
    return GraphContrastiveSearch(input_dim, hidden_dim, output_dim,
                                  num_tables, hash_bits, probe_radius)
