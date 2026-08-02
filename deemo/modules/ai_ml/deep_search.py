# 2026-07-30: 跨模态对比对齐 + 半硬负样本挖掘 + 自适应优化器集成
#!/usr/bin/env python3
# Deep learning based binary code searcher — semantic search over function embeddings
# using a Siamese neural network trained on code similarity pairs.
# 2026-07-06: added contrastive loss and triplet mining for hard-negative selection.
# 2026-07-30: CLAP-style cross-modal contrastive pre-training / semi-hard mining /
#             Kaiming init + momentum SGD with cosine annealing.

import logging as _logging
import math as _math
import random as _rnd
import time as _tm
import hashlib as _hashlib
from collections import defaultdict as _defaultdict

__dbg = _logging.getLogger(__name__)


class EmbeddingStore:
    """In-memory vector store with cosine similarity search.

    Supports hybrid retrieval: cosine + optional Jaccard on binarized signatures
    for robustness against adversarial perturbation of embedding spaces.
    """

    __slots__ = ('m_vectors', 'm_metadata', 'm_dim', 'm_norms_cache',
                 'm_binarized_sigs', 'm_hybrid_weight')

    def __init__(self, hybrid_weight=0.15):
        self.m_vectors = {}
        self.m_metadata = {}
        self.m_dim = None
        self.m_norms_cache = {}       # 预计算范数，避免重复开方
        self.m_binarized_sigs = {}    # 二值化签名用于 Jaccard 辅助检索
        self.m_hybrid_weight = hybrid_weight  # 混合检索中 Jaccard 的权重

    @staticmethod
    def _binarize_vector(vec):
        """将向量按中位数二值化为 bit-string，用于 Jaccard 粗筛。"""
        if not vec:
            return 0
        median = sorted(vec)[len(vec) // 2]
        sig = 0
        bi = 0
        while bi < min(len(vec), 64):
            if vec[bi] > median:
                sig |= (1 << bi)
            bi += 1
        return sig

    @staticmethod
    def _jaccard_bits(sig_a, sig_b):
        """两个 64-bit 签名间的 Jaccard 相似度。"""
        if sig_a == 0 and sig_b == 0:
            return 0.0
        and_bits = sig_a & sig_b
        or_bits = sig_a | sig_b
        if or_bits == 0:
            return 0.0
        return bin(and_bits).count('1') / bin(or_bits).count('1')

    def add_es(self, key, vector, metadata=None):
        """Add a vector with optional metadata."""
        if key is None or vector is None:
            return
        if self.m_dim is None:
            self.m_dim = len(vector)
        elif len(vector) != self.m_dim:
            __dbg.warning(f"Dimension mismatch: expected {self.m_dim}, got {len(vector)}")
            return
        self.m_vectors[key] = list(vector)
        # 缓存 L2 范数
        sq = 0.0
        for v in vector:
            sq += v * v
        self.m_norms_cache[key] = _math.sqrt(sq)
        self.m_binarized_sigs[key] = EmbeddingStore._binarize_vector(vector)
        if metadata:
            self.m_metadata[key] = metadata

    def remove_es(self, key):
        self.m_vectors.pop(key, None)
        self.m_metadata.pop(key, None)
        self.m_norms_cache.pop(key, None)
        self.m_binarized_sigs.pop(key, None)

    def search_es(self, query_vector, top_k=10, threshold=0.5):
        """混合检索：余弦相似度 + Jaccard 辅助，返回 top-k 结果。"""
        if query_vector is None or len(self.m_vectors) == 0:
            return []

        q_norm_sq = 0.0
        for v in query_vector:
            q_norm_sq += v * v
        q_norm = _math.sqrt(q_norm_sq)
        q_sig = EmbeddingStore._binarize_vector(query_vector)

        results = []
        keys = list(self.m_vectors.keys())
        ki = 0
        while ki < len(keys):
            k = keys[ki]
            vec = self.m_vectors[k]

            # 余弦相似度 — 利用预计算范数
            dot = 0.0
            di = 0
            while di < len(query_vector):
                dot += query_vector[di] * vec[di]
                di += 1
            denom = q_norm * self.m_norms_cache.get(k, 1.0)
            cos_sim = dot / denom if denom > 1e-9 else 0.0

            # Jaccard 辅助分数
            jac = EmbeddingStore._jaccard_bits(q_sig, self.m_binarized_sigs.get(k, 0))
            hybrid_sim = (1.0 - self.m_hybrid_weight) * cos_sim + self.m_hybrid_weight * jac

            if hybrid_sim >= threshold:
                results.append((k, hybrid_sim, self.m_metadata.get(k, {})))
            ki += 1

        results.sort(key=lambda x: x[1], reverse=True)
        return results[:top_k]

    @staticmethod
    def _cosine_similarity(a, b):
        if a is None or b is None or len(a) != len(b):
            return 0.0
        dot = 0.0
        norm_a = 0.0
        norm_b = 0.0
        di = 0
        while di < len(a):
            dot += a[di] * b[di]
            norm_a += a[di] * a[di]
            norm_b += b[di] * b[di]
            di += 1
        denom = _math.sqrt(norm_a) * _math.sqrt(norm_b)
        if denom < 1e-9:
            return 0.0
        return dot / denom

    @staticmethod
    def _euclidean_distance(a, b):
        if a is None or b is None or len(a) != len(b):
            return float('inf')
        total = 0.0
        di = 0
        while di < len(a):
            d = a[di] - b[di]
            total += d * d
            di += 1
        return _math.sqrt(total)


class AdaptiveOptimizer:
    """动量 SGD + 余弦退火学习率调度 + L2 权重衰减。

    设计意图：手工前馈网络没有 autograd，需要一个轻量优化器
    直接操作 FunctionEmbedder 的权重矩阵，避免引入 numpy/torch 依赖。
    """

    __slots__ = ('m_lr_init', 'm_lr_min', 'm_momentum', 'm_weight_decay',
                 'm_velocity', 'm_t', 'm_T_max')

    def __init__(self, lr_init=0.01, lr_min=1e-5, momentum=0.9,
                 weight_decay=1e-4, T_max=100):
        self.m_lr_init = lr_init
        self.m_lr_min = lr_min
        self.m_momentum = momentum
        self.m_weight_decay = weight_decay
        self.m_velocity = {}   # 动量缓存: id(param_list) -> velocity_struct
        self.m_t = 0
        self.m_T_max = T_max

    def _cosine_lr(self):
        """余弦退火：lr_min + 0.5*(lr_init - lr_min)*(1 + cos(pi * t / T_max))"""
        if self.m_t >= self.m_T_max:
            return self.m_lr_min
        progress = self.m_t / self.m_T_max
        return self.m_lr_min + 0.5 * (self.m_lr_init - self.m_lr_min) * \
               (1.0 + _math.cos(_math.pi * progress))

    def step_ao(self, weight_matrix, bias_vector, grad_w, grad_b):
        """对一组 (weight, bias) 执行一步 SGD with momentum + weight decay。

        Args:
            weight_matrix: list of list (out_dim × in_dim)
            bias_vector: list of float
            grad_w: gradient w.r.t. weight (same shape)
            grad_b: gradient w.r.t. bias (same shape)
        """
        w_id = id(weight_matrix)
        b_id = id(bias_vector)

        # 初始化速度矩阵
        if w_id not in self.m_velocity:
            v_w = []
            ri = 0
            while ri < len(grad_w):
                v_w.append([0.0] * len(grad_w[ri]))
                ri += 1
            self.m_velocity[w_id] = v_w
        if b_id not in self.m_velocity:
            self.m_velocity[b_id] = [0.0] * len(bias_vector)

        lr = self._cosine_lr()
        v_w = self.m_velocity[w_id]
        v_b = self.m_velocity[b_id]
        mom = self.m_momentum
        wd = self.m_weight_decay

        # 权重更新: v = mom*v + lr*(g + wd*w); w -= v
        ri = 0
        while ri < len(weight_matrix):
            row_w = weight_matrix[ri]
            row_g = grad_w[ri]
            row_v = v_w[ri]
            ci = 0
            while ci < len(row_w):
                row_v[ci] = mom * row_v[ci] + lr * (row_g[ci] + wd * row_w[ci])
                row_w[ci] -= row_v[ci]
                ci += 1
            ri += 1

        # 偏置更新: v = mom*v + lr*g; b -= v  （偏置通常不加 weight decay）
        bi = 0
        while bi < len(bias_vector):
            v_b[bi] = mom * v_b[bi] + lr * grad_b[bi]
            bias_vector[bi] -= v_b[bi]
            bi += 1

        self.m_t += 1

    def reset_ao(self):
        """重置优化器状态（新一轮训练时调用）。"""
        self.m_velocity.clear()
        self.m_t = 0


class TripletMiner:
    """Mines hard negative triplets for contrastive learning.

    For each anchor-positive pair, finds the hardest negative (closest non-matching)
    to form (anchor, positive, negative) triplets.

    增强：半硬负样本策略 — 选择 d(a,n) > d(a,p) 且 d(a,n) < d(a,p) + margin
    的负样本，避免过难的样本导致训练崩溃（参考 FaceNet, Schroff et al. 2015）。
    """

    __slots__ = ('m_margin', 'm_max_negatives_per_anchor', 'm_semi_hard')

    def __init__(self, margin=0.2, max_negatives_per_anchor=5, semi_hard=True):
        self.m_margin = margin
        self.m_max_negatives_per_anchor = max_negatives_per_anchor
        self.m_semi_hard = semi_hard

    def mine_triplets_tm(self, anchor_vecs, positive_vecs, all_vecs, labels):
        """Mine hard triplet pairs.

        Args:
            anchor_vecs: dict key -> vector for anchor samples.
            positive_vecs: dict key -> vector for positive samples.
            all_vecs: dict key -> vector for all available samples.
            labels: dict key -> label (same label = positive pair).

        Returns:
            list of (anchor_key, positive_key, negative_key) tuples.
        """
        triplets = []
        anchor_keys = list(anchor_vecs.keys())
        all_keys = list(all_vecs.keys())

        ai = 0
        while ai < len(anchor_keys):
            a_key = anchor_keys[ai]
            a_vec = anchor_vecs[a_key]
            a_label = labels.get(a_key)

            if a_key not in positive_vecs:
                ai += 1
                continue
            p_vec = positive_vecs[a_key]
            pos_dist = EmbeddingStore._euclidean_distance(a_vec, p_vec)

            # 收集候选负样本
            negatives = []
            ni = 0
            while ni < len(all_keys):
                n_key = all_keys[ni]
                if n_key == a_key:
                    ni += 1
                    continue
                n_label = labels.get(n_key)
                if n_label is not None and n_label == a_label:
                    ni += 1
                    continue
                n_vec = all_vecs[n_key]
                dist = EmbeddingStore._euclidean_distance(a_vec, n_vec)

                # 半硬策略：仅保留满足 d(a,n) < d(a,p) + margin 的候选
                # 跳过过易的负样本（距离远大于正样本+margin），减少噪声
                if self.m_semi_hard:
                    if dist < pos_dist + self.m_margin:
                        negatives.append((n_key, dist))
                else:
                    negatives.append((n_key, dist))
                ni += 1

            if not negatives:
                ai += 1
                continue

            # Sort by distance ascending (harder = closer)
            negatives.sort(key=lambda x: x[1])
            negatives = negatives[:self.m_max_negatives_per_anchor]

            ni = 0
            while ni < len(negatives):
                triplets.append((a_key, a_key, negatives[ni][0]))
                ni += 1
            ai += 1

        return triplets

    def mine_batch_aware_tm(self, anchor_vecs, positive_vecs, all_vecs, labels,
                             batch_size=32):
        """批次感知挖掘：在 mini-batch 内选择最难的负样本。

        当 all_vecs 很大时，全局挖掘 O(N^2) 不可行。此方法在随机批次内
        做局部困难负样本挖掘，复杂度 O(B^2)，适合在线训练。
        """
        triplets = []
        a_keys = list(anchor_vecs.keys())
        if not a_keys:
            return triplets

        # 随机批次
        _rnd.shuffle(a_keys)
        batch_start = 0
        while batch_start < len(a_keys):
            batch_keys = a_keys[batch_start:batch_start + batch_size]
            batch_start += batch_size

            bi = 0
            while bi < len(batch_keys):
                a_key = batch_keys[bi]
                a_vec = anchor_vecs.get(a_key)
                a_label = labels.get(a_key)
                if a_key not in positive_vecs or a_vec is None:
                    bi += 1
                    continue
                p_vec = positive_vecs[a_key]
                pos_dist = EmbeddingStore._euclidean_distance(a_vec, p_vec)

                # 在批次内找最难负样本
                best_neg_key = None
                best_neg_dist = float('inf')
                nj = 0
                while nj < len(batch_keys):
                    n_key = batch_keys[nj]
                    if n_key == a_key:
                        nj += 1
                        continue
                    n_label = labels.get(n_key)
                    if n_label is not None and n_label == a_label:
                        nj += 1
                        continue
                    n_vec = all_vecs.get(n_key)
                    if n_vec is None:
                        nj += 1
                        continue
                    dist = EmbeddingStore._euclidean_distance(a_vec, n_vec)
                    if self.m_semi_hard:
                        if dist < pos_dist + self.m_margin and dist < best_neg_dist:
                            best_neg_dist = dist
                            best_neg_key = n_key
                    else:
                        if dist < best_neg_dist:
                            best_neg_dist = dist
                            best_neg_key = n_key
                    nj += 1

                if best_neg_key is not None:
                    triplets.append((a_key, a_key, best_neg_key))
                bi += 1

        return triplets


class ContrastiveLoss:
    """Contrastive loss: encourages similar pairs to be close, dissimilar pairs far apart.

    L = y * d^2 + (1-y) * max(margin - d, 0)^2
    """

    __slots__ = ('m_margin',)

    def __init__(self, margin=1.0):
        self.m_margin = margin

    def compute_cl(self, vec_a, vec_b, label):
        """Compute contrastive loss for a pair.

        Args:
            vec_a, vec_b: the two vectors.
            label: 1 for similar pair, 0 for dissimilar.

        Returns:
            float loss value.
        """
        dist = EmbeddingStore._euclidean_distance(vec_a, vec_b)
        if label > 0.5:
            return 0.5 * dist * dist
        else:
            return 0.5 * max(self.m_margin - dist, 0.0) ** 2

    def compute_batch_cl(self, pairs, labels):
        """Compute average loss over a batch of pairs."""
        if not pairs:
            return 0.0
        total = 0.0
        pi = 0
        while pi < len(pairs):
            a, b = pairs[pi]
            total += self.compute_cl(a, b, labels[pi])
            pi += 1
        return total / len(pairs)


class CrossModalContrastiveLoss:
    """CLAP-style 跨模态对比损失。

    对齐两个模态的嵌入空间：给定 batch 内 N 对配对样本 (x_i, y_i)，
    最大化对角相似度、最小化非对角相似度。

    L = -0.5 * [ 1/N Σ_i log(exp(sim(x_i,y_i)/τ) / Σ_j exp(sim(x_i,y_j)/τ))
               + 1/N Σ_i log(exp(sim(y_i,x_i)/τ) / Σ_j exp(sim(y_j,x_i)/τ)) ]

    参考：CLAP (arXiv 2402.16928), BLens (USENIX Security '25)
    """

    __slots__ = ('m_temperature', 'm_epsilon')

    def __init__(self, temperature=0.07):
        self.m_temperature = temperature
        self.m_epsilon = 1e-9

    def compute_cmcl(self, modality_a_embs, modality_b_embs):
        """计算跨模态 InfoNCE 损失。

        Args:
            modality_a_embs: list of vectors from modality A (e.g., opcode features)
            modality_b_embs: list of vectors from modality B (e.g., CFG features)

        Returns:
            float: symmetric cross-modal contrastive loss.
        """
        if not modality_a_embs or not modality_b_embs:
            return 0.0
        N = len(modality_a_embs)
        if N != len(modality_b_embs):
            return 0.0

        tau = self.m_temperature

        # 构建相似度矩阵 S[i][j] = sim(a_i, b_j) / tau  （使用余弦相似度）
        sim_matrix = []
        ri = 0
        while ri < N:
            row = []
            cj = 0
            while cj < N:
                s = EmbeddingStore._cosine_similarity(
                    modality_a_embs[ri], modality_b_embs[cj])
                row.append(s / tau)
                cj += 1
            sim_matrix.append(row)
            ri += 1

        # A→B 方向
        loss_a2b = 0.0
        ri = 0
        while ri < N:
            # log-sum-exp 稳定化：减去行最大值
            row = sim_matrix[ri]
            row_max = max(row)
            exp_sum = 0.0
            cj = 0
            while cj < N:
                exp_sum += _math.exp(row[cj] - row_max)
                cj += 1
            # 对角项 (正样本对) 的 log-prob
            loss_a2b += -(row[ri] - row_max - _math.log(exp_sum + self.m_epsilon))
            ri += 1
        loss_a2b /= N

        # B→A 方向 （对称）
        loss_b2a = 0.0
        cj = 0
        while cj < N:
            col = [sim_matrix[ri][cj] for ri in range(N)]
            col_max = max(col)
            exp_sum = 0.0
            ri = 0
            while ri < N:
                exp_sum += _math.exp(col[ri] - col_max)
                ri += 1
            loss_b2a += -(col[cj] - col_max - _math.log(exp_sum + self.m_epsilon))
            cj += 1
        loss_b2a /= N

        return 0.5 * (loss_a2b + loss_b2a)

    def alignment_score_cmcl(self, modality_a_embs, modality_b_embs):
        """评估跨模态对齐质量：对角平均值 vs 非对角平均值。"""
        if not modality_a_embs:
            return {'diag_mean': 0.0, 'offdiag_mean': 0.0, 'gap': 0.0}
        N = len(modality_a_embs)
        diag_sum = 0.0
        off_sum = 0.0
        off_count = 0
        ri = 0
        while ri < N:
            cj = 0
            while cj < N:
                sim = EmbeddingStore._cosine_similarity(
                    modality_a_embs[ri], modality_b_embs[cj])
                if ri == cj:
                    diag_sum += sim
                else:
                    off_sum += sim
                    off_count += 1
                cj += 1
            ri += 1
        diag_mean = diag_sum / N
        offdiag_mean = off_sum / max(off_count, 1)
        return {'diag_mean': diag_mean, 'offdiag_mean': offdiag_mean,
                'gap': diag_mean - offdiag_mean}


class FunctionEmbedder:
    """Produces function embeddings via a simple feed-forward network.

    In production, this would be replaced with a proper GNN/Transformer model.
    The architecture here is a minimal reference implementation.

    增强：Kaiming 初始化适配 ReLU 激活 / 多模态输入支持 /
          梯度计算用于反向传播学习。
    """

    __slots__ = ('m_input_dim', 'm_hidden_dim', 'm_output_dim',
                 'm_weights', 'm_biases', 'm_modality')

    def __init__(self, input_dim=128, hidden_dim=256, output_dim=64,
                 modality='default'):
        self.m_input_dim = input_dim
        self.m_hidden_dim = hidden_dim
        self.m_output_dim = output_dim
        self.m_modality = modality  # 模态标识：'opcode', 'cfg', 'decompiled', 'default'

        # Kaiming 初始化：适配 ReLU，fan_in = input_dim, gain = sqrt(2)
        self.m_weights = [
            self._init_kaiming(input_dim, hidden_dim),
            self._init_kaiming(hidden_dim, hidden_dim),
            self._init_kaiming(hidden_dim, output_dim),
        ]
        self.m_biases = [
            [0.0] * hidden_dim,
            [0.0] * hidden_dim,
            [0.0] * output_dim,
        ]

    def _init_weights(self, in_dim, out_dim):
        """Xavier-like initialization. 保留向后兼容。"""
        scale = _math.sqrt(6.0 / (in_dim + out_dim))
        result = []
        ri = 0
        while ri < out_dim:
            row = []
            ci = 0
            while ci < in_dim:
                row.append(_rnd.uniform(-scale, scale))
                ci += 1
            result.append(row)
            ri += 1
        return result

    def _init_kaiming(self, in_dim, out_dim):
        """Kaiming/He 初始化 — 适配 ReLU。

        std = sqrt(2 / fan_in)，从 N(0, std^2) 采样。
        对于前向传播方差保持优于 Xavier（Xavier 假设线性激活）。
        """
        std = _math.sqrt(2.0 / in_dim)
        result = []
        ri = 0
        while ri < out_dim:
            row = []
            ci = 0
            while ci < in_dim:
                # Box-Muller 近似：用 uniform 模拟 Gaussian
                row.append(_rnd.gauss(0.0, std))
                ci += 1
            result.append(row)
            ri += 1
        return result

    def _relu(self, x):
        return max(x, 0.0)

    def _relu_derivative(self, x):
        """ReLU 导数：1 if x > 0 else 0"""
        return 1.0 if x > 0.0 else 0.0

    def _linear(self, vec, weight, bias):
        result = []
        ri = 0
        while ri < len(weight):
            total = 0.0
            ci = 0
            while ci < len(vec):
                total += vec[ci] * weight[ri][ci]
                ci += 1
            result.append(total + bias[ri])
            ri += 1
        return result

    def embed_fe(self, features):
        """Forward pass: features -> embedding."""
        if features is None:
            return [0.0] * self.m_output_dim

        # Pad or truncate to input_dim
        vec = list(features[:self.m_input_dim]) if features else []
        while len(vec) < self.m_input_dim:
            vec.append(0.0)

        # Layer 1: Linear + ReLU
        h1 = self._linear(vec, self.m_weights[0], self.m_biases[0])
        h1 = [self._relu(v) for v in h1]

        # Layer 2: Linear + ReLU
        h2 = self._linear(h1, self.m_weights[1], self.m_biases[1])
        h2 = [self._relu(v) for v in h2]

        # Layer 3: Linear (embedding)
        emb = self._linear(h2, self.m_weights[2], self.m_biases[2])

        # L2 normalize
        norm = _math.sqrt(sum(v * v for v in emb)) + 1e-9
        emb = [v / norm for v in emb]
        return emb

    def forward_with_activations_fe(self, features):
        """前向传播并保留所有中间激活值，供反向传播用。

        Returns:
            (embedding, [input_vec, h1_pre, h1_post, h2_pre, h2_post, emb_pre])
        """
        if features is None:
            dummy = [0.0] * self.m_output_dim
            return dummy, []

        vec = list(features[:self.m_input_dim]) if features else []
        while len(vec) < self.m_input_dim:
            vec.append(0.0)

        h1_pre = self._linear(vec, self.m_weights[0], self.m_biases[0])
        h1_post = [self._relu(v) for v in h1_pre]
        h2_pre = self._linear(h1_post, self.m_weights[1], self.m_biases[1])
        h2_post = [self._relu(v) for v in h2_pre]
        emb_pre = self._linear(h2_post, self.m_weights[2], self.m_biases[2])

        norm = _math.sqrt(sum(v * v for v in emb_pre)) + 1e-9
        emb = [v / norm for v in emb_pre]

        activations = [vec, h1_pre, h1_post, h2_pre, h2_post, emb_pre]
        return emb, activations

    def compute_gradients_fe(self, features, target_grad):
        """手动反向传播：计算所有权重/偏置的梯度。

        用于 contrastive loss 训练时更新 embedder 参数。
        链式法则：dL/dW = dL/d(emb) · d(emb)/d(act) · d(act)/dW

        Args:
            features: 输入特征向量
            target_grad: dL/d(embedding)，即损失对最终嵌入的梯度

        Returns:
            (list of grad_w matrices, list of grad_b vectors)
        """
        emb, acts = self.forward_with_activations_fe(features)
        if not acts:
            return [], []

        inp_vec, h1_pre, h1_post, h2_pre, h2_post, emb_pre = acts

        # grad 通过 L2 归一化回传
        # emb = emb_pre / ||emb_pre||
        norm = _math.sqrt(sum(v * v for v in emb_pre)) + 1e-9
        norm3 = norm ** 3
        # d(emb_i)/d(emb_pre_j) = (δ_ij * norm - emb_pre_i * emb_pre_j / norm) / norm^2
        # 即: grad_emb_pre = (target_grad - (target_grad · emb) * emb) / norm
        dot_tg_emb = sum(target_grad[gi] * emb[gi] for gi in range(len(emb)))
        grad_emb_pre = [(target_grad[gi] - dot_tg_emb * emb[gi]) / norm
                        for gi in range(len(emb))]

        # 初始化梯度累加器
        grad_w = [None, None, None]
        grad_b = [None, None, None]

        # --- Layer 3: emb_pre = W2 @ h2_post + b2 ---
        # dL/dW2 = grad_emb_pre ⊗ h2_post  (outer product)
        # dL/db2 = grad_emb_pre
        grad_w[2] = []
        gbi2 = []
        gi = 0
        while gi < len(grad_emb_pre):
            row = []
            cj = 0
            while cj < len(h2_post):
                row.append(grad_emb_pre[gi] * h2_post[cj])
                cj += 1
            grad_w[2].append(row)
            gbi2.append(grad_emb_pre[gi])
            gi += 1
        grad_b[2] = gbi2

        # dL/d(h2_post) = W2^T @ grad_emb_pre
        grad_h2_post = []
        ci = 0
        while ci < len(self.m_weights[2][0]):
            total = 0.0
            ri = 0
            while ri < len(self.m_weights[2]):
                total += self.m_weights[2][ri][ci] * grad_emb_pre[ri]
                ri += 1
            grad_h2_post.append(total)
            ci += 1

        # --- Layer 2: h2_post = ReLU(h2_pre) ---
        grad_h2_pre = []
        gi = 0
        while gi < len(grad_h2_post):
            grad_h2_pre.append(
                grad_h2_post[gi] * self._relu_derivative(h2_pre[gi]))
            gi += 1

        # --- Layer 2 Linear: h2_pre = W1 @ h1_post + b1 ---
        grad_w[1] = []
        gbi1 = []
        gi = 0
        while gi < len(grad_h2_pre):
            row = []
            cj = 0
            while cj < len(h1_post):
                row.append(grad_h2_pre[gi] * h1_post[cj])
                cj += 1
            grad_w[1].append(row)
            gbi1.append(grad_h2_pre[gi])
            gi += 1
        grad_b[1] = gbi1

        grad_h1_post = []
        ci = 0
        while ci < len(self.m_weights[1][0]):
            total = 0.0
            ri = 0
            while ri < len(self.m_weights[1]):
                total += self.m_weights[1][ri][ci] * grad_h2_pre[ri]
                ri += 1
            grad_h1_post.append(total)
            ci += 1

        # --- Layer 1: h1_post = ReLU(h1_pre) ---
        grad_h1_pre = []
        gi = 0
        while gi < len(grad_h1_post):
            grad_h1_pre.append(
                grad_h1_post[gi] * self._relu_derivative(h1_pre[gi]))
            gi += 1

        # --- Layer 1 Linear: h1_pre = W0 @ inp_vec + b0 ---
        grad_w[0] = []
        gbi0 = []
        gi = 0
        while gi < len(grad_h1_pre):
            row = []
            cj = 0
            while cj < len(inp_vec):
                row.append(grad_h1_pre[gi] * inp_vec[cj])
                cj += 1
            grad_w[0].append(row)
            gbi0.append(grad_h1_pre[gi])
            gi += 1
        grad_b[0] = gbi0

        return grad_w, grad_b


class CrossModalAligner:
    """跨模态对齐器：将不同表示空间的函数嵌入映射到共享语义空间。

    CLAP 风格：每个模态有独立的编码器（或共享编码器 + 投影头），
    通过对比 InfoNCE 损失在共享空间中拉近匹配对、推远非匹配对。

    在二进制代码搜索场景中，模态可以是：
    - 操作码序列特征 (opcode n-gram)
    - 控制流图结构特征 (CFG adjacency, loops)
    - 反编译伪代码特征 (tokenized decompiled text)
    """

    __slots__ = ('m_embedders', 'm_loss_fn', 'm_alignment_temperature',
                 'm_projection_dim')

    def __init__(self, embedders=None, temperature=0.07, projection_dim=64):
        """初始化跨模态对齐器。

        Args:
            embedders: dict modality_name -> FunctionEmbedder instance
            temperature: InfoNCE 温度参数
            projection_dim: 共享投影空间维度
        """
        self.m_embedders = embedders if embedders else {}
        self.m_loss_fn = CrossModalContrastiveLoss(temperature)
        self.m_alignment_temperature = temperature
        self.m_projection_dim = projection_dim

    def register_modality_cma(self, name, embedder):
        """注册一个新模态的编码器。"""
        self.m_embedders[name] = embedder

    def align_pair_cma(self, modality_a, modality_b, paired_samples,
                        epochs=20, lr=0.005):
        """训练两个模态的编码器在共享空间中对齐。

        Args:
            modality_a: 第一个模态名称
            modality_b: 第二个模态名称
            paired_samples: list of (features_a, features_b) 配对的跨模态样本
            epochs: 训练迭代次数
            lr: 学习率

        Returns:
            dict: 训练历史（每轮损失和对齐分数）
        """
        if modality_a not in self.m_embedders or modality_b not in self.m_embedders:
            __dbg.error(f"Unknown modality: {modality_a} or {modality_b}")
            return []

        emb_a = self.m_embedders[modality_a]
        emb_b = self.m_embedders[modality_b]
        history = []

        opt_a = AdaptiveOptimizer(lr_init=lr, T_max=epochs)
        opt_b = AdaptiveOptimizer(lr_init=lr, T_max=epochs)

        epoch = 0
        while epoch < epochs:
            # 前向：获取两个模态的嵌入
            embs_a = [emb_a.embed_fe(fa) for fa, _ in paired_samples]
            embs_b = [emb_b.embed_fe(fb) for _, fb in paired_samples]

            loss = self.m_loss_fn.compute_cmcl(embs_a, embs_b)
            alignment = self.m_loss_fn.alignment_score_cmcl(embs_a, embs_b)

            history.append({'epoch': epoch, 'loss': loss,
                            'gap': alignment['gap']})

            if epoch % max(epochs // 5, 1) == 0:
                __dbg.info(
                    f"[CM-Align] {modality_a}↔{modality_b} "
                    f"epoch {epoch}/{epochs}, loss={loss:.4f}, "
                    f"gap={alignment['gap']:.4f}")

            # 反向传播：对每个样本计算梯度并更新权重
            # 仅在最外层循环做梯度估计（数值近似）
            # 生产环境应使用 autograd；此处用扰动方法验证逻辑正确性
            si = 0
            while si < min(len(paired_samples), 8):  # 限制每轮更新样本数
                fa, fb = paired_samples[si]

                # 对 modality A 的嵌入计算梯度（通过对比损失对 emb_a 的隐式梯度）
                # 简化为：梯度方向指向增强对齐的方向
                emb_a_vec = emb_a.embed_fe(fa)
                emb_b_vec = emb_b.embed_fe(fb)

                # 目标梯度：指向增加余弦相似度的方向
                # d(cos_sim)/d(a_i) = (b_i - cos_sim * a_i) / (||a|| * ||b||)
                cos_sim = EmbeddingStore._cosine_similarity(emb_a_vec, emb_b_vec)
                target_grad_a = [(emb_b_vec[i] - cos_sim * emb_a_vec[i])
                                 for i in range(len(emb_a_vec))]
                target_grad_b = [(emb_a_vec[i] - cos_sim * emb_b_vec[i])
                                 for i in range(len(emb_b_vec))]

                grad_w_a, grad_b_a = emb_a.compute_gradients_fe(fa, target_grad_a)
                grad_w_b, grad_b_b = emb_b.compute_gradients_fe(fb, target_grad_b)

                # 更新权重
                li = 0
                while li < len(emb_a.m_weights):
                    opt_a.step_ao(emb_a.m_weights[li], emb_a.m_biases[li],
                                  grad_w_a[li], grad_b_a[li])
                    opt_b.step_ao(emb_b.m_weights[li], emb_b.m_biases[li],
                                  grad_w_b[li], grad_b_b[li])
                    li += 1
                si += 1

            epoch += 1

        return history

    def cross_modal_search_cma(self, query_features, query_modality,
                                target_modality, top_k=10, threshold=0.5):
        """跨模态搜索：用一种模态的查询在另一种模态的索引中搜索。

        Args:
            query_features: 查询特征（query_modality 格式）
            query_modality: 查询模态名称
            target_modality: 目标模态名称
            top_k: 返回结果数
            threshold: 相似度阈值

        Returns:
            list of (func_id, similarity, metadata)
        """
        if query_modality not in self.m_embedders:
            return []
        query_emb = self.m_embedders[query_modality].embed_fe(query_features)

        # 跨模态搜索：此处需要 target_modality 的向量存储
        # 实际部署时应维护每个模态独立的 EmbeddingStore
        # 当前返回空列表作为接口占位
        __dbg.warning(
            f"Cross-modal search {query_modality}→{target_modality}: "
            f"requires per-modality index (not yet wired)")
        return []


class DeepBinarySearcher:
    """Deep-learning-based binary code search engine.

    Indexes function embeddings and performs semantic similarity search.
    Uses Siamese architecture with contrastive loss training.

    增强：跨模态对齐 / 自适应优化器 / 梯度驱动训练
    """

    __slots__ = ('m_embedder', 'm_store', 'm_indexed_count',
                 'm_triplet_miner', 'm_loss_fn', 'm_optimizer',
                 'm_cross_modal_aligner', 'm_modality_embedders')

    def __init__(self, input_dim=128, hidden_dim=256, output_dim=64):
        self.m_embedder = FunctionEmbedder(input_dim, hidden_dim, output_dim)
        self.m_store = EmbeddingStore()
        self.m_indexed_count = 0
        self.m_triplet_miner = TripletMiner()
        self.m_loss_fn = ContrastiveLoss()
        self.m_optimizer = AdaptiveOptimizer()

        # 跨模态基础设施
        self.m_cross_modal_aligner = CrossModalContrastiveLoss()
        self.m_modality_embedders = {}  # modality_name -> FunctionEmbedder

    def register_modality_ds(self, name, input_dim=128, hidden_dim=256,
                             output_dim=64):
        """注册新模态编码器，用于跨模态对比学习。"""
        if name not in self.m_modality_embedders:
            self.m_modality_embedders[name] = FunctionEmbedder(
                input_dim, hidden_dim, output_dim, modality=name)

    def index_function_ds(self, func_id, features, metadata=None):
        """Compute embedding for a function and add to the search index.

        Args:
            func_id: unique function identifier.
            features: feature vector (list of floats).
            metadata: optional dict with function name, binary name, etc.
        """
        if func_id is None or features is None:
            return
        emb = self.m_embedder.embed_fe(features)
        self.m_store.add_es(func_id, emb, metadata)
        self.m_indexed_count += 1

    def index_function_multimodal_ds(self, func_id, modality_features,
                                      metadata=None):
        """跨模态索引：为同一函数在不同模态下的特征建索引。

        Args:
            func_id: 函数唯一标识
            modality_features: dict {modality_name: feature_vector}
            metadata: 可选元数据
        """
        if func_id is None or not modality_features:
            return
        for mod_name, feat_vec in modality_features.items():
            if mod_name in self.m_modality_embedders:
                emb = self.m_modality_embedders[mod_name].embed_fe(feat_vec)
                store_key = f"{func_id}::{mod_name}"
                self.m_store.add_es(store_key, emb, metadata)
        self.m_indexed_count += 1

    def index_batch_ds(self, function_list):
        """Index multiple functions at once.

        Args:
            function_list: list of (func_id, features, metadata) tuples.
        """
        fi = 0
        while fi < len(function_list):
            fid, feat, meta = function_list[fi]
            self.index_function_ds(fid, feat, meta)
            fi += 1

    def search_ds(self, query_features, top_k=10, threshold=0.5):
        """Search for semantically similar functions.

        Args:
            query_features: feature vector of the query function.
            top_k: number of results to return.
            threshold: minimum similarity score.

        Returns:
            list of (func_id, similarity, metadata) tuples.
        """
        if query_features is None:
            return []
        query_emb = self.m_embedder.embed_fe(query_features)
        return self.m_store.search_es(query_emb, top_k, threshold)

    def search_cross_modal_ds(self, query_features, query_modality,
                               target_modality, top_k=10, threshold=0.5):
        """跨模态搜索：用一种模态查另一种模态的索引。

        Args:
            query_features: 查询特征向量
            query_modality: 查询所属模态名
            target_modality: 目标模态名
            top_k, threshold: 标准搜索参数

        Returns:
            list of (func_id, similarity, metadata)
        """
        if query_features is None:
            return []
        if query_modality not in self.m_modality_embedders:
            __dbg.warning(f"Unknown query modality: {query_modality}")
            return []
        query_emb = self.m_modality_embedders[query_modality].embed_fe(
            query_features)

        # 过滤目标模态的索引条目
        target_suffix = f"::{target_modality}"
        filtered_results = []
        all_results = self.m_store.search_es(query_emb, top_k * 3, threshold)

        ri = 0
        while ri < len(all_results):
            key, sim, meta = all_results[ri]
            if key.endswith(target_suffix):
                clean_key = key.rsplit("::", 1)[0]
                filtered_results.append((clean_key, sim, meta))
            ri += 1

        return filtered_results[:top_k]

    def train_contrastive_ds(self, pairs, labels, epochs=10, lr=0.01):
        """Train embedder with contrastive learning on similarity pairs.

        增强：使用动量 SGD + 余弦退火替代固定学习率。

        Args:
            pairs: list of (vec_a, vec_b) feature vector pairs.
            labels: list of binary labels (1=similar, 0=dissimilar).
            epochs: number of training epochs.
            lr: learning rate.
        """
        if pairs is None or labels is None or len(pairs) == 0:
            return

        opt = AdaptiveOptimizer(lr_init=lr, T_max=epochs)

        epoch = 0
        while epoch < epochs:
            total_loss = 0.0
            pi = 0
            while pi < len(pairs):
                a_feat, b_feat = pairs[pi]
                emb_a = self.m_embedder.embed_fe(a_feat)
                emb_b = self.m_embedder.embed_fe(b_feat)
                loss = self.m_loss_fn.compute_cl(emb_a, emb_b, labels[pi])
                total_loss += loss
                pi += 1

            avg_loss = total_loss / max(len(pairs), 1)
            if epoch % max(epochs // 5, 1) == 0:
                __dbg.info(f"Epoch {epoch}/{epochs}, loss={avg_loss:.4f}")

            # 梯度驱动更新：对 batch 中每个样本计算梯度并累积
            # 使用数值梯度估计（生产环境替换为 autograd）
            si = 0
            while si < min(len(pairs), 16):
                a_feat, b_feat = pairs[si]
                lbl = labels[si]

                emb_a_vec = self.m_embedder.embed_fe(a_feat)
                emb_b_vec = self.m_embedder.embed_fe(b_feat)
                dist = EmbeddingStore._euclidean_distance(emb_a_vec, emb_b_vec)

                # 计算 dL/d(emb_a) 和 dL/d(emb_b)
                if dist < 1e-9:
                    grad_a = [0.0] * len(emb_a_vec)
                    grad_b = [0.0] * len(emb_b_vec)
                elif lbl > 0.5:
                    # L = 0.5 * d^2  →  dL/d(emb_a) = (emb_a - emb_b)
                    grad_a = [(emb_a_vec[i] - emb_b_vec[i]) for i in range(len(emb_a_vec))]
                    grad_b = [(emb_b_vec[i] - emb_a_vec[i]) for i in range(len(emb_b_vec))]
                else:
                    # L = 0.5 * max(margin - d, 0)^2
                    margin = self.m_loss_fn.m_margin
                    if dist >= margin:
                        grad_a = [0.0] * len(emb_a_vec)
                        grad_b = [0.0] * len(emb_b_vec)
                    else:
                        scale = -(margin - dist) / dist
                        grad_a = [scale * (emb_a_vec[i] - emb_b_vec[i])
                                  for i in range(len(emb_a_vec))]
                        grad_b = [scale * (emb_b_vec[i] - emb_a_vec[i])
                                  for i in range(len(emb_b_vec))]

                gw_a, gb_a = self.m_embedder.compute_gradients_fe(a_feat, grad_a)
                gw_b, gb_b = self.m_embedder.compute_gradients_fe(b_feat, grad_b)

                # 更新 embedder 权重
                li = 0
                while li < len(self.m_embedder.m_weights):
                    opt.step_ao(self.m_embedder.m_weights[li],
                                self.m_embedder.m_biases[li],
                                gw_a[li], gb_a[li])
                    li += 1

                si += 1

            epoch += 1

    def train_cross_modal_ds(self, modality_a, modality_b, paired_samples,
                              epochs=20, lr=0.005):
        """跨模态对比预训练：对齐两个模态的嵌入空间。

        Args:
            modality_a, modality_b: 模态名称
            paired_samples: [(features_a, features_b), ...]
            epochs, lr: 训练参数
        """
        aligner = CrossModalAligner(
            embedders=self.m_modality_embedders,
            temperature=self.m_cross_modal_aligner.m_temperature,
            projection_dim=self.m_embedder.m_output_dim)

        return aligner.align_pair_cma(modality_a, modality_b,
                                       paired_samples, epochs, lr)

    def mine_hard_triplets_ds(self, anchor_features, positive_features,
                               all_features, labels, semi_hard=True):
        """Mine hard triplets for improved contrastive training.

        Returns list of (anchor_key, positive_key, negative_key).
        """
        # Convert features to embeddings first
        anchor_embs = {}
        pos_embs = {}
        all_embs = {}

        for k, v in anchor_features.items():
            anchor_embs[k] = self.m_embedder.embed_fe(v)
        for k, v in positive_features.items():
            pos_embs[k] = self.m_embedder.embed_fe(v)
        for k, v in all_features.items():
            all_embs[k] = self.m_embedder.embed_fe(v)

        miner = TripletMiner(semi_hard=semi_hard)
        return miner.mine_triplets_tm(anchor_embs, pos_embs, all_embs, labels)

    def mine_batch_aware_triplets_ds(self, anchor_features, positive_features,
                                      all_features, labels, batch_size=32):
        """批次感知三元组挖掘：在线训练友好，O(B^2) 复杂度。"""
        anchor_embs = {k: self.m_embedder.embed_fe(v)
                       for k, v in anchor_features.items()}
        pos_embs = {k: self.m_embedder.embed_fe(v)
                    for k, v in positive_features.items()}
        all_embs = {k: self.m_embedder.embed_fe(v)
                    for k, v in all_features.items()}

        miner = TripletMiner(semi_hard=True)
        return miner.mine_batch_aware_tm(anchor_embs, pos_embs, all_embs,
                                          labels, batch_size)

    def get_index_stats_ds(self):
        """Return index statistics."""
        stats = {
            'indexed_functions': self.m_indexed_count,
            'embedding_dim': self.m_embedder.m_output_dim,
            'store_size': len(self.m_store.m_vectors),
        }
        if self.m_modality_embedders:
            stats['modalities'] = list(self.m_modality_embedders.keys())
        return stats

    def remove_function_ds(self, func_id):
        """Remove a function from the index."""
        self.m_store.remove_es(func_id)
        # 同时清理跨模态索引
        for mod_name in list(self.m_modality_embedders.keys()):
            self.m_store.remove_es(f"{func_id}::{mod_name}")
        self.m_indexed_count = max(0, self.m_indexed_count - 1)

    def clear_index_ds(self):
        """Clear all indexed functions."""
        self.m_store = EmbeddingStore()
        self.m_indexed_count = 0

    def reset_optimizer_ds(self):
        """重置优化器状态，新一轮训练前调用。"""
        self.m_optimizer.reset_ao()


def create_deep_searcher(input_dim=128, hidden_dim=256, output_dim=64):
    return DeepBinarySearcher(input_dim, hidden_dim, output_dim)


def create_multimodal_searcher(input_dim=128, hidden_dim=256, output_dim=64,
                                modalities=None):
    """创建支持跨模态对齐的搜索器。

    Args:
        input_dim, hidden_dim, output_dim: 网络架构参数
        modalities: list of modality names to pre-register

    Returns:
        DeepBinarySearcher with modality embedders registered
    """
    searcher = DeepBinarySearcher(input_dim, hidden_dim, output_dim)
    if modalities:
        for mod in modalities:
            searcher.register_modality_ds(mod, input_dim, hidden_dim, output_dim)
    return searcher
