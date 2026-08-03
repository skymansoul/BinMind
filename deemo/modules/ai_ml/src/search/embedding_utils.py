# Embedding utilities extracted from deep_search.py.
# INTJ rationale: EmbeddingStore and FunctionEmbedder form the core representation
# layer — 向量 storage, similarity metrics, and neural 嵌入 构造.
# Extracting them into a dedicated module decouples the representation concern
# from the 训练/推理 orchestration in deep_search.py, allowing each
# to evolve independently. The remaining classes (AdaptiveOptimizer, TripletMiner,
# ContrastiveLoss, CrossModalContrastiveLoss, CrossModalAligner, DeepBinarySearcher)
# are 训练/search orchestration and naturally depend on these primitives.
# This split follows the single-responsibility principle: one module owns the
# "what is an 嵌入" question; the other owns "how to learn and use them."

import logging as _logging
import math as _math
import random as _rnd

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

        # Layer 3: Linear (嵌入)
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
        # dL/dW2 = grad_emb_pre ⊗ h2_post (outer product)
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
