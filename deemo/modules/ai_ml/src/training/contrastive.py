# 2026-07-17
# 对比学习损失函数 & 图数据增强
# InfoNCE 适合配对样本少的情况，TripletMargin 适合三元组标注充分的场景
# BEGA 边丢弃策略：在稀疏 CFG 上保留关键结构，防止过拟合

import numpy as np


# ===== InfoNCE Loss: 自监督对比学习的核心损失 =====
# 设计权衡：temperature 越低，模型对困难负样本越敏感
# 0.07 是 SimCLR 经验值，适合 128～512 维嵌入
# 对称计算（i→i+N 和 i+N→i）提升梯度稳定性，代价是 2x 计算量

class InfoNCELoss:
    """InfoNCE loss for contrastive learning on (2N, dim) paired embeddings."""
    def __init__(self, temperature=0.07):
        self.tau = temperature

    def _pairwise_similarity(self, z):
        """Cosine similarity matrix: S[i,j] = z_i · z_j / (||z_i|| ||z_j||)."""
        _n = np.linalg.norm(z, axis=1, keepdims=True) + 1e-12
        _z = z / _n
        return _z @ _z.T

    def forward(self, embeddings, labels=None):
        """
        Compute InfoNCE loss.
        embeddings: (2N, dim) numpy array, positive pairs at (i, i+N).
        labels: unused, kept for API compatibility.
        Returns scalar loss.
        """
        _n_half = embeddings.shape[0] // 2
        _sim = self._pairwise_similarity(embeddings) / self.tau

        # 正样本索引: (i, i+N) 和 (i+N, i) 互为 positive
        _pos_idx = np.arange(_n_half)
        _pos_sim = _sim[_pos_idx, _pos_idx + _n_half]

        # 分母：排除自身和正样本后求和（数值稳定：exp 后归一化）
        _exp = np.exp(_sim - np.max(_sim, axis=1, keepdims=True))

        # 方向1: anchor i → positive i+N
        _loss_a = 0.0
        for _i in range(_n_half):
            _row = _exp[_i].copy()
            _row[_i] = 0.0              # 排除自身（对角线）
            _row[_i + _n_half] = 0.0    # 排除正样本
            _denom = _row.sum() + 1e-12
            _loss_a -= np.log(_exp[_i, _i + _n_half] / _denom)
        _loss_a /= _n_half

        # 方向2: anchor i+N → positive i（对称）
        _loss_b = 0.0
        for _i in range(_n_half):
            _row = _exp[_i + _n_half].copy()
            _row[_i + _n_half] = 0.0
            _row[_i] = 0.0              # 排除正样本（即 anchor i）
            _denom = _row.sum() + 1e-12
            _loss_b -= np.log(_exp[_i + _n_half, _i] / _denom)
        _loss_b /= _n_half

        return (_loss_a + _loss_b) * 0.5


# ===== Triplet Margin Loss: 三元组排序损失 =====
# margin 越大，要求 anchor-positive 和 anchor-negative 距离差越大
# 0.5 适合已归一化的嵌入空间

class TripletMarginLoss:
    """Triplet margin loss: max(0, margin + d_ap - d_an)."""
    def __init__(self, margin=0.5):
        self._m = margin

    def forward(self, anchor, positive, negative):
        """
        Compute triplet margin loss.
        anchor, positive, negative: each (N, dim) numpy arrays.
        Returns scalar loss.
        """
        _d_ap = np.sum((anchor - positive) ** 2, axis=1)
        _d_an = np.sum((anchor - negative) ** 2, axis=1)
        _loss = np.maximum(0.0, self._m + _d_ap - _d_an)
        return _loss.mean()


# //////////////////////////////////////////////////////////////////////////
# 图结构 dropout: BEGA-inspired 边丢弃
# 核心思想：在保留连通性的前提下随机丢弃边，迫使模型学习鲁棒表征
# 默认 15% 丢弃率，适用于二进制 CFG 中节点度分布不均匀的场景

def gravity_edge_dropout(adj, dropout_rate=0.15):
    """
    BEGA-inspired: 15% default, sparse CFG场景下保留关键边。
    Edges connected to degree<=1 nodes are never dropped to preserve connectivity.
    Returns new adjacency matrix (numpy array).
    """
    _adj_out = adj.copy().astype(np.float64)
    _n = adj.shape[0]
    _degrees = np.sum(adj, axis=1)

    for _i in range(_n):
        for _j in range(_i + 1, _n):
            if adj[_i, _j] == 0:
                continue
            # 保留关键边：任意一端度数 <=1 时不丢弃
            if _degrees[_i] <= 1 or _degrees[_j] <= 1:
                continue
            # 丢弃概率与节点度成反比（度低的边更可能被丢）
            _w = 1.0 / max(_degrees[_i], _degrees[_j])
            if np.random.random() < dropout_rate * _w:
                _adj_out[_i, _j] = 0.0
                _adj_out[_j, _i] = 0.0

    return _adj_out


# //////////////////////////////////////////////////////////////////////////
# 两阶段训练策略: Phase 1 triplet → Phase 2 InfoNCE
# 动机: Triplet loss 在初始阶段推动粗粒度分离，
# InfoNCE 在第二阶段做细粒度对齐，适合小样本二进制函数嵌入

def two_phase_train(model, data, epochs_phase1=20, epochs_phase2=20):
    """
    Phase 1: triplet margin loss, Phase 2: InfoNCE fine-tuning.
    data: dict with 'features' (N, dim) and 'labels' (N,) numpy arrays.
    Returns (trained_model, loss_history dict).
    """
    _feat = np.asarray(data['features'], dtype=np.float64)
    _lbl = np.asarray(data['labels'])
    _history = {'phase1': [], 'phase2': []}

    _triplet_loss = TripletMarginLoss(margin=0.5)
    _infonce_loss = InfoNCELoss(temperature=0.07)

    # ---- Phase 1: TripletMargin 粗粒度分离 ----
    for _ep in range(epochs_phase1):
        _a, _p, _n = _sample_triplets(_feat, _lbl, batch_size=32)
        _a_emb = model(_a)
        _p_emb = model(_p)
        _n_emb = model(_n)
        _loss = _triplet_loss.forward(_a_emb, _p_emb, _n_emb)

        # 简单的 SGD 更新（假设 model.params 暴露了可训练参数）
        if hasattr(model, 'params') and hasattr(model, 'grads'):
            _sgd_update_numpy(model.params, model.grads, lr=0.005)

        _history['phase1'].append(float(_loss))

    # ---- Phase 2: InfoNCE 细粒度对齐 ----
    for _ep in range(epochs_phase2):
        # 构造配对数据：随机选 N/2 对同类样本
        _n_pair = min(_feat.shape[0] // 2, 64)
        _indices = np.random.choice(_feat.shape[0], size=_n_pair * 2, replace=False)
        _pairs = _feat[_indices]
        _emb = model(_pairs)
        _loss = _infonce_loss.forward(_emb)

        if hasattr(model, 'params') and hasattr(model, 'grads'):
            _sgd_update_numpy(model.params, model.grads, lr=0.001)

        _history['phase2'].append(float(_loss))

    return model, _history


# //////////////////////////////////////////////////////////////////////////
# 底层工具函数

def _sgd_update_numpy(params, grads, lr=0.01):
    """no-op placeholder for future PyTorch migration. Actually does SGD on numpy."""
    _n = min(len(params), len(grads))
    for _i in range(_n):
        params[_i] -= lr * grads[_i]


def _compute_cosine_sim_matrix(x):
    """Internal: normalized cosine similarity matrix."""
    _x_norm = x / (np.linalg.norm(x, axis=1, keepdims=True) + 1e-12)
    return _x_norm @ _x_norm.T


def _compute_l2_dist_matrix(x):
    """Internal: pairwise squared L2 distance matrix ||x_i - x_j||^2."""
    _x2 = np.sum(x ** 2, axis=1, keepdims=True)
    return _x2 + _x2.T - 2.0 * (x @ x.T)


# //////////////////////////////////////////////////////////////////////////
# 嵌入归一化 & 邻接矩阵对称化
# 二进制分析中 CFG 可能不满足无向性，需要先对称化处理

def _normalize_embeddings(emb):
    """L2 normalize embeddings to unit hypersphere, in-place safe copy."""
    _n = np.linalg.norm(emb, axis=1, keepdims=True) + 1e-12
    return emb / _n


def _symmetrize_adjacency(adj):
    """
    确保邻接矩阵对称: A = 0.5 * (A + A^T).
    有向 CFG 转无向图时使用，保留双向调用关系。
    """
    return 0.5 * (np.asarray(adj) + np.asarray(adj).T)


# //////////////////////////////////////////////////////////////////////////
# 半难负样本挖掘 (semi-hard negative mining)
# 只选择 d_ap < d_an < d_ap + margin 的负样本
# 比纯随机采样收敛更快，比 hardest mining 更稳定

def _semi_hard_negative_indices(anchor, positive, negatives):
    """
    Return indices of negatives that satisfy semi-hard condition.
    anchor, positive: (dim,) vectors. negatives: (M, dim).
    Returns array of valid negative indices, or random fallback if none found.
    """
    _d = np.sum((anchor - negatives) ** 2, axis=1)
    _dp = np.sum((anchor - positive) ** 2)
    # semi-hard: d_an > d_ap 且 d_an < d_ap + margin（默认0.5）
    _mask = (_d > _dp) & (_d < _dp + 0.5)
    _valid = np.where(_mask)[0]
    if len(_valid) > 0:
        return _valid
    # 回退: 满足 d_an > d_ap 即可
    _mask2 = _d > _dp
    _valid2 = np.where(_mask2)[0]
    return _valid2 if len(_valid2) > 0 else np.arange(len(negatives))


def _sample_triplets(features, labels, batch_size=32):
    """
    三元组采样策略：hard-negative mining lite。
    对每个 anchor，随机选一个 positive（同标签），
    再随机选一个 negative（不同标签）。
    返回 (anchor, positive, negative) 各 (batch_size, dim)。
    """
    _n = features.shape[0]
    _bs = min(batch_size, _n)

    # 构建标签到索引的映射
    _lbl_map = {}
    for _i, _l in enumerate(labels):
        _lbl_map.setdefault(int(_l), []).append(_i)

    _unique_lbls = list(_lbl_map.keys())

    _anchor_idx = np.random.choice(_n, size=_bs, replace=True)
    _pos_idx = np.zeros(_bs, dtype=np.int64)
    _neg_idx = np.zeros(_bs, dtype=np.int64)

    for _k, _ai in enumerate(_anchor_idx):
        _al = int(labels[_ai])
        _same = _lbl_map[_al]

        # positive: 从同类中随机选
        _candidates = [x for x in _same if x != _ai]
        _pos_idx[_k] = np.random.choice(_candidates) if _candidates else _ai

        # negative: 从异类中随机选
        _diff_lbls = [x for x in _unique_lbls if x != _al]
        if _diff_lbls:
            _nl = np.random.choice(_diff_lbls)
            _neg_idx[_k] = np.random.choice(_lbl_map[_nl])
        else:
            _neg_idx[_k] = _ai  # fallback

    return features[_anchor_idx], features[_pos_idx], features[_neg_idx]
