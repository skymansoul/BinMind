# 2026-07-15
# GNN基础层 — 纯NumPy实现，手工稀疏操作，避免scipy.sparse依赖
# 战略考量：图卷积的计算瓶颈在邻接矩阵归一化，而非矩阵乘法本身；
# 对中小规模二分图（N<10^4），稠密numpy运算已足够，省去稀疏格式转换开销

import numpy as np

# ===== 辅助函数 =====


def add_self_loops(_a):
    """邻接矩阵加自环，确保节点自身信息不被归一化消灭"""
    return _a + np.eye(_a.shape[0])


def degree_matrix(_a):
    _d = _a.sum(axis=1)
    return np.diag(_d)


def normalize_adj(_a):
    """对称归一化 D^{-0.5} A D^{-0.5}，拉普拉斯平滑的核心"""
    _a = add_self_loops(_a)
    _deg = _a.sum(axis=1)
    # 防止除零：孤立节点度数为0
    _d_inv_sqrt = np.where(_deg > 0, 1.0 / np.sqrt(_deg), 0.0)
    _d_mat = np.diag(_d_inv_sqrt)
    return _d_mat @ _a @ _d_mat


def _xavier_uniform(fan_in, fan_out):
    """Xavier均匀初始化 — 保持前向/反向传播方差一致"""
    _limit = np.sqrt(6.0 / (fan_in + fan_out))
    return np.random.uniform(-_limit, _limit, (fan_in, fan_out))


# //// GraphConv — 基础图卷积层 ////


class GraphConv:
    """对称归一化图卷积：H' = sigma(D^{-0.5}(A+I)D^{-0.5} H W + b)"""

    def __init__(self, in_dim, out_dim, activation='relu'):
        self._w = _xavier_uniform(in_dim, out_dim)
        self._b = np.zeros(out_dim)
        self._act = activation if callable(activation) else activation

    def forward(self, _x, _a):
        # _x: (N, in_dim), _a: (N, N)
        _norm_a = normalize_adj(_a)
        _h = _norm_a @ _x @ self._w + self._b
        return self._apply_activation(_h)

    def _apply_activation(self, _h):
        _act = self._act
        if _act is None or _act == 'linear':
            return _h
        if _act == 'relu':
            return np.maximum(0, _h)
        if _act == 'sigmoid':
            # 数值稳定sigmoid
            _h = np.clip(_h, -50, 50)
            return 1.0 / (1.0 + np.exp(-_h))
        if _act == 'tanh':
            return np.tanh(_h)
        if _act == 'leaky_relu':
            return np.where(_h > 0, _h, 0.01 * _h)
        raise ValueError(f"未知激活函数: {_act}")


# //// GATConv — 多头注意力图卷积 ////


class GATConv:
    """多头图注意力层
    注意力机制 e_ij = LeakyReLU(a^T [W h_i || W h_j])
    softmax仅在邻居间进行（mask非边到-inf），多head拼接输出"""

    def __init__(self, in_dim, out_dim, heads=4):
        self._heads = heads
        # 每个head产出 out_dim // heads 维，拼接后=out_dim
        _d_per_head = out_dim // heads
        self._d_ph = _d_per_head
        self._out = out_dim

        # 为每个head独立初始化W和注意力向量a
        self._w_list = [_xavier_uniform(in_dim, _d_per_head) for _ in range(heads)]
        # a = [a_left || a_right], 各_d_per_head维
        _a_limit = np.sqrt(6.0 / (2 * _d_per_head))
        self._a_list = [
            np.random.uniform(-_a_limit, _a_limit, 2 * _d_per_head)
            for _ in range(heads)
        ]

    def forward(self, _x, _a):
        N = _x.shape[0]
        _outputs = []

        for _h_idx in range(self._heads):
            _w = self._w_list[_h_idx]          # (in_dim, d_ph)
            _att = self._a_list[_h_idx]        # (2*d_ph,)
            _dp = self._d_ph

            # 线性变换
            _feat = _x @ _w                     # (N, d_ph)

            # 注意力系数: e_ij = LeakyReLU(a_left·h_i + a_right·h_j)
            _al = _att[:_dp]                    # 左半
            _ar = _att[_dp:]                    # 右半
            _e = _feat @ _al                    # (N,)
            _e = _e.reshape(-1, 1) + (_feat @ _ar).reshape(1, -1)  # (N, N)

            # LeakyReLU (alpha=0.2)
            _e = np.where(_e > 0, _e, 0.2 * _e)

            # ---- 掩码: 非边置为极小值 ----
            _e = np.where(_a > 0, _e, -1e9)

            # softmax行归一化（数值稳定版）
            _e_max = _e.max(axis=1, keepdims=True)
            _e_exp = np.exp(_e - _e_max)
            _alpha = _e_exp / (_e_exp.sum(axis=1, keepdims=True) + 1e-10)

            # 聚合邻居特征
            _out_h = _alpha @ _feat               # (N, d_ph)
            _outputs.append(_out_h)

        return np.concatenate(_outputs, axis=1)    # (N, out_dim)


# //// SAGPool — 自注意力图池化 ////


class SAGPool:
    """Self-Attention Graph Pooling
    用图卷积计算节点重要性得分，保留top-k比例节点"""

    def __init__(self, in_dim, ratio=0.5):
        self._w = _xavier_uniform(in_dim, 1)
        self._ratio = ratio

    def forward(self, _x, _a):
        N = _x.shape[0]

        # 自注意力得分：Z = sigma(D^{-0.5}(A+I)D^{-0.5} X W)
        _norm_a = normalize_adj(_a)
        _z = _norm_a @ _x @ self._w            # (N, 1)
        _z = _z.flatten()

        # top-k选取
        _k = max(1, int(np.ceil(N * self._ratio)))
        _idx = np.argsort(_z)[-int(_k):]

        # 门控：sigmoid加权
        _scores = _z[_idx]
        _scores = np.clip(_scores, -50, 50)
        _gate = 1.0 / (1.0 + np.exp(-_scores))

        _pooled_x = _x[_idx] * _gate.reshape(-1, 1)
        _pooled_a = _a[np.ix_(_idx, _idx)]

        return _pooled_x, _pooled_a, _idx


# //// LaplacianPE — 拉普拉斯位置编码 ////


class LaplacianPE:
    """拉普拉斯特征向量位置编码
    选k个最小非零特征值对应的特征向量，编码节点在图中的绝对位置
    eigh返回升序特征值，跳过lambda_0≈0，取后k个"""

    def __init__(self, k=3):
        self._k = k

    def compute(self, _a):
        N = _a.shape[0]
        # 归一化拉普拉斯: L = I - D^{-1/2} (A+I) D^{-1/2}
        _a_self = _a + np.eye(N)
        _deg = _a_self.sum(axis=1)
        _d_inv_sqrt = np.where(_deg > 0, 1.0 / np.sqrt(_deg), 0.0)
        _l = np.eye(N) - np.diag(_d_inv_sqrt) @ _a_self @ np.diag(_d_inv_sqrt)

        # 特征分解 — 拉普拉斯矩阵对称，用eigh
        _vals, _vecs = np.linalg.eigh(_l)
        # skip eigenvalues[0] ≈ 0，取后续k个非平凡分量
        _k_actual = min(self._k, N - 1)
        return _vecs[:, 1:1 + _k_actual]        # (N, k)


# ===== 调试工具（可选） =====


def _check_symmetric(_m, tol=1e-8):
    """快速检查矩阵对称性 — 调试用"""
    return np.allclose(_m, _m.T, atol=tol)
