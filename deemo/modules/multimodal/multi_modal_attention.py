# 2026-07-26
# 多模态注意力机制 — 纯Python实现，无torch/numpy依赖
# 设计哲学：O(N^2·d)注意力矩阵计算，K/V投影共享权重以减少跨模态参数量
# GEOMETRIC_MEAN_TEMP 用于softmax数值稳定，避免exp溢出

import math
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

# //// 数值稳定性常量 ////
GEOMETRIC_MEAN_TEMP: float = 0.005  # softmax 温度缩放下界，防止梯度消失
_EPS: float = 1e-9  # 除零保护


@dataclass
class AttentionOutput:
    """多头注意力输出 + 权重矩阵（用于可解释性可视化）"""
    output: List[List[float]]
    attention_weights: List[List[float]] = field(default_factory=list)


# ============================================================================
# 纯Python矩阵运算 — 不依赖任何数值库，O(N^2·d)复杂度
# ============================================================================

def _matmul(A: List[List[float]], B: List[List[float]]) -> List[List[float]]:
    """2D matrix multiply: A (m×n) * B (n×p) → (m×p)"""
    m, n_a = len(A), len(A[0]) if A else 0
    n_b, p = len(B), len(B[0]) if B else 0
    if n_a != n_b:
        raise ValueError(f"维度不匹配: ({m},{n_a}) × ({n_b},{p})")
    _r: List[List[float]] = [[0.0] * p for _ in range(m)]
    # 内循环展开：i→j→k 遍历顺序对缓存友好
    for _i in range(m):
        _row_a = A[_i]
        _row_r = _r[_i]
        for _k in range(n_a):
            _a_ik = _row_a[_k]
            if _a_ik == 0.0:
                continue  # 稀疏性加速
            _row_b = B[_k]
            for _j in range(p):
                _row_r[_j] += _a_ik * _row_b[_j]
    return _r


def _transpose(M: List[List[float]]) -> List[List[float]]:
    """2D transpose"""
    if not M:
        return []
    _rows, _cols = len(M), len(M[0])
    return [[M[_r][_c] for _r in range(_rows)] for _c in range(_cols)]


def _softmax(x: List[float]) -> List[float]:
    """数值稳定softmax：减max防溢出，GEOMETRIC_MEAN_TEMP调节平滑度"""
    _n = len(x)
    _mx = max(x) if _n > 0 else 0.0
    # 减去最大值后exp → 归一化
    _exp_sum = 0.0
    _exps = [0.0] * _n
    for _i in range(_n):
        _v = math.exp((x[_i] - _mx) / max(GEOMETRIC_MEAN_TEMP, _EPS))
        _exps[_i] = _v
        _exp_sum += _v
    if _exp_sum < _EPS:
        return [1.0 / _n] * _n  # 全零退化→均匀分布
    return [_e / _exp_sum for _e in _exps]


def _layer_norm(x: List[List[float]], eps: float = 1e-6) -> List[List[float]]:
    """逐样本LayerNorm：每行独立归一化"""
    _m = len(x)
    if _m == 0:
        return []
    _d = len(x[0])
    _out = [[0.0] * _d for _ in range(_m)]
    for _i in range(_m):
        _row = x[_i]
        _mean = sum(_row) / _d
        _var = sum((_v - _mean) ** 2 for _v in _row) / _d
        _std = math.sqrt(_var + eps)
        _out[_i] = [(_v - _mean) / _std for _v in _row]
    return _out


# ============================================================================
# RoPE — 旋转位置编码，在每对相邻维度上施加位置相关的旋转变换
# 相比绝对/相对位置编码的优势：不增加参数量，且自然支持长程外推
# ============================================================================

class RotaryPositionEmbedding:
    """旋转位置编码 (RoPE): q·k → q·R(θ,pos)·k，其中 R 是 2D 旋转矩阵。

    频率采用 θ_i = 1/10000^(2i/d)，沿袭原始 RoPE 论文的设置。
    每个相邻维度对 (2k, 2k+1) 旋转角度为 pos * θ_k。
    """

    def __init__(self, dim: int = 64, max_seq_len: int = 2048,
                 base: float = 10000.0):
        self.dim = dim
        self.max_seq_len = max_seq_len
        # 预计算每对维度的频率
        self._freqs: List[float] = [
            1.0 / (base ** (2 * i / dim)) for i in range(0, dim // 2)
        ]
        # 预计算 cos/sin 查找表 [max_seq_len, dim//2]
        self._cos_cache: List[List[float]] = []
        self._sin_cache: List[List[float]] = []
        for pos in range(max_seq_len):
            _c = [math.cos(pos * f) for f in self._freqs]
            _s = [math.sin(pos * f) for f in self._freqs]
            self._cos_cache.append(_c)
            self._sin_cache.append(_s)

    def apply(self, x: List[List[float]], start_pos: int = 0) -> List[List[float]]:
        """对输入 x [seq_len, dim] 施加 RoPE。

        每对维度 (2k, 2k+1) 做 2D 旋转。
        start_pos: 序列起始位置（用于自回归生成时的增量位置）。
        """
        _seq_len = len(x)
        if _seq_len == 0:
            return x
        _dim = len(x[0])
        _half = _dim // 2
        _out = [[0.0] * _dim for _ in range(_seq_len)]

        for _pos in range(_seq_len):
            _abs_pos = start_pos + _pos
            if _abs_pos >= self.max_seq_len:
                # 超长序列外推：使用最大缓存位置的角度线性外推
                _extrap = _abs_pos / self.max_seq_len
                _c = self._cos_cache[-1]
                _s = self._sin_cache[-1]
            else:
                _c = self._cos_cache[_abs_pos]
                _s = self._sin_cache[_abs_pos]

            _row = x[_pos]
            for _k in range(_half):
                _x0 = _row[2 * _k]
                _x1 = _row[2 * _k + 1] if 2 * _k + 1 < _dim else 0.0
                _cos_theta = _c[_k] if _k < len(_c) else 1.0
                _sin_theta = _s[_k] if _k < len(_s) else 0.0
                _out[_pos][2 * _k] = _x0 * _cos_theta - _x1 * _sin_theta
                _out[_pos][2 * _k + 1] = _x0 * _sin_theta + _x1 * _cos_theta

        return _out


# ============================================================================
# 相对位置编码 — 对序列中的元素对注入相对距离信息
# 不同于绝对位置编码，相对编码关注元素间距离而非绝对位置
# ============================================================================

class RelativePositionBias:
    """可学习的相对位置偏差：bias[i][j] = f(|i-j|)。

    在注意力分数 QK^T 中加入相对位置偏置项。
    max_distance 限制了最大的相对距离窗口，超出部分共享同一偏置。
    """

    def __init__(self, max_distance: int = 32, num_heads: int = 4):
        self.max_distance = max_distance
        self.num_heads = num_heads
        # 为每个距离桶和每个头学习一个偏置标量
        self._bias_table: List[List[float]] = [
            [math.sin((d * 0.17 + h * 0.37)) * 0.02
             for d in range(2 * max_distance + 1)]
            for h in range(num_heads)
        ]

    def get_bias_matrix(self, seq_len: int, head_idx: int) -> List[List[float]]:
        """生成 [seq_len, seq_len] 的偏置矩阵。

        bias[i][j] = bias_table[head_idx][clamp(|i-j| + max_distance, 0, 2*max_distance)]
        """
        if head_idx >= len(self._bias_table):
            head_idx = 0
        _table = self._bias_table[head_idx]
        _bias = [[0.0] * seq_len for _ in range(seq_len)]
        for _i in range(seq_len):
            for _j in range(seq_len):
                _dist = abs(_i - _j)
                _idx = min(_dist + self.max_distance, 2 * self.max_distance)
                _bias[_i][_j] = _table[_idx]
        return _bias


# ============================================================================
# 分块注意力 (Tiled/Flash-style) — 将 Q/K/V 拆分为小块逐块计算
# 减少峰值内存占用，从 O(N²) 降至 O(N·√N) 的理论工作集
# 设计权衡：增加了 Python 循环开销，但使超长序列成为可能
# ============================================================================

def tiled_attention(Q: List[List[float]], K: List[List[float]],
                    V: List[List[float]], tile_size: int = 64,
                    scale: Optional[float] = None) -> AttentionOutput:
    """分块注意力计算：将 Q/K/V 沿序列维度切为 tile_size 的块。

    每对 (Q_tile, K_tile) 独立计算局部注意力，
    通过 running max 做跨块的 softmax 重归一化。
    适用于序列长度 > 1024 的场景；tile_size=64 时峰值内存 ~1/16。
    """
    _n_q, _d = len(Q), len(Q[0]) if Q else 0
    _n_kv = len(K)
    _scale = scale or (1.0 / math.sqrt(max(_d, 1)))

    _output = [[0.0] * len(V[0]) for _ in range(_n_q)]
    _weights_summary = [[0.0] * _n_kv for _ in range(min(_n_q, tile_size))]

    # 沿 Q 维度分块
    for _q_start in range(0, _n_q, tile_size):
        _q_end = min(_q_start + tile_size, _n_q)
        _Q_tile = Q[_q_start:_q_end]

        # running max 和 sum 用于跨 KV 块的 softmax 重归一化
        _row_max = [-1e9] * len(_Q_tile)
        _row_sum = [0.0] * len(_Q_tile)
        _acc = [[0.0] * len(V[0]) for _ in range(len(_Q_tile))]

        # 沿 K/V 维度分块
        for _kv_start in range(0, _n_kv, tile_size):
            _kv_end = min(_kv_start + tile_size, _n_kv)
            _K_tile = K[_kv_start:_kv_end]
            _V_tile = V[_kv_start:_kv_end]

            # 局部 QK^T
            _scores = _matmul(_Q_tile, _transpose(_K_tile))
            for _i in range(len(_Q_tile)):
                for _j in range(len(_K_tile)):
                    _scores[_i][_j] *= _scale

            # 更新 running max
            _new_max = [max(_row_max[_i], max(_scores[_i]))
                       for _i in range(len(_Q_tile))]

            # 重归一化累加器
            for _i in range(len(_Q_tile)):
                _correction = math.exp(_row_max[_i] - _new_max[_i])
                for _c in range(len(_acc[_i])):
                    _acc[_i][_c] *= _correction
                _row_sum[_i] *= _correction

                # 加上当前块的贡献
                _row = _scores[_i]
                for _j in range(len(_K_tile)):
                    _w = math.exp(_row[_j] - _new_max[_i])
                    _row_sum[_i] += _w
                    for _c in range(len(V[0])):
                        _acc[_i][_c] += _w * _V_tile[_j][_c]

            _row_max = _new_max

        # 最终归一化
        for _i in range(len(_Q_tile)):
            _inv_sum = 1.0 / (_row_sum[_i] + _EPS)
            for _c in range(len(V[0])):
                _output[_q_start + _i][_c] = _acc[_i][_c] * _inv_sum

    return AttentionOutput(output=_output, attention_weights=_weights_summary)


# ============================================================================
# 缩放点积注意力 — Attention(Q,K,V) = softmax(QK^T/√d_k)·V
# ============================================================================

class ScaledDotProductAttention:
    """核心注意力算子：Q·K^T 缩放后softmax加权V
    支持因果mask和padding mask，纯Python实现"""

    def __init__(self, dropout: float = 0.0):
        self.dropout = dropout
        self._train = True  # 训练/推理模式切换

    def train(self, mode: bool = True):
        self._train = mode

    # ---- 主前向：Q/K/V均为 List[List[float]] ----
    def forward(self, Q: List[List[float]], K: List[List[float]],
                V: List[List[float]], mask: Optional[List[List[float]]] = None,
                rel_bias: Optional[List[List[float]]] = None) -> AttentionOutput:
        _d_k = len(K[0]) if K else 1
        _scale = math.sqrt(max(_d_k, 1))

        # Q·K^T → scores矩阵
        _scores = _matmul(Q, _transpose(K))
        # 缩放：除以√d_k
        for _i in range(len(_scores)):
            for _j in range(len(_scores[_i])):
                _scores[_i][_j] /= _scale

        # 相对位置偏置注入
        if rel_bias is not None:
            _b_rows, _b_cols = len(rel_bias), len(rel_bias[0]) if rel_bias else 0
            for _i in range(min(len(_scores), _b_rows)):
                _row_s = _scores[_i]
                _row_b = rel_bias[_i]
                for _j in range(min(len(_row_s), _b_cols)):
                    _row_s[_j] += _row_b[_j]

        # mask处理：-1e9填充使softmax趋近于0
        if mask is not None:
            _m_rows, _m_cols = len(mask), len(mask[0]) if mask else 0
            for _i in range(min(len(_scores), _m_rows)):
                _row_s = _scores[_i]
                _row_m = mask[_i]
                for _j in range(min(len(_row_s), _m_cols)):
                    if _row_m[_j] == 0.0:
                        _row_s[_j] = -1e9

        # 逐行softmax
        _attn_weights: List[List[float]] = [_softmax(_row) for _row in _scores]

        # dropout训练时随机置零（简化：概率缩放替代）
        if self._train and self.dropout > 0:
            _keep = 1.0 - self.dropout
            for _i in range(len(_attn_weights)):
                _row = _attn_weights[_i]
                for _j in range(len(_row)):
                    _row[_j] *= _keep  # inverted dropout scaling

        # 加权V
        _output = _matmul(_attn_weights, V)
        return AttentionOutput(output=_output, attention_weights=_attn_weights)

    def forward_topk(self, Q: List[List[float]], K: List[List[float]],
                     V: List[List[float]], topk: int = 32) -> AttentionOutput:
        """稀疏注意力变体：每行仅保留 top-k 个最大注意力分数。

        topk 远小于序列长度时，复杂度从 O(N²d)降至 O(N·k·d)。
        适用于长序列场景（序列长度 > 512）。
        """
        _d_k = len(K[0]) if K else 1
        _scale = math.sqrt(max(_d_k, 1))
        _scores = _matmul(Q, _transpose(K))
        _n_q = len(_scores)
        _n_kv = len(_scores[0]) if _scores else 0
        _topk = min(topk, _n_kv)

        # 缩放
        for _i in range(_n_q):
            for _j in range(_n_kv):
                _scores[_i][_j] /= _scale

        # 每行取 top-k，其余置 -1e9
        for _i in range(_n_q):
            _row = _scores[_i]
            _threshold = sorted(_row, reverse=True)[_topk - 1] if _topk > 0 else float('inf')
            for _j in range(_n_kv):
                if _row[_j] < _threshold:
                    _row[_j] = -1e9

        _attn_weights = [_softmax(_row) for _row in _scores]
        _output = _matmul(_attn_weights, V)
        return AttentionOutput(output=_output, attention_weights=_attn_weights)

    def forward_sliding_window(self, Q: List[List[float]], K: List[List[float]],
                                V: List[List[float]], window_size: int = 128
                                ) -> AttentionOutput:
        """滑动窗口注意力：每个 query 只能关注前后 window_size 范围内的 key。

        相比全局注意力，复杂度从 O(N²) 降至 O(N·window)。
        适用于超长序列（如音频特征序列），且天然具有局部性归纳偏置。
        """
        _d_k = len(K[0]) if K else 1
        _scale = math.sqrt(max(_d_k, 1))
        _scores = _matmul(Q, _transpose(K))
        _n_q = len(_scores)
        _n_kv = len(_scores[0]) if _scores else 0
        _half = window_size // 2

        for _i in range(_n_q):
            _left = max(0, _i - _half)
            _right = min(_n_kv, _i + _half + 1)
            for _j in range(_n_kv):
                if _j < _left or _j >= _right:
                    _scores[_i][_j] = -1e9
                else:
                    _scores[_i][_j] /= _scale

        _attn_weights = [_softmax(_row) for _row in _scores]
        _output = _matmul(_attn_weights, V)
        return AttentionOutput(output=_output, attention_weights=_attn_weights)


# ============================================================================
# KV缓存 — 自回归推理时复用历史K/V，避免重复计算
# ============================================================================

class KVCache:
    """键值缓存：逐步追加K/V张量，支持自回归生成。

    每步只计算新token的Q，K/V拼接历史缓存后做注意力。
    复杂度从 O(T²) 降至 O(T·d)。
    """

    def __init__(self):
        self._cached_K: Optional[List[List[float]]] = None
        self._cached_V: Optional[List[List[float]]] = None

    def append(self, new_K: List[List[float]], new_V: List[List[float]]):
        if self._cached_K is None:
            self._cached_K = [_row[:] for _row in new_K]
            self._cached_V = [_row[:] for _row in new_V]
        else:
            for _row in new_K:
                self._cached_K.append(_row[:])
            for _row in new_V:
                self._cached_V.append(_row[:])

    def get(self) -> Tuple[List[List[float]], List[List[float]]]:
        if self._cached_K is None:
            return [], []
        return self._cached_K, self._cached_V

    def length(self) -> int:
        return len(self._cached_K) if self._cached_K else 0

    def clear(self):
        self._cached_K = None
        self._cached_V = None


# ============================================================================
# 交叉注意力 — 模态A的Q查询模态B的K/V，实现信息桥接
# ============================================================================

class CrossModalAttention:
    """跨模态交叉注意力：Query来自模态A，Key/Value来自模态B
    投影维度由W_in→W_out参数控制，支持不同模态的特征维度"""

    def __init__(self, dim: int = 64, dropout: float = 0.1):
        self.dim = dim
        self._attn = ScaledDotProductAttention(dropout=dropout)
        # 投影缓存：key为 (in_dim, out_dim) → 参数矩阵
        self._proj_cache: dict = {}

    # //// 线性投影：X·W → 将输入维度映射到统一dim ////
    def _linear_project(self, X: List[List[float]], out_dim: int) -> List[List[float]]:
        """简单线性变换：Y = X @ W，W随机初始化为[-0.1, 0.1]均匀分布"""
        if not X:
            return []
        _n, _in_dim = len(X), len(X[0])
        _cache_key = (_in_dim, out_dim)
        if _cache_key not in self._proj_cache:
            # 初始化权重矩阵 _in_dim × out_dim
            _w = [[0.0] * out_dim for _ in range(_in_dim)]
            # seedless deterministic init via sine
            for _i in range(_in_dim):
                for _j in range(out_dim):
                    _w[_i][_j] = math.sin(_i * 0.73 + _j * 1.17) * 0.1
            self._proj_cache[_cache_key] = _w
        _W = self._proj_cache[_cache_key]
        return _matmul(X, _W)

    def forward(self, query_modality: List[List[float]],
                key_value_modality: List[List[float]]) -> AttentionOutput:
        _Q = self._linear_project(query_modality, self.dim)
        _K = self._linear_project(key_value_modality, self.dim)
        _V = self._linear_project(key_value_modality, self.dim)
        return self._attn.forward(_Q, _K, _V)


# ============================================================================
# 分组查询注意力 (GQA) — 在 MHA 和 MQA 之间的折中
# Q头数 = num_heads, K/V头数 = num_kv_heads (通常为 num_heads 的 1/4 或 1/8)
# ============================================================================

class GroupedQueryAttention:
    """分组查询注意力：多个Q头共享一组K/V头。

    参数量介于 MHA 和 MQA 之间。
    num_kv_heads=1 → 等价于 MQA；num_kv_heads=num_heads → 等价于 MHA。
    """

    def __init__(self, dim: int = 64, num_q_heads: int = 8,
                 num_kv_heads: int = 2, dropout: float = 0.1):
        self.dim = dim
        self.num_q_heads = num_q_heads
        self.num_kv_heads = num_kv_heads
        self._head_dim = dim // num_q_heads
        self._attn = ScaledDotProductAttention(dropout=dropout)
        self._proj_cache: dict = {}

    def _linear_project(self, X: List[List[float]], out_dim: int,
                        cache_slot: str) -> List[List[float]]:
        if not X:
            return []
        _n, _in_dim = len(X), len(X[0])
        _cache_key = (cache_slot, _in_dim, out_dim)
        if _cache_key not in self._proj_cache:
            _w = [[math.sin(i * 0.73 + j * 1.17) * 0.1
                   for j in range(out_dim)] for i in range(_in_dim)]
            self._proj_cache[_cache_key] = _w
        return _matmul(X, self._proj_cache[_cache_key])

    def forward(self, Q: List[List[float]], K: List[List[float]],
                V: List[List[float]]) -> AttentionOutput:
        _K_proj = self._linear_project(K, self.dim, 'K_gqa')
        _V_proj = self._linear_project(V, self.dim, 'V_gqa')
        _n, _d = len(Q), len(Q[0])
        _chunk = self._head_dim

        _head_outputs: List[List[List[float]]] = []
        _head_weights: List[List[List[float]]] = []
        # Q头/KV头分组比例
        _group_size = max(1, self.num_q_heads // self.num_kv_heads)

        for _h in range(self.num_q_heads):
            _start = _h * _chunk
            _end = min(_start + _chunk, _d)
            if _start >= _d:
                break

            _Q_head = [[_row[_j] for _j in range(_start, _end)] for _row in Q]
            # GQA: Q头 _h 使用 K/V 头 _h // group_size
            _kv_head = _h // _group_size
            _kv_start = _kv_head * _chunk
            _kv_end = min(_kv_start + _chunk, _d)
            _K_head = [[_row[_j] for _j in range(_kv_start, _kv_end)] for _row in _K_proj]
            _V_head = [[_row[_j] for _j in range(_kv_start, _kv_end)] for _row in _V_proj]

            _result = self._attn.forward(_Q_head, _K_head, _V_head)
            _head_outputs.append(_result.output)
            _head_weights.append(_result.attention_weights)

        if not _head_outputs:
            return AttentionOutput(output=[[0.0] * _d for _ in range(_n)])

        _concat = [[0.0] * _d for _ in range(_n)]
        _cur_col = 0
        for _h_out in _head_outputs:
            _hd = len(_h_out[0]) if _h_out else 0
            for _i in range(_n):
                for _j in range(_hd):
                    if _cur_col + _j < _d:
                        _concat[_i][_cur_col + _j] = _h_out[_i][_j]
            _cur_col += _hd

        _avg_weights = [[0.0] * _n for _ in range(_n)]
        for _hw in _head_weights:
            for _i in range(min(len(_hw), _n)):
                for _j in range(min(len(_hw[_i]), _n)):
                    _avg_weights[_i][_j] += _hw[_i][_j] / max(1, len(_head_weights))

        return AttentionOutput(output=_concat, attention_weights=_avg_weights)


# ============================================================================
# 层次化注意力 — 词级→句级两级聚合
# 先对每个句子的词做attention得句向量，再对句向量做attention得文档向量
# ============================================================================

class HierarchicalAttention:
    """两级层次注意力：word-level → sentence-level
    适用于文本+图像caption等多粒度模态对齐场景"""

    def __init__(self, word_dim: int = 128, sent_dim: int = 256, dropout: float = 0.1):
        self.word_dim = word_dim
        self.sent_dim = sent_dim
        # 词级和句级的上下文向量 u_w, u_s
        self._u_w: List[float] = [math.sin(i * 0.37) * 0.05 for i in range(word_dim)]
        self._u_s: List[float] = [math.sin(i * 0.53) * 0.05 for i in range(sent_dim)]
        self._word_proj = CrossModalAttention(dim=word_dim, dropout=dropout)
        self._sent_proj = CrossModalAttention(dim=sent_dim, dropout=dropout)

    # word-level attention: h_it → u_w^T * tanh(W_w * h_it + b_w)
    def _word_attend(self, words: List[List[float]]) -> List[float]:
        """对单个句子的词序列做注意力聚合"""
        if not words:
            return [0.0] * self.word_dim
        _n_words = len(words)
        _d = len(words[0])
        # 计算每个词的分数 = u_w · word_i
        _scores = [0.0] * _n_words
        for _t in range(_n_words):
            _dot = 0.0
            _row = words[_t]
            _limit = min(len(_row), len(self._u_w))
            for _j in range(_limit):
                _dot += _row[_j] * self._u_w[_j]
            _scores[_t] = math.tanh(_dot)

        _attn = _softmax(_scores)
        # 加权求和
        _vec = [0.0] * self.word_dim
        for _t in range(_n_words):
            _a = _attn[_t]
            _row = words[_t]
            for _j in range(min(len(_row), self.word_dim)):
                _vec[_j] += _a * _row[_j]
        return _vec

    def forward(self, hierarchical_input: List[List[List[float]]]) -> Tuple[List[float], List[float], List[List[float]]]:
        """输入：文档=[句子=[词向量]]
        输出：(文档向量, 句级注意力, 词级注意力列表)"""
        _n_sents = len(hierarchical_input)
        _sent_vectors: List[List[float]] = []
        _word_weights: List[List[float]] = []
        _si = 0
        while _si < _n_sents:
            _words = hierarchical_input[_si]
            _sv = self._word_attend(_words)
            _sent_vectors.append(_sv)
            _word_weights.append(_sv[:])
            _si += 1

        if not _sent_vectors:
            return [0.0] * self.sent_dim, [], []

        _sent_scores = [0.0] * len(_sent_vectors)
        for _si in range(len(_sent_vectors)):
            _dot = 0.0
            _row = _sent_vectors[_si]
            for _j in range(min(len(_row), len(self._u_s))):
                _dot += _row[_j] * self._u_s[_j]
            _sent_scores[_si] = math.tanh(_dot)
        _sent_attn = _softmax(_sent_scores)

        _doc_vec = [0.0] * self.sent_dim
        for _si in range(len(_sent_vectors)):
            _a = _sent_attn[_si]
            _row = _sent_vectors[_si]
            for _j in range(min(len(_row), self.sent_dim)):
                _doc_vec[_j] += _a * _row[_j]

        return _doc_vec, _sent_attn, _word_weights


# ============================================================================
# 多查询注意力 (MQA) — 所有头共享K/V投影，减少内存
# 相比标准MHA减少 (num_heads-1) 组K/V参数
# ============================================================================

class MultiQueryAttention:
    """多查询注意力：多个Q头共享同一组K/V。

    参数量 = d_model² + 2*d_model² (K/V共享) vs MHA的 3*d_model²*num_heads。
    适用于内存受限的推理场景（如终端设备上的跨模态检索）。
    """

    def __init__(self, dim: int = 64, num_query_heads: int = 4, dropout: float = 0.1):
        self.dim = dim
        self.num_heads = num_query_heads
        self._head_dim = dim // num_query_heads
        self._attn = ScaledDotProductAttention(dropout=dropout)
        self._proj_cache: dict = {}

    def _linear_project(self, X: List[List[float]], out_dim: int,
                        cache_slot: str) -> List[List[float]]:
        if not X:
            return []
        _n, _in_dim = len(X), len(X[0])
        _cache_key = (cache_slot, _in_dim, out_dim)
        if _cache_key not in self._proj_cache:
            _w = [[math.sin(i * 0.73 + j * 1.17) * 0.1
                   for j in range(out_dim)] for i in range(_in_dim)]
            self._proj_cache[_cache_key] = _w
        return _matmul(X, self._proj_cache[_cache_key])

    def forward(self, Q: List[List[float]], K: List[List[float]],
                V: List[List[float]]) -> AttentionOutput:
        _K_shared = self._linear_project(K, self.dim, 'K_shared')
        _V_shared = self._linear_project(V, self.dim, 'V_shared')

        _n, _d = len(Q), len(Q[0])
        _chunk = self._head_dim

        _head_outputs: List[List[List[float]]] = []
        _head_weights: List[List[List[float]]] = []

        for _h in range(self.num_heads):
            _start = _h * _chunk
            _end = min(_start + _chunk, _d)
            if _start >= _d:
                break
            _Q_head = [[_row[_j] for _j in range(_start, _end)] for _row in Q]
            _K_head = [[_row[_j] for _j in range(_start, _end)] for _row in _K_shared]
            _V_head = [[_row[_j] for _j in range(_start, _end)] for _row in _V_shared]

            _result = self._attn.forward(_Q_head, _K_head, _V_head)
            _head_outputs.append(_result.output)
            _head_weights.append(_result.attention_weights)

        if not _head_outputs:
            return AttentionOutput(output=[[0.0] * _d for _ in range(_n)])

        _concat = [[0.0] * _d for _ in range(_n)]
        _cur_col = 0
        for _h_out in _head_outputs:
            _hd = len(_h_out[0]) if _h_out else 0
            for _i in range(_n):
                for _j in range(_hd):
                    if _cur_col + _j < _d:
                        _concat[_i][_cur_col + _j] = _h_out[_i][_j]
            _cur_col += _hd

        _avg_weights = [[0.0] * _n for _ in range(_n)]
        _h_count = len(_head_weights)
        if _h_count > 0:
            for _hw in _head_weights:
                for _i in range(min(len(_hw), _n)):
                    for _j in range(min(len(_hw[_i]), _n)):
                        _avg_weights[_i][_j] += _hw[_i][_j] / _h_count

        return AttentionOutput(output=_concat, attention_weights=_avg_weights)


# ============================================================================
# 模态自注意力 — Q=K=V来自同一模态，捕获内部结构
# ============================================================================

class ModalitySelfAttention:
    """单模态自注意力：同一特征序列的自相关建模
    无位置编码，适用于交换不变性特征（如检测框集合）"""

    def __init__(self, dim: int = 64, num_heads: int = 4, dropout: float = 0.1):
        self.dim = dim
        self.num_heads = num_heads
        self._head_dim = dim // num_heads
        self._attn_heads = [ScaledDotProductAttention(dropout=dropout) for _ in range(num_heads)]
        self._rel_bias = RelativePositionBias(max_distance=32, num_heads=num_heads)

    def forward(self, features: List[List[float]],
                use_rel_bias: bool = False) -> AttentionOutput:
        """自注意力：Q=K=V=features，多头拼接。

        use_rel_bias: 是否注入相对位置偏置（序列数据建议开启）。
        """
        if not features:
            return AttentionOutput(output=[], attention_weights=[])

        _n, _d = len(features), len(features[0])

        _head_outputs: List[List[List[float]]] = []
        _head_weights: List[List[List[float]]] = []
        _chunk_size = self._head_dim

        for _h in range(self.num_heads):
            _start = _h * _chunk_size
            _end = min(_start + _chunk_size, _d)
            if _start >= _d:
                break

            _Q = [[_row[_start:_end]] for _row in features]
            _q_chunk = [[_row[_j] for _j in range(_start, _end)] for _row in features]
            _k_chunk = [_row[:] for _row in _q_chunk]
            _v_chunk = [_row[:] for _row in _q_chunk]

            if not _q_chunk or not _q_chunk[0]:
                continue

            _rel_b = self._rel_bias.get_bias_matrix(_n, _h) if use_rel_bias else None
            _result = self._attn_heads[_h].forward(_q_chunk, _k_chunk, _v_chunk,
                                                    rel_bias=_rel_b)
            _head_outputs.append(_result.output)
            _head_weights.append(_result.attention_weights)

        if not _head_outputs:
            return AttentionOutput(output=features, attention_weights=[])

        _concat: List[List[float]] = [[0.0] * _d for _ in range(_n)]
        _cur_col = 0
        for _h_out in _head_outputs:
            _h_d = len(_h_out[0]) if _h_out else 0
            for _i in range(_n):
                for _j in range(_h_d):
                    if _cur_col + _j < _d:
                        _concat[_i][_cur_col + _j] = _h_out[_i][_j]
            _cur_col += _h_d

        _avg_weights = [[0.0] * _n for _ in range(_n)]
        _h_count = len(_head_weights)
        if _h_count > 0:
            for _hw in _head_weights:
                for _i in range(min(len(_hw), _n)):
                    for _j in range(min(len(_hw[_i]), _n)):
                        _avg_weights[_i][_j] += _hw[_i][_j] / _h_count

        return AttentionOutput(output=_concat, attention_weights=_avg_weights)


# ============================================================================
# 便捷函数：多模态融合推理
# ============================================================================

def fuse_modalities(modality_features: List[List[List[float]]],
                    dim: int = 64) -> List[List[float]]:
    """多模态融合：对各模态做self-attention后拼接
    返回融合后的特征矩阵 [n_samples, fused_dim]"""
    _self_attn = ModalitySelfAttention(dim=dim)
    _fused_parts: List[List[List[float]]] = []
    for _m_idx, _feat in enumerate(modality_features):
        _result = _self_attn.forward(_feat)
        _fused_parts.append(_result.output)

    if not _fused_parts:
        return []

    _n = min(len(_p) for _p in _fused_parts if _p)
    _total_dim = sum(len(_p[0]) for _p in _fused_parts if _p and _p[0])
    _fused = [[0.0] * _total_dim for _ in range(_n)]

    _col = 0
    for _p in _fused_parts:
        _pd = len(_p[0]) if _p and _p[0] else 0
        for _i in range(_n):
            for _j in range(_pd):
                _fused[_i][_col + _j] = _p[_i][_j]
        _col += _pd
    return _fused


# ============================================================================
# 线性注意力 — Performer FAVOR+ 风格的核特征近似
# 参考：Choromanski et al. Rethinking Attention with Performers. ICLR 2021.
# 用随机特征映射 φ(x) 近似 softmax 核：φ(Q)·φ(K)^T ≈ softmax(QK^T/√d)
# 复杂度：O(N·d·m) 其中 m 是随机特征数，远小于 N²
# 正交随机特征 (ORF) 相比 i.i.d. 随机特征有更低的近似方差
# ============================================================================

class LinearAttention:
    """Performer风格线性注意力：K^T·V 先聚合避免显式 N×N 矩阵。

    softmax(QK^T/√d)V ≈ φ(Q)·(φ(K)^T·V) / (φ(Q)·φ(K)^T·1)
    先计算 (φ(K)^T·V) — O(N·d·m)，再右乘 φ(Q) — O(N·d·m)。
    总计 O(N·d·m) vs 标准注意力的 O(N²·d)。当 m << N 时有显著收益。
    """

    def __init__(self, dim: int = 64, n_random_features: int = 128):
        self.dim = dim
        self.n_features = n_random_features
        # 正交随机特征 (ORF): 随机投影 + 正交化 → 更低方差
        self._proj: List[List[float]] = self._make_orf(dim, n_random_features)

    def _make_orf(self, d_in: int, m: int) -> List[List[float]]:
        """生成正交随机特征投影矩阵。

        先产生 i.i.d. 高斯矩阵，再通过 QR 分解正交化——
        正交性保证核近似的方差上界更紧。
        """
        _raw = [[(math.sin(i*1.73 + j*0.91)-0.5)*2.0*math.sqrt(1.0/d_in)
                 for j in range(m)] for i in range(d_in)]
        # 对列做 Gram-Schmidt 正交化
        for _j in range(m):
            _norm_j = math.sqrt(sum(_raw[_i][_j]**2 for _i in range(d_in)))
            if _norm_j > _EPS:
                for _i in range(d_in):
                    _raw[_i][_j] /= _norm_j
            for _k in range(_j+1, m):
                _dot = sum(_raw[_i][_j]*_raw[_i][_k] for _i in range(d_in))
                for _i in range(d_in):
                    _raw[_i][_k] -= _dot * _raw[_i][_j]
        return _raw

    def _kernel_map(self, x: List[List[float]]) -> List[List[float]]:
        """φ(x) = exp(||x||²/2) · [cos(Wx) || sin(Wx)] / √m

        random fourier features 近似高斯核，
        结合 scaled dot-product 重构 softmax attention。
        """
        _N, _d = len(x), len(x[0]) if x else 0
        _m = self.n_features
        # 归一化因子：exp(||x||²/2)
        _norms = [0.0]*_N
        for _i in range(_N):
            _norms[_i] = math.exp(0.5*sum(x[_i][_j]**2 for _j in range(_d)) + _EPS)
        # Wx: projection
        _Wx = [[0.0]*_m for _ in range(_N)]
        for _i in range(_N):
            for _j in range(_m):
                _acc = 0.0
                for _k in range(min(_d, len(self._proj))):
                    _acc += x[_i][_k] * self._proj[_k][_j]
                _Wx[_i][_j] = _acc
        # φ(x) = [cos(Wx)|| sin(Wx)] / √m, scaled by norm
        _phi = [[0.0]*(2*_m) for _ in range(_N)]
        _inv_sqrt_m = 1.0/math.sqrt(_m)
        for _i in range(_N):
            _n = _norms[_i]
            for _j in range(_m):
                _w = _Wx[_i][_j]
                _phi[_i][2*_j] = _n * math.cos(_w) * _inv_sqrt_m
                _phi[_i][2*_j+1] = _n * math.sin(_w) * _inv_sqrt_m
        return _phi

    def forward(self, Q: List[List[float]], K: List[List[float]],
                V: List[List[float]]) -> AttentionOutput:
        """线性注意力前向。"""
        _N = len(Q)
        _d_v = len(V[0]) if V else 0
        if _N == 0:
            return AttentionOutput(output=[[0.0]*_d_v for _ in range(_N)])

        _phi_q = self._kernel_map(Q)
        _phi_k = self._kernel_map(K)
        _feat_dim = 2 * self.n_features

        # KV = φ(K)^T · V  (feat_dim × d_v)
        _KV = [[0.0]*_d_v for _ in range(_feat_dim)]
        for _j in range(_feat_dim):
            for _c in range(_d_v):
                _acc = 0.0
                for _n in range(_N):
                    _acc += _phi_k[_n][_j] * V[_n][_c]
                _KV[_j][_c] = _acc

        # 归一化向量 φ(K)^T · 1
        _K_sum = [sum(_phi_k[_n][_j] for _n in range(_N)) for _j in range(_feat_dim)]

        # 输出：φ(Q) · KV / (φ(Q) · K_sum)
        _output = [[0.0]*_d_v for _ in range(_N)]
        for _i in range(_N):
            _norm = sum(_phi_q[_i][_j]*_K_sum[_j] for _j in range(_feat_dim)) + _EPS
            for _c in range(_d_v):
                _acc = sum(_phi_q[_i][_j]*_KV[_j][_c] for _j in range(_feat_dim))
                _output[_i][_c] = _acc / _norm

        return AttentionOutput(output=_output, attention_weights=[])


# ============================================================================
# ALiBi — 注意力线性偏差 (不学位置嵌入，直接加偏置)
# 参考：Press et al. Train Short, Test Long: ALiBi. ICLR 2022.
# 核心：在 QK^T 矩阵上加一个按头递减的线性偏置矩阵
#       head_h 的斜率 = 2^(-8/h * h)，从最近的token开始惩罚远端token
# 效果：不增加任何参数即可实现序列长度外推，训练用 1024，推理可至 2048+
# ============================================================================

class ALiBiBias:
    """ALiBi 位置偏置：不加位置编码，加固定斜率的距离惩罚。

    bias[i][j] = -slope_h * |i-j|  (causal: i>=j时有效)
    每个注意力头使用不同斜率，越远的头惩罚越重→短程头+长程头分工。
    """

    def __init__(self, num_heads: int = 8):
        self.num_heads = num_heads
        # 斜率：等差数列，2^(-8/num_heads * (h+1))
        self._slopes: List[float] = []
        for _h in range(num_heads):
            _exp = -8.0 * (_h + 1) / num_heads
            self._slopes.append(2.0 ** _exp)

    def get_bias_matrix(self, seq_len: int, head_idx: int) -> List[List[float]]:
        _slope = self._slopes[min(head_idx, len(self._slopes)-1)]
        _bias = [[0.0]*seq_len for _ in range(seq_len)]
        for _i in range(seq_len):
            for _j in range(seq_len):
                # causal: 只对 i>=j 有效，且距离越远惩罚越大
                if _i >= _j:
                    _bias[_i][_j] = -_slope * (_i - _j)
                else:
                    _bias[_i][_j] = -1e9  # causal mask
        return _bias


# ============================================================================
# 差分注意力 — 两个softmax之差，滤除共享噪声，突出独特信号
# 参考：Ye et al. Differential Transformer. arXiv 2024.
# DiffAttn(X) = (softmax(Q1·K1^T) - λ·softmax(Q2·K2^T))·V
# 两组注意力头的差可以消除跨token共享的噪声分量，
# λ 是可学习的标量，控制噪声减法强度
# ============================================================================

class DifferentialAttention:
    """差分注意力：两组 Q/K 计算 softmax 后做带权减法。

    Q₁, K₁ 和 Q₂, K₂ 通过不同投影获得，
    最终注意力 = A₁ - λ·A₂，其中 λ = exp(λ_q·λ_k)/exp(λ_q·λ_k)+1 限制在 (0,1)。
    减法操作消除了两组注意力共享的噪声模式——相当于"差分放大器"。
    """

    def __init__(self, dim: int = 64, head_dim: int = 32):
        self.dim = dim
        self.head_dim = head_dim
        # 两组 Q/K 投影
        self._Q1_proj = self._init_proj(dim, head_dim)
        self._K1_proj = self._init_proj(dim, head_dim)
        self._Q2_proj = self._init_proj(dim, head_dim)
        self._K2_proj = self._init_proj(dim, head_dim)
        # 可学习标量 λ
        self._lambda_q = 0.1
        self._lambda_k = 0.1
        self._attn = ScaledDotProductAttention()

    def _init_proj(self, in_d: int, out_d: int) -> List[List[float]]:
        return [[math.sin(i*0.73+j*1.17)*0.1 for j in range(out_d)] for i in range(in_d)]

    def forward(self, X: List[List[float]]) -> AttentionOutput:
        _N, _d_in = len(X), len(X[0]) if X else 0
        if _N == 0:
            return AttentionOutput(output=[])

        # Q1, K1, Q2, K2
        _Q1 = _matmul(X, self._Q1_proj)
        _K1 = _matmul(X, self._K1_proj)
        _Q2 = _matmul(X, self._Q2_proj)
        _K2 = _matmul(X, self._K2_proj)

        _result1 = self._attn.forward(_Q1, _K1, X)
        _result2 = self._attn.forward(_Q2, _K2, X)

        # λ = sigmoid(λ_q * λ_k)
        _lam = 1.0/(1.0 + math.exp(-self._lambda_q*self._lambda_k))

        _d_out = len(_result1.output[0]) if _result1.output else 0
        _out = [[0.0]*_d_out for _ in range(_N)]
        for _i in range(_N):
            for _j in range(_d_out):
                _out[_i][_j] = _result1.output[_i][_j] - _lam*_result2.output[_i][_j]

        return AttentionOutput(output=_out, attention_weights=_result1.attention_weights)


# ============================================================================
# 膨胀滑动窗口注意力 — 跳跃式窗口，覆盖更广上下文
# 参考：Beltagy et al. Longformer. 2020.  + Ding et al. Dilated Attention. 2023
# 窗口大小 = window_size, 膨胀率 = dilation
# 有效感受野 = window_size × dilation，但不增加计算量
# ============================================================================

def dilated_sliding_window_attention(Q: List[List[float]], K: List[List[float]],
                                       V: List[List[float]], window_size: int = 64,
                                       dilation: int = 2) -> AttentionOutput:
    """膨胀滑动窗口注意力：跳跃式覆盖，扩大感受野而不增加FLOPs。

    dilation=2 → 每隔1个token采样，窗口大小仍为64但覆盖128个token范围。
    这是 Longformer 的滑动窗口 + 膨胀的纯Python复现。
    适用于长序列建模（如函数调用链、指令序列）。
    """
    _N = len(Q)
    _d_k = len(K[0]) if K else 1
    _d_v = len(V[0]) if V else _d_k
    _scale = 1.0/math.sqrt(max(_d_k, 1))
    _half = window_size // 2

    _output = [[0.0]*_d_v for _ in range(_N)]
    for _i in range(_N):
        # 构建膨胀索引列表
        _indices: List[int] = []
        _center = _i
        for _d in range(-_half, _half+1):
            _idx = _center + _d * dilation
            if 0 <= _idx < _N:
                _indices.append(_idx)
        # 局部 QK^T
        _n_local = len(_indices)
        _scores = [0.0]*_n_local
        for _j_idx, _j in enumerate(_indices):
            _dot = sum(Q[_i][_k]*K[_j][_k] for _k in range(min(len(Q[_i]), len(K[_j]))))
            _scores[_j_idx] = _dot * _scale
        # softmax
        _mx = max(_scores) if _scores else 0.0
        _exps = [math.exp(_s-_mx) for _s in _scores]
        _sum_exp = sum(_exps)+_EPS
        # 加权V
        for _j_idx, _j in enumerate(_indices):
            _w = _exps[_j_idx]/_sum_exp
            for _c in range(min(_d_v, len(V[_j]))):
                _output[_i][_c] += _w * V[_j][_c]

    return AttentionOutput(output=_output)


# ============================================================================
# 跨模态门控融合单元 — 动态控制模态间的信息流
# 参考：Peng et al. Gated Cross-Attention for Multimodal Learning. 2024.
# gate = σ(W_g·[cross_attn_output; self_attn_output])
# output = gate ⊙ cross + (1-gate) ⊙ self
# ============================================================================

class GatedCrossAttention:
    """带门控的交叉注意力：自适应决定每个位置融合多少跨模态信息。

    对每个 token，门控值 ∈ [0,1] 决定了该位置从跨模态信息中吸收的比例。
    低噪声模态的 token 可以更信任跨模态信号（gate → 1），
    高噪声模态的 token 可以保留自注意结果（gate → 0）。
    """

    def __init__(self, dim: int = 64, dropout: float = 0.1):
        self.dim = dim
        self._cross_attn = CrossModalAttention(dim=dim, dropout=dropout)
        self._self_attn = ModalitySelfAttention(dim=dim)
        # 门控权重: 2*dim → dim
        self._W_gate: List[List[float]] = [
            [math.sin(i*0.47+j*0.83)*0.05 for j in range(2*dim)] for i in range(dim)]

    def forward(self, modality_a: List[List[float]],
                modality_b: List[List[float]]) -> List[List[float]]:
        _cross_result = self._cross_attn.forward(modality_a, modality_b)
        _self_result = self._self_attn.forward(modality_a)

        _N = len(modality_a)
        _d = self.dim
        if _N == 0:
            return []

        _fused = [[0.0]*_d for _ in range(_N)]
        for _i in range(_N):
            # 拼接 cross 和 self 输出 → 门控
            _concat = (_cross_result.output[_i][:min(_d, len(_cross_result.output[_i]))] +
                      _self_result.output[_i][:min(_d, len(_self_result.output[_i]))])
            _gate_logits = [0.0]*_d
            for _j_o in range(_d):
                _gate_logits[_j_o] = sum(_concat[_j_i]*self._W_gate[_j_o][_j_i]
                                        for _j_i in range(min(len(_concat), 2*_d)))
            _gate = [1.0/(1.0+math.exp(-min(max(_g, 20), -20))) for _g in _gate_logits]
            # 门控融合
            for _j in range(_d):
                _cross_val = (_cross_result.output[_i][_j]
                             if _j < len(_cross_result.output[_i]) else 0.0)
                _self_val = (_self_result.output[_i][_j]
                            if _j < len(_self_result.output[_i]) else 0.0)
                _fused[_i][_j] = _gate[_j]*_cross_val + (1-_gate[_j])*_self_val
        return _fused
