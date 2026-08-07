# MixHop图卷积 — 混合多跳邻域聚合
# MixHop 的高阶邻域混合
# DESCG 使用MixHop进行二进制数据编码方案分类
# 核心: 对k=1,2,...跳邻域分别卷积后拼接, 捕获多尺度图拓扑

from __future__ import annotations
import math
import random
import logging
from typing import Dict, List, Optional, Tuple
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 纯Python矩阵运算 (参见 gat_graph_encoder.py 中的同名函数)

def _mx_vec_dot(a: List[float], b: List[float]) -> float:
    s = 0.0
    for i in range(len(a)):
        s += a[i] * b[i]
    return s

def _mx_matvec(W: List[List[float]], x: List[float]) -> List[float]:
    return [sum(row[j] * x[j] for j in range(len(x))) for row in W]

def _mx_zeros(n: int) -> List[float]:
    return [0.0] * n

def _mx_l2_norm(v: List[float]) -> List[float]:
    n = math.sqrt(sum(x * x for x in v))
    if n < 1e-12:
        return v[:]
    return [x / n for x in v]

def _mx_xavier(rows: int, cols: int) -> List[List[float]]:
    rng = random.Random(hash(f"mixhop_{rows}_{cols}") & 0x7FFFFFFF)
    lim = math.sqrt(6.0 / (rows + cols))
    return [[rng.uniform(-lim, lim) for _ in range(cols)] for _ in range(rows)]

def _mx_relu(x: float) -> float:
    return x if x >= 0.0 else 0.0

def _mx_elu(x: float) -> float:
    return x if x >= 0.0 else math.exp(x) - 1.0


# 配置

@dataclass
class MixHopConfig:
    in_dim: int = 12
    hidden_dim: int = 64
    out_dim: int = 128
    hop_powers: List[int] = field(default_factory=lambda: [0, 1, 2])
    layer_dims: List[int] = field(default_factory=lambda: [64, 128])
    activation: str = 'relu'
    dropout_rate: float = 0.1
    use_layer_norm: bool = True


# MixHop层实现

class MixHopLayer:
    """单层MixHop: 对多个邻接矩阵幂进行独立卷积后拼接

    对于k跳邻接, 使用 A^k 对特征进行变换 (A为归一化邻接矩阵)
    A^0 = I: 自特征
    A^1: 直接邻居聚合
    A^2: 二跳邻居
    等等

    输出: concat[A^0 H W_0, A^1 H W_1, ..., A^K H W_K]
    维度: |V| x (K+1)*hidden_dim
    """

    def __init__(self, in_dim: int, hidden_dim: int, hop_powers: List[int],
                 activation: str = 'relu'):
        self.in_dim = in_dim
        self.hidden_dim = hidden_dim
        self.hop_powers = hop_powers
        self.activation_name = activation
        self.num_hops = len(hop_powers)

        # 每跳独立权重矩阵
        self.weights = [_mx_xavier(in_dim, hidden_dim) for _ in range(self.num_hops)]
        self.biases = [_mx_zeros(hidden_dim) for _ in range(self.num_hops)]

        # LayerNorm参数
        self.out_dim = self.num_hops * hidden_dim
        self.ln_gamma = [1.0] * self.out_dim
        self.ln_beta = [0.0] * self.out_dim

    def forward(self, features: List[List[float]],
                adj: List[List[int]]) -> List[List[float]]:
        """前向传播 — 对归一化邻接矩阵的每个幂次独立变换后拼接"""
        N = len(features)
        if N == 0:
            return []

        # 预计算邻接矩阵的各次幂 (稀疏格式: adj_pow[k][i] = 列表的k跳邻居索引)
        adj_pows = self._compute_adj_powers(adj, N)

        hop_outputs = []
        for hop_idx, k in enumerate(self.hop_powers):
            W = self.weights[hop_idx]
            b = self.biases[hop_idx]

            if k == 0:
                # A^0 = I: 直接对自身特征进行线性变换
                hop_h = []
                for i in range(N):
                    h_i = _mx_matvec(W, features[i])
                    h_i = [h_i[j] + b[j] for j in range(self.hidden_dim)]
                    hop_h.append(h_i)
            else:
                # A^k: 从k跳邻居聚合特征后再线性变换
                hop_h = []
                k_hop_adj = adj_pows[min(k, len(adj_pows) - 1)]

                for i in range(N):
                    neighbors = k_hop_adj[i]
                    if not neighbors:
                        aggregated = features[i][:]
                    else:
                        aggregated = _mx_zeros(len(features[i]))
                        deg = len(neighbors)
                        for j in neighbors:
                            for d in range(len(aggregated)):
                                aggregated[d] += features[j][d]
                        for d in range(len(aggregated)):
                            aggregated[d] /= max(deg, 1)

                    h_i = _mx_matvec(W, aggregated)
                    h_i = [h_i[j] + b[j] for j in range(self.hidden_dim)]
                    hop_h.append(h_i)

            hop_outputs.append(hop_h)

        # 拼接所有跳的输出
        out_features = []
        for i in range(N):
            merged = []
            for hop_idx in range(self.num_hops):
                merged.extend(hop_outputs[hop_idx][i])
            # LayerNorm
            if True:  # use_layer_norm
                merged = self._layer_norm(merged)
            # 激活
            for j in range(len(merged)):
                merged[j] = _mx_relu(merged[j]) if self.activation_name == 'relu' else _mx_elu(merged[j])
            out_features.append(merged)

        return out_features

    def _compute_adj_powers(self, adj: List[List[int]], N: int) -> List[List[List[int]]]:
        """计算邻接矩阵的1..K次幂 (稀疏BFS实现)

        返回: list of [N][List[neighbor_idx]]
        adj_pows[0] = 1-hop = 原始邻接
        adj_pows[1] = 2-hop = 邻居的邻居 (去重)
        ...
        """
        max_k = max(self.hop_powers)
        if max_k <= 0:
            return []

        pows = [adj]  # k=1
        for k in range(1, max_k):
            prev = pows[-1]
            kp1 = [[] for _ in range(N)]
            for i in range(N):
                seen = set(adj[i]) | {i}
                for j in prev[i]:
                    for nxt in adj[j]:
                        if nxt not in seen:
                            seen.add(nxt)
                            kp1[i].append(nxt)
            pows.append(kp1)

        return pows

    def _layer_norm(self, x: List[float]) -> List[float]:
        d = len(x)
        if d == 0:
            return x
        mu = sum(x) / d
        var = sum((v - mu) ** 2 for v in x) / d
        eps = 1e-5
        std = math.sqrt(var + eps)
        return [self.ln_gamma[j] * (x[j] - mu) / std + self.ln_beta[j]
                for j in range(d)]


# 完整MixHop GNN

class MixHopGNN:
    """多层MixHop图神经网络

    堆叠多个MixHopLayer, 每层捕获不同尺度的邻域信息。
    DESCG [Automated SE 2025] 表明 MixHop 相比标准GCN在二进制数据编码分类上
    有更好的跨编译器、跨优化等级鲁棒性 (原因: 多跳邻域弥合了编译器优化引入的图结构差异)
    """

    def __init__(self, config: MixHopConfig = None):
        if config is None:
            config = MixHopConfig()
        self.cfg = config
        self.layers: List[MixHopLayer] = []
        self._training = True
        self._build()

    def _build(self):
        dims = [self.cfg.in_dim] + self.cfg.layer_dims
        for li in range(len(dims) - 1):
            if li == 0:
                # 第一层: 使用hop_powers进行多跳混合
                layer = MixHopLayer(
                    in_dim=dims[li],
                    hidden_dim=dims[li + 1] // len(self.cfg.hop_powers),
                    hop_powers=self.cfg.hop_powers,
                    activation=self.cfg.activation,
                )
            else:
                # 后续层: 单跳 (hop_powers=[1]) 因为输入已经是混合特征
                layer = MixHopLayer(
                    in_dim=dims[li],
                    hidden_dim=dims[li + 1],
                    hop_powers=[1],
                    activation=self.cfg.activation,
                )
            self.layers.append(layer)

    def set_training(self, flag: bool):
        self._training = flag

    def encode(self, node_features: List[List[float]],
               adjacency: List[List[int]]) -> List[float]:
        """编码单图 -> 图级嵌入"""
        h = [row[:] for row in node_features]
        for layer in self.layers:
            h = layer.forward(h, adjacency)

        if not h:
            return _mx_zeros(self.cfg.out_dim)

        N = len(h)
        dim = len(h[0])
        pooled = _mx_zeros(dim)
        for node_h in h:
            for j in range(dim):
                pooled[j] += node_h[j]
        for j in range(dim):
            pooled[j] /= N

        return _mx_l2_norm(pooled)

    def encode_with_node_level(self, node_features: List[List[float]],
                                adj: List[List[int]]) -> Tuple[List[float], List[List[float]]]:
        h = [row[:] for row in node_features]
        for layer in self.layers:
            h = layer.forward(h, adj)

        if not h:
            return _mx_zeros(self.cfg.out_dim), []

        N = len(h)
        dim = len(h[0])
        pooled = _mx_zeros(dim)
        for nh in h:
            for j in range(dim):
                pooled[j] += nh[j]
        for j in range(dim):
            pooled[j] /= N

        return _mx_l2_norm(pooled), h

    def embed_batch(self, graphs: List[Tuple[List[List[float]], List[List[int]]]]) -> List[List[float]]:
        return [self.encode(nf, adj) for nf, adj in graphs]


# DESCG风格的数据编码方案分类器

class DESCGEncodingClassifier:
    """基于MixHop的二进制数据编码方案分类

    目标: 识别二进制中的加密/压缩/解压/哈希算法
    DESCG原文使用动态trace构建数据依赖图, 本实现使用静态特征近似

    分类4类:
      0: encryption (AES, DES, RC4, ...)
      1: compression (zlib, LZMA, ...)
      2: decompression
      3: hashing (MD5, SHA1, SHA256, ...)

    依据: DESCG [Automated SE 2025] Table 3 — MixHop达到97.7%准确率
    """

    N_CLASSES = 4
    CLASS_NAMES = ['encryption', 'compression', 'decompression', 'hashing']

    def __init__(self, mixhop_cfg: MixHopConfig = None):
        if mixhop_cfg is None:
            mixhop_cfg = MixHopConfig(in_dim=12, hidden_dim=64, out_dim=64,
                                       hop_powers=[0, 1, 2], layer_dims=[64, 64])
        self.mixhop = MixHopGNN(mixhop_cfg)
        self.classifier_w: List[List[float]] = _mx_xavier(64, self.N_CLASSES)
        self.classifier_b: List[float] = _mx_zeros(self.N_CLASSES)
        self._feature_cache: Dict[str, Tuple[List[List[float]], List[List[int]]]] = {}

    def classify(self, node_features: List[List[float]],
                 adjacency: List[List[int]]) -> Dict[str, float]:
        """对单个函数图进行分类"""
        emb = self.mixhop.encode(node_features, adjacency)
        logits = _mx_matvec(self.classifier_w, emb)
        logits = [logits[i] + self.classifier_b[i] for i in range(len(logits))]

        # softmax
        mx = max(logits)
        exps = [math.exp(l - mx) for l in logits]
        total = sum(exps)
        probs = [e / total for e in exps]

        return {self.CLASS_NAMES[i]: probs[i] for i in range(self.N_CLASSES)}

    def predict(self, node_features: List[List[float]],
                adjacency: List[List[int]]) -> Tuple[str, float]:
        probs = self.classify(node_features, adjacency)
        best = max(probs, key=lambda k: probs[k])
        return best, probs[best]


def create_mixhop_encoder(in_dim: int = 12, hop_powers: List[int] = None,
                           out_dim: int = 128) -> MixHopGNN:
    if hop_powers is None:
        hop_powers = [0, 1, 2]
    cfg = MixHopConfig(in_dim=in_dim, out_dim=out_dim, hop_powers=hop_powers)
    return MixHopGNN(cfg)


def create_descg_classifier() -> DESCGEncodingClassifier:
    return DESCGEncodingClassifier()


def _debug_print(*args, **kwargs):  # 调试残余--未删除
    """Print debug info if env var is set. Not currently called."""
    if __import__("os").environ.get("BINMIND_DEBUG"):
        print(*args, **kwargs)
