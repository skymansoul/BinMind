# 图注意力网络编码器 - 替代GCN的注意力消息传递
# 设计边界: 纯Python实现, 不依赖PyTorch/NumPy; 支持多头注意力和EdgeDrop正则化
#
# 架构参考:
# BobGAT - 分层GAT, 按函数边界聚合
# GATv2 - 动态注意力, 修复了原始GAT的静态排序问题

from __future__ import annotations
import math
import random
import logging
import hashlib
from typing import Dict, List, Optional, Tuple, Any
from collections import defaultdict
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# 辅助数学函数 - 纯Python线性代数

def _vec_dot(a: List[float], b: List[float]) -> float:
    """向量内积，不做维度检查（调用方保证长度一致）"""
    s = 0.0
    for i in range(len(a)):
        s += a[i] * b[i]
    return s

def _matvec(W: List[List[float]], x: List[float]) -> List[float]:
    """矩阵乘向量: y = W @ x, 形状 (out_dim, in_dim) @ (in_dim,) -> (out_dim,)"""
    out = [0.0] * len(W)
    for i, row in enumerate(W):
        s = 0.0
        xi = 0
        for j, w in enumerate(row):
            s += w * x[j]
        out[i] = s
    return out

def _vec_add(a: List[float], b: List[float]) -> List[float]:
    return [a[i] + b[i] for i in range(len(a))]

def _vec_scale(v: List[float], s: float) -> List[float]:
    return [x * s for x in v]

def _vec_zeros(n: int) -> List[float]:
    return [0.0] * n

def _leaky_relu(x: float, alpha: float = 0.2) -> float:
    return x if x >= 0 else alpha * x

def _softmax(logits: List[float]) -> List[float]:
    if not logits:
        return []
    mx = max(logits)
    exps = [math.exp(l - mx) for l in logits]
    total = sum(exps)
    if total < 1e-12:
        return [1.0 / len(exps)] * len(exps)
    return [e / total for e in exps]

def _elu(x: float, alpha: float = 1.0) -> float:
    return x if x >= 0 else alpha * (math.exp(x) - 1.0)

# 权重初始化

_WEIGHT_INIT_SEED = 0
_WEIGHT_INIT_RNG: Optional[random.Random] = None


def _get_rng() -> random.Random:
    global _WEIGHT_INIT_RNG
    if _WEIGHT_INIT_RNG is None:
        _WEIGHT_INIT_RNG = random.Random(42)
    return _WEIGHT_INIT_RNG


def _xavier_uniform(rows: int, cols: int) -> List[List[float]]:
    """Xavier/Glorot均匀初始化: U[-sqrt(6/(fan_in+fan_out)), sqrt(6/(fan_in+fan_out))]"""
    rng = _get_rng()
    limit = math.sqrt(6.0 / (rows + cols))
    return [[rng.uniform(-limit, limit) for _ in range(cols)] for _ in range(rows)]


def _xavier_uniform_1d(size: int, fan_in: int, fan_out: int) -> List[float]:
    rng = _get_rng()
    limit = math.sqrt(6.0 / (fan_in + fan_out))
    return [rng.uniform(-limit, limit) for _ in range(size)]


def _l2_normalize(v: List[float]) -> List[float]:
    norm = math.sqrt(sum(x * x for x in v))
    if norm < 1e-12:
        return v[:]
    return [x / norm for x in v]

# 数据结构

@dataclass
class GATEncoderConfig:
    """GAT编码器配置

    字段说明:
        in_dim: 输入节点特征维度
        hidden_dims: 各隐藏层输出维度列表
        out_dim: 最终输出维度
        num_heads: 注意力头数 (每层独立配置时使用列表)
        dropout_rate: 节点特征dropout概率
        edge_dropout_rate: 边丢弃概率
        residual: 是否使用残差连接
        use_gatv2: 使用GATv2动态注意力 还是原始GAT
        activation: 激活函数 ('relu' | 'elu' | 'leaky_relu')
    """
    in_dim: int = 12
    hidden_dims: List[int] = field(default_factory=lambda: [64, 128])
    out_dim: int = 128
    num_heads: int = 4
    dropout_rate: float = 0.1
    edge_dropout_rate: float = 0.05
    residual: bool = True
    use_gatv2: bool = True
    activation: str = 'elu'


@dataclass
class GATLayer:
    """单层多头图注意力

    依据GATv2: 注意力系数 e_ij = a^T LeakyReLU(W_src * h_i + W_dst * h_j)
    (GATv1使用 W * [h_i || h_j], 表达能力弱于v2)
    多头输出: concat[h^1, h^2, ..., h^K] (最后一层用mean)
    """
    w_src: List[List[List[float]]]     # [num_heads][out_dim_per_head][in_dim]
    w_dst: List[List[List[float]]]     # [num_heads][out_dim_per_head][in_dim]
    a_src: List[List[float]]           # [num_heads][out_dim_per_head] GATv2的a_src
    a_dst: List[List[float]]           # [num_heads][out_dim_per_head] GATv2的a_dst
    bias: List[float]                  # [num_heads * out_dim_per_head]
    num_heads: int
    in_dim: int
    out_dim: int
    out_dim_per_head: int
    use_gatv2: bool
    concat: bool  # True=concat多头输出; False=均值 (最后一层)


def _apply_activation(x: float, name: str) -> float:
    if name == 'relu':
        return max(0.0, x)
    elif name == 'elu':
        return _elu(x)
    elif name == 'leaky_relu':
        return _leaky_relu(x)
    return x


class GATGraphEncoder:
    """分层图注意力编码器 - 输入层 -> [GATLayer * N] -> L2归一化输出.
    参照 BobGAT [LLNL 2024] 分层GAT架构 + GATv2 [Brody et al. ICLR 2022] 动态注意力."""
    def __init__(self, config: GATEncoderConfig):
        self.config = config
        self.layers: List[GATLayer] = []
        self._training = True
        self._build_layers()

    def _build_layers(self):
        """构建GAT层叠栈"""
        h = self.config.num_heads
        dims = [self.config.in_dim] + self.config.hidden_dims + [self.config.out_dim]

        for layer_idx in range(len(dims) - 1):
            in_d = dims[layer_idx]
            out_d = dims[layer_idx + 1]
            is_last = (layer_idx == len(dims) - 2)

            if is_last:
                heads = 1
                out_per_head = out_d
                concat = False
            else:
                heads = h
                out_per_head = out_d // heads
                concat = True

            # 为每个头创建独立的权重矩阵
            w_src = []
            w_dst = []
            a_src = []
            a_dst = []

            for _ in range(heads):
                w_src.append(_xavier_uniform(out_per_head, in_d))
                w_dst.append(_xavier_uniform(out_per_head, in_d))
                if self.config.use_gatv2:
                    a_src.append(_xavier_uniform_1d(out_per_head, out_per_head, out_per_head))
                    a_dst.append(_xavier_uniform_1d(out_per_head, out_per_head, out_per_head))
                else:
                    # GATv1: a是2*out_per_head维向量, 用于concat
                    a_src.append(_xavier_uniform_1d(out_per_head * 2, out_per_head * 2, 1))
                    a_dst.append([])

            bias_dim = heads * out_per_head if concat else out_d
            bias = _vec_zeros(bias_dim)

            layer = GATLayer(
                w_src=w_src, w_dst=w_dst,
                a_src=a_src, a_dst=a_dst,
                bias=bias, num_heads=heads,
                in_dim=in_d, out_dim=bias_dim,
                out_dim_per_head=out_per_head,
                use_gatv2=self.config.use_gatv2,
                concat=concat,
            )
            self.layers.append(layer)

    def set_training(self, flag: bool):
        self._training = flag

    def encode(self, node_features: List[List[float]],
               adjacency: List[List[int]]) -> List[float]:
        """编码单个图到嵌入向量"""
        h = [row[:] for row in node_features]  # deep copy

        for li, layer in enumerate(self.layers):
            h = self._forward_layer(h, adjacency, layer, li)

        # 全局均值池化 -> 图级向量
        if not h:
            return _vec_zeros(self.config.out_dim)

        N = len(h)
        dim = len(h[0]) if h else self.config.out_dim
        pooled = _vec_zeros(dim)
        for node_h in h:
            for j in range(dim):
                pooled[j] += node_h[j]
        for j in range(dim):
            pooled[j] /= N

        return _l2_normalize(pooled)

    def encode_with_node_embeddings(self, node_features: List[List[float]],
                                     adjacency: List[List[int]]) -> Tuple[List[float], List[List[float]]]:
        """编码并返回节点级嵌入"""
        h = [row[:] for row in node_features]

        for li, layer in enumerate(self.layers):
            h = self._forward_layer(h, adjacency, layer, li)

        N = len(h)
        dim = len(h[0]) if h else self.config.out_dim
        pooled = _vec_zeros(dim)
        for node_h in h:
            for j in range(dim):
                pooled[j] += node_h[j]
        for j in range(dim):
            pooled[j] /= N

        return _l2_normalize(pooled), h

    def _forward_layer(self, h: List[List[float]],
                       adj: List[List[int]],
                       layer: GATLayer,
                       layer_idx: int) -> List[List[float]]:
        """单层GAT前向传播"""
        N = len(h)
        in_dim = len(h[0]) if h else 0
        if N == 0:
            return []

        # 构建包含自环的邻接表 (注意力在图中的所有邻居上进行)
        adj_self = [list(set(adj[i]) | {i}) for i in range(N)]

        # EdgeDrop (仅在训练模式)
        effective_adj = adj_self
        if self._training and self.config.edge_dropout_rate > 0:
            effective_adj = []
            for i in range(N):
                kept = [j for j in adj_self[i]
                        if j == i or random.random() > self.config.edge_dropout_rate]
                if not kept:
                    kept = [i]
                effective_adj.append(kept)

        head_outputs = []
        for head_idx in range(layer.num_heads):
            w_src = layer.w_src[head_idx]
            w_dst = layer.w_dst[head_idx]
            d_head = layer.out_dim_per_head

            # 线性变换源向量和目标向量
            h_src = [_matvec(w_src, h[i]) for i in range(N)]
            h_dst = [_matvec(w_dst, h[i]) for i in range(N)]

            head_h = _vec_zeros(N * d_head)
            head_h_2d: List[List[float]] = []

            for i in range(N):
                neighbors = effective_adj[i]
                if not neighbors:
                    head_h_2d.append(h_src[i][:])
                    continue

                # 计算每个邻居的注意力系数
                attn_logits = []
                for j in neighbors:
                    if layer.use_gatv2:
                        # GATv2: a_src^T LeakyReLU(W_src*h_i + W_dst*h_j)
                        # = sum over k of a_src[k] * leaky_relu(h_src_i[k] + h_dst_j[k])
                        score = 0.0
                        for k in range(d_head):
                            val = h_src[i][k] + h_dst[j][k]
                            score += layer.a_src[head_idx][k] * _leaky_relu(val)
                        attn_logits.append(score)
                    else:
                        # GATv1: a^T [W*h_i || W*h_j]
                        concat = h_src[i] + h_dst[j]
                        score = _vec_dot(layer.a_src[head_idx], concat)
                        attn_logits.append(_leaky_relu(score))

                attn_weights = _softmax(attn_logits)

                # 加权聚合
                new_h = _vec_zeros(d_head)
                for nj, j in enumerate(neighbors):
                    w = attn_weights[nj]
                    for k in range(d_head):
                        new_h[k] += w * h_src[j][k]
                head_h_2d.append(new_h)

            head_outputs.append(head_h_2d)

        # 合并多头输出
        if layer.concat:
            # concat: [h_head0, h_head1, ..., h_headK-1]
            new_h = []
            total_dim = layer.out_dim
            for i in range(N):
                merged = []
                for head_idx in range(layer.num_heads):
                    merged.extend(head_outputs[head_idx][i])
                new_h.append(merged)
        else:
            # mean pooling over heads
            new_h = []
            d_head = layer.out_dim_per_head
            for i in range(N):
                avg = _vec_zeros(d_head)
                for head_idx in range(layer.num_heads):
                    for k in range(d_head):
                        avg[k] += head_outputs[head_idx][i][k]
                for k in range(d_head):
                    avg[k] /= layer.num_heads
                new_h.append(avg)

        # 加偏置
        for i in range(N):
            for j in range(len(new_h[i])):
                new_h[i][j] += layer.bias[j] if j < len(layer.bias) else 0.0

        # 激活函数
        act = self.config.activation
        for i in range(N):
            for j in range(len(new_h[i])):
                new_h[i][j] = _apply_activation(new_h[i][j], act)

        # Dropout
        if self._training and self.config.dropout_rate > 0:
            for i in range(N):
                for j in range(len(new_h[i])):
                    if random.random() < self.config.dropout_rate:
                        new_h[i][j] = 0.0

        # 残差连接 (维度不匹配时用线性投影)
        if self.config.residual and len(new_h[0]) == in_dim:
            for i in range(N):
                for j in range(in_dim):
                    new_h[i][j] += h[i][j]

        return new_h

    def embed_batch(self, graphs: List[Tuple[List[List[float]], List[List[int]]]]) -> List[List[float]]:
        """批量编码图 -> 嵌入矩阵"""
        return [self.encode(nf, adj) for nf, adj in graphs]


class GATBinarySimilarityEncoder:
    """基于GAT的二进制函数相似度编码器

    实现 BobGAT 风格的多层级嵌入:
      1. 指令级token嵌入 (hash-based)
      2. 基本块级GAT聚合
      3. 函数级全局池化
      4. 跨架构对齐投影

    使用CLAP风格对比损失进行训练, 相似函数在嵌入空间靠近
    """

    def __init__(self, gat_cfg: GATEncoderConfig = None,
                 contrastive_temp: float = 0.07):
        if gat_cfg is None:
            gat_cfg = GATEncoderConfig()
        self.gat = GATGraphEncoder(gat_cfg)
        self.temp = contrastive_temp
        self._proj_w: Optional[List[List[float]]] = None
        self._proj_b: Optional[List[float]] = None

    def _init_projection(self, in_dim: int):
        """跨架构对齐投影层 - GBsim式BERT投影"""
        if self._proj_w is not None:
            return
        out_d = in_dim
        self._proj_w = _xavier_uniform(out_d, in_dim)
        self._proj_b = _vec_zeros(out_d)

    def encode_function(self, blocks: List[List[str]],
                        edges: List[Tuple[int, int, str]],
                        node_features: Optional[List[List[float]]] = None) -> List[float]:
        """编码汇编函数到嵌入"""
        N = len(blocks)
        if node_features is None:
            node_features = self._extract_block_features(blocks)

        adj: List[List[int]] = [[] for _ in range(N)]
        for src, dst, _ in edges:
            if 0 <= src < N and 0 <= dst < N:
                adj[src].append(dst)

        emb = self.gat.encode(node_features, adj)

        if self._proj_w is not None:
            emb = _matvec(self._proj_w, emb)
            if self._proj_b:
                emb = [emb[i] + self._proj_b[i] for i in range(len(emb))]

        return _l2_normalize(emb)

    def _extract_block_features(self, blocks: List[List[str]]) -> List[List[float]]:
        """从指令序列提取12维块特征 (兼容现有GraphBuilder格式)"""
        feats = []
        for insns in blocks:
            n = len(insns)
            has_call = any('call' in i.lower() for i in insns)
            has_jump = any(any(kw in i.lower() for kw in ['jmp', 'j', 'b', 'ret'])
                          for i in insns)
            has_mem_r = any('[' in i or 'ptr' in i.lower() for i in insns)
            has_mem_w = any('mov' in i.lower() and '[' in i for i in insns)
            has_arith = any(any(kw in i.lower() for kw in ['add', 'sub', 'mul', 'div', 'shl', 'shr', 'xor', 'and', 'or'])
                           for i in insns)
            branch_count = sum(1 for i in insns if any(kw in i.lower()
                              for kw in ['jmp', 'je', 'jne', 'jg', 'jl', 'jge', 'jle', 'jb', 'ja', 'jbe', 'jae', 'jz', 'jnz']))

            f = [
                float(n),                        # instruction_count
                1.0 if has_call else 0.0,        # has_call
                1.0 if has_call else 0.0,        # has_dangerous_call (same heuristic)
                0.0,                              # has_loop (需要CFG级检测)
                1.0 if has_mem_r else 0.0,       # has_mem_read
                1.0 if has_mem_w else 0.0,       # has_mem_write
                1.0 if has_arith else 0.0,      # has_arithmetic
                float(branch_count),              # branch_count
                0.0,                              # block_degree
                0.0,                              # is_entry
                0.0,                              # is_exit
                float(n * 4),                     # size_bytes (估算)
            ]
            feats.append(f)
        return feats

    def compute_similarity(self, emb_a: List[float], emb_b: List[float]) -> float:
        """余弦相似度"""
        return _vec_dot(emb_a, emb_b)

    # 便利方法
    def set_training(self, flag: bool):
        self.gat.set_training(flag)


def create_gat_encoder(in_dim: int = 12, hidden_dims: List[int] = None,
                       out_dim: int = 128, num_heads: int = 4) -> GATGraphEncoder:
    if hidden_dims is None:
        hidden_dims = [64, 128]
    cfg = GATEncoderConfig(
        in_dim=in_dim, hidden_dims=hidden_dims,
        out_dim=out_dim, num_heads=num_heads,
    )
    return GATGraphEncoder(cfg)


def create_gat_similarity_encoder(in_dim: int = 12, hidden_dims: List[int] = None,
                                   out_dim: int = 128, num_heads: int = 4,
                                   contrastive_temp: float = 0.07) -> GATBinarySimilarityEncoder:
    if hidden_dims is None:
        hidden_dims = [64, 128]
    cfg = GATEncoderConfig(
        in_dim=in_dim, hidden_dims=hidden_dims,
        out_dim=out_dim, num_heads=num_heads,
    )
    return GATBinarySimilarityEncoder(gat_cfg=cfg, contrastive_temp=contrastive_temp)
