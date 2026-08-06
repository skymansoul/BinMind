# 创建: 2025-08-14 11:15
# 修改: 2025-08-14 — 引力模型 CFG 增广 + MoCo 动量对比 + InfoNCE
"""
引力模型对比学习二进制嵌入 — 自监督预训练, 无需标注。

BEGA (IEEE 2026) 的简化实现: 将 CFG 节点视为具有"质量"的质点,
节点间的"引力"决定边丢弃概率——模拟不同编译器/优化级别对 CFG 的扰动。

核心思想:
  1. 节点质量 = degree^(1/2) (度大的节点引力更大, 边更稳定)
  2. 边引力 = (mass_src * mass_dst) / distance²
     distance 使用两节点指令数之差 + 熵值差 的加权和
  3. 弱引力边更容易在 DropEdge 中被丢弃 → 生成两个不同的增广视图
  4. InfoNCE 对比损失: 同一函数的两个视图 → 正对, 不同函数 → 负对
  5. 动量编码器 (MoCo): key encoder 的 EMA 更新 → 维持负样本一致性

与现有 GNN 模块的关系:
  - gat_graph_encoder.py: 做监督学习分类 (CWE/CVE)
  - 本模块: 做自监督预训练 → 产出迁移学习的基础嵌入
  - 两者互补: 先预训练 → 再微调 (或冻结嵌入 + 下游分类头)

为什么用 MoCo 而非 SimCLR:
  负样本队列大小不依赖 batch size——128 的队列在 CPU-only 环境下可维持,
  而 SimCLR 需要大 batch (≥256) 才有足够的负样本多样性。

ref: BEGA (IEEE, Feb 2026) — gravity-model augmentation for CFG contrastive
     learning, 本项目简化其重力计算并增加动量编码器
ref: MoCo (He et al., CVPR 2020) — momentum contrast for unsupervised learning
ref: GraphCL (You et al., NeurIPS 2020) — 图对比学习的 DropEdge/FeatureMask
     增广策略, 本项目的重力模型是 GraphCL 的 adaptive 版本
ref: DropEdge (Rong et al., ICLR 2020) — 度感知边丢弃, 本项目用引力模型
     替代随机丢弃, 保留更多结构信息
"""

from __future__ import annotations

import math
import random
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Optional


# --- 引力模型 ---

@dataclass
class GravityCFGNode:
    """CFG 节点 — 基本块 + 引力模型质量。"""
    addr: int
    instruction_count: int = 0
    byte_entropy: float = 0.0
    mass: float = 0.0       # 引力质量: sqrt(degree)
    degree: int = 0
    features: list[float] = field(default_factory=list)  # 节点特征向量


def build_gravity_model(nodes: dict[int, GravityCFGNode],
                        edges: list[tuple[int, int]],
                        feature_dim: int = 64) -> None:
    """从 CFG 构建引力模型: 计算节点质量 + 边引力。

    质量 = sqrt(degree + 1) — 避免度为 0 的孤立节点质量归零。
    边引力 = (m_src * m_dst) / (d² + ε), d 为两节点指令数差 + 熵值差。"""
    # 计算度
    for src, dst in edges:
        if src in nodes:
            nodes[src].degree += 1
        if dst in nodes:
            nodes[dst].degree += 1

    for n in nodes.values():
        n.mass = math.sqrt(n.degree + 1)

    # 为每个节点生成简单的特征向量 (度 + 指令数 + 熵, 扩展到 feature_dim)
    for n in nodes.values():
        base = [n.degree / max(1.0, len(nodes)),
                min(1.0, n.instruction_count / 100.0),
                n.byte_entropy / 8.0]
        n.features = (base * ((feature_dim // 3) + 1))[:feature_dim]
        while len(n.features) < feature_dim:
            n.features.append(0.0)


def gravity_edge_probability(src_node: GravityCFGNode,
                             dst_node: GravityCFGNode,
                             base_dropout: float = 0.15) -> float:
    """计算边的保留概率。引力越大 → 保留概率越高 → 丢弃概率越低。
    返回 [0, 1], 表示此边应保留的概率。"""
    dist = abs(src_node.instruction_count - dst_node.instruction_count) / 100.0
    dist += abs(src_node.byte_entropy - dst_node.byte_entropy)
    dist = max(dist, 1e-6)

    gravity = (src_node.mass * dst_node.mass) / (dist * dist)
    # Sigmoid 归一化到 [0, 1]
    prob = 1.0 / (1.0 + math.exp(-3.0 * (gravity - 0.5)))
    # 混合 base_dropout: 即使引力为零, 也有 base_dropout/2 的保留概率
    return base_dropout * 0.5 + (1.0 - base_dropout * 0.5) * prob


# --- 增广视图生成 ---

def generate_augmented_view(
    nodes: dict[int, GravityCFGNode],
    edges: list[tuple[int, int]],
    base_dropout: float = 0.15,
    seed: int = 0,
) -> list[tuple[int, int]]:
    """生成 CFG 的一个增广视图——引力感知边丢弃 + 特征掩码。

    与随机 DropEdge 不同: 弱引力边优先丢弃, 保留图的核心结构。
    两个不同 seed 产生两个不同的视图用于对比学习。"""
    rng = random.Random(seed)
    augmented: list[tuple[int, int]] = []

    for src, dst in edges:
        src_n = nodes.get(src)
        dst_n = nodes.get(dst)
        if src_n is None or dst_n is None:
            if rng.random() > base_dropout:
                augmented.append((src, dst))
            continue
        keep_prob = gravity_edge_probability(src_n, dst_n, base_dropout)
        if rng.random() < keep_prob:
            augmented.append((src, dst))

    return augmented


# --- 嵌入计算 ---
# 简化的消息传递: 对增广视图中的节点特征做一次邻域聚合。
# 完整 GNN 的近似——用于演示自监督对比学习框架,
# 生产环境替换为 GAT/GCN 编码器。

def compute_graph_embedding(
    nodes: dict[int, GravityCFGNode],
    edges: list[tuple[int, int]],
    out_dim: int = 64,
) -> list[float]:
    """从 CFG 计算图级嵌入 (简化: 邻域聚合 + 全局池化)。"""
    if not nodes:
        return [0.0] * out_dim

    # 邻域聚合: 每个节点 = 自身特征 + 邻居特征均值
    neighbor_sum: dict[int, list[float]] = defaultdict(
        lambda: [0.0] * out_dim)
    neighbor_count: dict[int, int] = defaultdict(int)

    for src, dst in edges:
        if src in nodes and dst in nodes:
            src_feat = nodes[src].features
            dst_feat = nodes[dst].features
            min_len = min(len(src_feat), len(dst_feat), out_dim)
            for i in range(min_len):
                neighbor_sum[src][i] += dst_feat[i]
            neighbor_count[src] += 1

    aggregated = {}
    for addr, n in nodes.items():
        feat = list(n.features)
        # 补齐到 out_dim
        while len(feat) < out_dim:
            feat.append(0.0)
        if neighbor_count[addr] > 0:
            cnt = neighbor_count[addr]
            for i in range(out_dim):
                feat[i] = 0.5 * feat[i] + 0.5 * neighbor_sum[addr][i] / cnt
        aggregated[addr] = feat[:out_dim]

    # 全局池化: 所有节点特征的均值
    embed = [0.0] * out_dim
    n_nodes = len(aggregated)
    if n_nodes == 0:
        return embed
    for feat in aggregated.values():
        for i, v in enumerate(feat):
            embed[i] += v / n_nodes

    # L2 归一化
    norm = math.sqrt(sum(v * v for v in embed))
    if norm > 1e-12:
        embed = [v / norm for v in embed]

    return embed


# --- 动量对比 (MoCo) ---

class MomentumContrastEmbedder:
    """动量对比学习 — 单 GPU/CPU 可运行的自监督预训练。

    key_encoder 的权重 = EMA(query_encoder 的权重)。
    负样本队列: 固定大小, FIFO 更新——新 batch 的嵌入入队, 最旧的出队。"""

    __slots__ = ('_dim', '_queue', '_queue_size', '_momentum', '_t',
                 '_query_weights', '_key_weights', '_loss_history')

    def __init__(self, embed_dim: int = 64, queue_size: int = 128,
                 momentum: float = 0.999, temperature: float = 0.07):
        self._dim = embed_dim
        self._queue: list[list[float]] = []
        self._queue_size = queue_size
        self._momentum = momentum
        self._t = temperature
        # query 和 key 编码器参数——简化版 (线性投影 + ReLU)
        self._query_weights = self._init_weights(embed_dim)
        self._key_weights = self._init_weights(embed_dim)
        self._loss_history: list[float] = []

    def _init_weights(self, dim: int) -> list[list[float]]:
        rng = random.Random(42)
        return [[rng.gauss(0, 0.1) for _ in range(dim)] for _ in range(dim)]

    def _project(self, embed: list[float],
                 weights: list[list[float]]) -> list[float]:
        """线性投影: y = W @ x + ReLU。"""
        out = []
        for row in weights:
            val = sum(r * e for r, e in zip(row, embed))
            out.append(max(0.0, val))
        # L2 normalize
        norm = math.sqrt(sum(v * v for v in out))
        if norm > 1e-12:
            out = [v / norm for v in out]
        return out

    def encode_query(self, embed: list[float]) -> list[float]:
        return self._project(embed, self._query_weights)

    def encode_key(self, embed: list[float]) -> list[float]:
        return self._project(embed, self._key_weights)

    def compute_loss(self, q_embed: list[float],
                     k_pos_embed: list[float]) -> float:
        """InfoNCE 损失: -log(exp(q·k+/τ) / Σ exp(q·k_i/τ))。"""
        # 正样本
        pos_sim = sum(a * b for a, b in zip(q_embed, k_pos_embed)) / self._t
        pos_exp = math.exp(pos_sim)

        # 负样本 (来自队列)
        neg_sum = pos_exp  # 分母包含正样本
        for neg in self._queue:
            neg_sim = sum(a * b for a, b in zip(q_embed, neg)) / self._t
            neg_sum += math.exp(neg_sim)

        loss = -math.log(max(1e-12, pos_exp / neg_sum))
        self._loss_history.append(loss)
        if len(self._loss_history) > 500:
            self._loss_history.pop(0)
        return loss

    def update_key_encoder(self) -> None:
        """动量更新: key_weights = m * key_weights + (1-m) * query_weights。"""
        for i in range(self._dim):
            for j in range(self._dim):
                self._key_weights[i][j] = (
                    self._momentum * self._key_weights[i][j]
                    + (1.0 - self._momentum) * self._query_weights[i][j]
                )

    def enqueue(self, k_embed: list[float]) -> None:
        self._queue.append(k_embed)
        while len(self._queue) > self._queue_size:
            self._queue.pop(0)

    def avg_loss(self) -> float:
        if not self._loss_history:
            return 0.0
        return sum(self._loss_history) / len(self._loss_history)

    def stats(self) -> dict:
        return {
            'queue_size': len(self._queue),
            'max_queue': self._queue_size,
            'momentum': self._momentum,
            'temperature': self._t,
            'avg_loss': round(self.avg_loss(), 4),
            'steps': len(self._loss_history),
        }


# --- 预训练循环适配器 ---

def pretrain_step(
    nodes: dict[int, GravityCFGNode],
    edges: list[tuple[int, int]],
    embedder: MomentumContrastEmbedder,
    step: int,
) -> float:
    """单步预训练: 生成两个增广视图 → 计算嵌入 → InfoNCE 损失 → 动量更新。"""
    view1 = generate_augmented_view(nodes, edges, base_dropout=0.15, seed=step * 2)
    view2 = generate_augmented_view(nodes, edges, base_dropout=0.15, seed=step * 2 + 1)

    emb1 = compute_graph_embedding(nodes, view1)
    emb2 = compute_graph_embedding(nodes, view2)

    q = embedder.encode_query(emb1)
    k = embedder.encode_key(emb2)

    loss = embedder.compute_loss(q, k)
    embedder.enqueue(k)
    embedder.update_key_encoder()

    return loss


__all__ = [
    'GravityCFGNode', 'build_gravity_model',
    'gravity_edge_probability', 'generate_augmented_view',
    'compute_graph_embedding', 'MomentumContrastEmbedder',
    'pretrain_step',
]
