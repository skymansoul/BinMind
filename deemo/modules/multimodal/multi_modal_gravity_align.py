"""
基于节点结构重要性增强的图对比学习多模态对齐。

理论基础:
  1. 重力启发式 CFG 边增强 + 图对比学习。
     为节点分配多维度结构质量分数，生成语义上有意义的增强视图。
  2. 文本-图三任务训练 (TGA + GMR + CL):
     - TGA: 对称 InfoNCE (text→graph + graph→text)
     - GMR: 图掩码恢复 (邻接矩阵重建)
     - CL:  MoCo 风格动量队列对比学习
  3. 动量队列 + 预洗牌机制，为大规模对比学习提供稳定的负样本信号。

动机:
  现有 multi_modal_alignment.py 使用 SimCLR 风格 NT-Xent 对比损失，
  但增强策略仅限于随机 dropout，缺乏语义上有意义的增强与自适应温度。

  结构重要性增强模拟编译器变换对 CFG 边的影响（死代码消除、函数内联），
  三任务训练同时捕获模态间与模态内关系，
  自适应温度根据对齐质量动态调整学习信号强度。

注: "BEGA" / "FuseBinRepr" 为设计引用的概念标签，对应论文的正式出版物信息待补录。

模块位置: multimodal/multi_modal_gravity_align.py
"""

import math
import random
from collections import deque
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

try:
    import numpy as np
    _NP = True
except ImportError:
    _NP = False

import logging
_log = logging.getLogger(__name__)


# ============================================================================
# BEGA 重力模型图增强
# ============================================================================

@dataclass
class GravityNode:
    """BEGA 重力模型节点 — 携带质量、位置和累积引力场。"""
    node_id: int
    mass: float = 1.0
    position: np.ndarray = None  # 2D 或 3D 位置向量
    gravity_field: float = 0.0   # 累积引力场强度

    def __post_init__(self):
        if self.position is None and _NP:
            self.position = np.random.randn(2) * 0.1  # 2D 随机初始化


def compute_node_masses(
    adj: "np.ndarray",
    node_features: "np.ndarray",
    alpha: float = 0.4,
    beta: float = 0.35,
    gamma: float = 0.25,
) -> "np.ndarray":
    """
    多维度节点质量计算 — BEGA Section 3.2。

    mass_i = alpha * deg_norm_i + beta * cc_norm_i + gamma * feat_norm_i

    feat_norm_i = ||feature_i||² / max(||feature||²)，
    作为语义重要性的代理：大范数特征 → 信息量更多的节点。
    """
    if not _NP:
        raise ImportError("BEGA 重力模型需要 NumPy")

    n = adj.shape[0]
    if n == 0:
        return np.array([])
    if n == 1:
        return np.array([1.0])

    # 度数归一化
    degrees = np.array(adj.sum(axis=0) + adj.sum(axis=1)).flatten()
    max_deg = degrees.max()
    deg_norm = degrees / max_deg if max_deg > 0 else np.ones(n) / n

    # 聚类系数
    cc = np.zeros(n)
    for i in range(n):
        neighbors = np.where((adj[i] > 0) | (adj[:, i] > 0))[0]
        k = len(neighbors)
        if k <= 1:
            continue
        sub = adj[np.ix_(neighbors, neighbors)]
        actual = (sub > 0).sum()
        possible = k * (k - 1)
        cc[i] = actual / possible if possible > 0 else 0.0
    max_cc = cc.max()
    cc_norm = cc / max_cc if max_cc > 0 else np.ones(n) / n

    # 特征范数归一化
    feat_norms = np.linalg.norm(node_features, axis=1) if node_features.ndim == 2 else np.ones(n)
    max_fn = feat_norms.max()
    feat_norm = feat_norms / max_fn if max_fn > 0 else np.ones(n) / n

    mass = alpha * deg_norm + beta * cc_norm + gamma * feat_norm
    return np.clip(mass, 0.05, 1.0)


def bega_gravity_edge_dropout(
    adj: "np.ndarray",
    node_masses: "np.ndarray",
    grav_constant: float = 1.0,
    dropout_rate: float = 0.20,
    seed: Optional[int] = None,
) -> "np.ndarray":
    """
    BEGA 引力驱动边丢弃 — 模拟编译器死代码消除。

    引力公式: F_ij = G * m_i * m_j

    低引力边（连接低质量节点）容易被编译器优化删除，
    因此以较高概率丢弃。高引力边保留。

    参数:
      dropout_rate: 目标丢弃率（实际丢弃率可能因引力分布略有偏差）。
    """
    if not _NP:
        return adj.copy()
    if seed is not None:
        np.random.seed(seed)

    augmented = adj.copy()
    edges = np.argwhere(augmented > 0)

    if len(edges) == 0:
        return augmented

    # 计算所有边的引力
    forces = np.array([
        grav_constant * node_masses[i] * node_masses[j]
        for i, j in edges
    ])

    # 引力越低 → 丢弃概率越高
    max_f = forces.max() if forces.max() > 0 else 1.0
    inv_forces = 1.0 - (forces / max_f)  # (0, 1)，低引力 → 接近 1

    # 确定丢弃阈值使期望丢弃率 = dropout_rate
    threshold = np.percentile(inv_forces, 100 * (1.0 - dropout_rate))

    for idx, (i, j) in enumerate(edges):
        if inv_forces[idx] > threshold:
            # 确保删除后不产生孤立节点
            temp = augmented.copy()
            temp[i, j] = 0
            if temp.sum(axis=0)[j] > 0 and temp.sum(axis=1)[i] > 0:
                augmented[i, j] = 0

    return augmented


# ============================================================================
# FuseBinRepr 三任务训练
# ============================================================================

class FuseBinReprAligner:
    """
    FuseBinRepr 三任务多模态对齐器。

    三个训练任务:
      TGA (Text-Graph Alignment):      跨模态对比学习，对齐文本与图嵌入
      GMR (Graph Masking Recovery):    掩码图结构恢复，学习模态内结构
      CL  (Contrastive Learning):      增强对比学习，利用负样本队列

    联合损失: L = λ_tga * L_TGA + λ_gmr * L_GMR + λ_cl * L_CL
    """

    def __init__(
        self,
        embed_dim: int = 256,
        temperature: float = 0.07,
        lambda_tga: float = 0.4,
        lambda_gmr: float = 0.3,
        lambda_cl: float = 0.3,
    ):
        if not _NP:
            raise ImportError("FuseBinRepr 需要 NumPy")
        self._dim = embed_dim
        self._temp = temperature
        self._lambda_tga = lambda_tga
        self._lambda_gmr = lambda_gmr
        self._lambda_cl = lambda_cl
        self._neg_queue: deque = deque(maxlen=65536)

    def tga_loss(
        self, text_emb: "np.ndarray", graph_emb: "np.ndarray"
    ) -> float:
        """
        TGA 损失 — 文本-图跨模态对齐。

        使用对称 InfoNCE：文本→图 和 图→文本 两个方向。
        """
        batch = text_emb.shape[0]
        if batch < 2:
            return 0.0

        # L2 归一化
        t = text_emb / (np.linalg.norm(text_emb, axis=1, keepdims=True) + 1e-8)
        g = graph_emb / (np.linalg.norm(graph_emb, axis=1, keepdims=True) + 1e-8)

        # 相似度矩阵
        sim = np.dot(t, g.T) / self._temp  # (B, B)

        # 对角线为正样本对
        labels = np.arange(batch)
        # softmax 交叉熵 — 双向
        loss_t2g = _cross_entropy(sim, labels)
        loss_g2t = _cross_entropy(sim.T, labels)

        return float((loss_t2g + loss_g2t) / 2.0)

    def gmr_loss(
        self, adj: "np.ndarray", adj_pred: "np.ndarray"
    ) -> float:
        """
        GMR 损失 — 图掩码恢复。

        二元交叉熵：比较原始邻接矩阵与从被掩码图恢复的预测。
        """
        mask = (adj > 0).astype(np.float64)
        eps = 1e-8
        # BCE: -[y*log(p) + (1-y)*log(1-p)]
        bce = -(
            mask * np.log(np.clip(adj_pred, eps, 1.0))
            + (1.0 - mask) * np.log(np.clip(1.0 - adj_pred, eps, 1.0))
        )
        return float(bce.mean())

    def contrastive_loss_with_queue(
        self,
        query_emb: "np.ndarray",
        key_emb: "np.ndarray",
    ) -> float:
        """
        CL 损失 — 对比学习 + 负样本队列。

        正样本: query_i ↔ key_i（同一样本的不同视图）
        负样本: query_i ↔ 队列中所有嵌入
        """
        batch = query_emb.shape[0]
        if batch == 0:
            return 0.0

        # L2 归一化
        q = query_emb / (np.linalg.norm(query_emb, axis=1, keepdims=True) + 1e-8)
        k = key_emb / (np.linalg.norm(key_emb, axis=1, keepdims=True) + 1e-8)

        # 正样本相似度
        pos = np.sum(q * k, axis=1) / self._temp  # (B,)

        # 负样本（从队列）
        if len(self._neg_queue) > 0:
            queue_arr = np.stack(list(self._neg_queue), axis=0)
            q_norm = queue_arr / (np.linalg.norm(queue_arr, axis=1, keepdims=True) + 1e-8)
            neg = np.dot(q, q_norm.T) / self._temp  # (B, Q)
            all_logits = np.concatenate([pos[:, None], neg], axis=1)  # (B, 1+Q)
        else:
            all_logits = pos[:, None]  # (B, 1)

        # 数值稳定
        all_logits -= np.max(all_logits, axis=1, keepdims=True)
        exp_logits = np.exp(all_logits)
        loss = -np.mean(np.log(exp_logits[:, 0] / (exp_logits.sum(axis=1) + 1e-8)))

        # 更新队列（入队前预洗牌）
        np.random.shuffle(k)
        for i in range(batch):
            self._neg_queue.append(k[i])

        return float(loss)

    def total_loss(
        self,
        text_emb: "np.ndarray",
        graph_emb: "np.ndarray",
        adj: "np.ndarray",
        adj_pred: "np.ndarray",
        query_emb: "np.ndarray",
        key_emb: "np.ndarray",
    ) -> Dict[str, float]:
        """计算三任务联合损失。"""
        l_tga = self.tga_loss(text_emb, graph_emb)
        l_gmr = self.gmr_loss(adj, adj_pred)
        l_cl = self.contrastive_loss_with_queue(query_emb, key_emb)

        total = (
            self._lambda_tga * l_tga
            + self._lambda_gmr * l_gmr
            + self._lambda_cl * l_cl
        )
        return {"tga": l_tga, "gmr": l_gmr, "cl": l_cl, "total": total}

    def reset_queue(self):
        self._neg_queue.clear()


# ============================================================================
# 自适应温度调度
# ============================================================================

class AdaptiveTemperature:
    """
    自适应温度调度器 — 根据对齐质量动态调整 NT-Xent 温度。

    设计意图:
      对比学习中温度参数控制 softmax 锐度。
      高温 (τ > 0.5): 软分配，适合训练早期（嵌入未稳定）
      低温 (τ < 0.1): 硬分配，适合训练后期（嵌入已收敛）

      自适应策略:
        τ_new = τ * (1 + β * (loss - target_loss))
      损失高于目标 → 提高温度（更宽容）
      损失低于目标 → 降低温度（更严格）
    """

    def __init__(
        self,
        initial_temp: float = 0.07,
        min_temp: float = 0.01,
        max_temp: float = 0.50,
        beta: float = 0.01,
        target_loss: float = 0.30,
    ):
        self._tau = initial_temp
        self._min = min_temp
        self._max = max_temp
        self._beta = beta
        self._target = target_loss
        self._history: List[float] = []

    @property
    def temperature(self) -> float:
        return self._tau

    def update(self, current_loss: float) -> float:
        """
        根据当前损失更新温度。

        更新公式:
          delta = β * (loss - target_loss)
          τ = clip(τ * (1 + delta), min, max)
        """
        delta = self._beta * (current_loss - self._target)
        self._tau = np.clip(self._tau * (1.0 + delta), self._min, self._max)
        self._history.append(self._tau)
        return self._tau

    def get_history(self) -> List[float]:
        return list(self._history)


# ============================================================================
# 辅助函数
# ============================================================================

def _cross_entropy(logits: "np.ndarray", labels: "np.ndarray") -> float:
    """Softmax 交叉熵 — NumPy 实现。"""
    logits = logits - np.max(logits, axis=1, keepdims=True)
    exp_l = np.exp(logits)
    probs = exp_l / exp_l.sum(axis=1, keepdims=True)
    n = logits.shape[0]
    loss = -np.log(probs[np.arange(n), labels] + 1e-8).mean()
    return float(loss)


def build_gravity_views(
    adj: "np.ndarray",
    node_features: "np.ndarray",
    view1_dropout: float = 0.15,
    view2_dropout: float = 0.35,
    seed: Optional[int] = None,
) -> Tuple["np.ndarray", "np.ndarray"]:
    """
    为对比学习生成两个 BEGA 重力增强视图。

    视图 1: 轻度丢弃（模拟 -O1 编译优化级别）
    视图 2: 重度丢弃（模拟 -O3 编译优化级别）

    返回: (view1_adj, view2_adj)
    """
    masses = compute_node_masses(adj, node_features)
    v1 = bega_gravity_edge_dropout(adj, masses, dropout_rate=view1_dropout, seed=seed)
    s2 = seed + 1 if seed is not None else None
    v2 = bega_gravity_edge_dropout(adj, masses, dropout_rate=view2_dropout, seed=s2)
    return v1, v2


__all__ = [
    "GravityNode",
    "compute_node_masses",
    "bega_gravity_edge_dropout",
    "FuseBinReprAligner",
    "AdaptiveTemperature",
    "build_gravity_views",
]
