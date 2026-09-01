# coding: utf-8
"""
对比跨架构漏洞嵌入 - 对比训练器。

技术问题:
  标准三元组损失(min(||a-p||² - ||a-n||² + α, 0))收敛慢且对负例质量敏感。
  跨架构场景中，架构差异引入的嵌入偏移与语义差异混杂，
  导致标准三元组损失的梯度信号噪声大。

解决方案:
  1. 架构解耦损失 - 额外约束同函数不同架构的嵌入差异仅由架构贡献
  2. CWE感知温度加权 - 同CWE负例施加更高权重，增强细粒度区分
  3. 嵌入投影器 - 将架构相关维度投影至共享子空间，降低架构噪声

损失函数设计:
  L_total = L_triplet + λ_arch * L_arch_invariance + λ_cwe * L_cwe_contrast

  L_triplet = max(||a-p||² - ||a-n||² + α, 0)  - 标准三元组
  L_arch_invariance = ||a - p||²  - 最小化跨架构正例距离
  L_cwe_contrast = -log(exp(sim(a, same_cwe) / τ) / Σ exp(sim(a, *) / τ))  - CWE感知

  目标: 嵌入空间中同漏洞函数跨架构聚集，不同漏洞函数分离，
  架构差异被投影器消除而非被损失函数压制。

与现有工作的差异:
  jTrans: 使用BERT-like预训练+微调（需大量标注）
  本方法: 三元组自监督+架构解耦 - 无需标注，利用编译工具链自动生成监督信号
"""

import math
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Callable
from collections import defaultdict

from .ccav_triplet_sampler import TripletSample, TripletBatch, CrossArchTripletSampler

_log = logging.getLogger(__name__)


# 损失函数


@dataclass
class ContrastiveLoss:
    """对比损失的三个分量 - 分离监控训练动态"""
    triplet_loss: float = 0.0
    arch_invariance_loss: float = 0.0
    cwe_contrast_loss: float = 0.0
    total_loss: float = 0.0
    # 用于监控的辅助指标
    mean_pos_dist: float = 0.0        # 正例对平均距离
    mean_neg_dist: float = 0.0        # 负例对平均距离（不含硬负例）
    hard_neg_recall: float = 0.0      # 困难负例被有效推开的比例
    active_triplets_ratio: float = 0.0  # margin>0的三元组比例


def compute_contrastive_loss(batch: TripletBatch,
                              lambda_arch: float = 0.5,
                              lambda_cwe: float = 0.3,
                              temperature: float = 0.07
                              ) -> ContrastiveLoss:
    """计算三组分的对比损失。

    参数:
      batch: 三元组批次
      lambda_arch: 架构不变性损失权重
      lambda_cwe: CWE对比损失权重
      temperature: softmax温度, 越小惩罚越集中

    温度选择依据:
      τ=0.07: 在小批次(<256)对比学习中表现最优
      τ=0.1: 大批次(≥4096)推荐值

    返回ContrastiveLoss - 含各分量值与监控指标。
    """
    if not batch.samples:
        return ContrastiveLoss()

    n = len(batch.samples)
    alpha = batch.samples[0].margin - (  # 从第一个样本反推margin
        _euclidean(batch.samples[0].anchor_embedding,
                    batch.samples[0].positive_embedding) -
        _euclidean(batch.samples[0].anchor_embedding,
                    batch.samples[0].negative_embedding))

    # 分量1: 标准三元组损失
    triplet_sum = 0.0
    active_count = 0
    for s in batch.samples:
        pos_d = _euclidean(s.anchor_embedding, s.positive_embedding)
        neg_d = _euclidean(s.anchor_embedding, s.negative_embedding)
        loss = max(pos_d - neg_d + alpha, 0.0)
        triplet_sum += loss
        if loss > 0:
            active_count += 1

    triplet_loss = triplet_sum / n

    # 分量2: 架构不变性 - 最小化跨架构正例距离
    arch_sum = sum(
        _euclidean(s.anchor_embedding, s.positive_embedding) ** 2
        for s in batch.samples)
    arch_loss = arch_sum / n

    # 分量3: CWE感知对比损失（简化InfoNCE）
    # 按CWE分组 - 同CWE样本互为正例
    cwe_groups: Dict[str, List[int]] = defaultdict(list)
    for i, s in enumerate(batch.samples):
        if s.cwe_type:
            cwe_groups[s.cwe_type].append(i)

    cwe_loss = 0.0
    if len(cwe_groups) > 1:
        for i, s in enumerate(batch.samples):
            if not s.cwe_type:
                continue
            # 正例: 同CWE的其他样本
            pos_indices = [j for j in cwe_groups[s.cwe_type] if j != i]
            if not pos_indices:
                continue
            # 计算与所有样本的相似度
            sims = []
            for j in range(n):
                sim = -_euclidean(s.anchor_embedding,
                                   batch.samples[j].anchor_embedding)
                sims.append(sim)
            # InfoNCE: -log(Σ_{pos} exp(sim/τ) / Σ_{all} exp(sim/τ))
            max_sim = max(sims)
            pos_sum = sum(math.exp((sims[j] - max_sim) / temperature)
                          for j in pos_indices)
            all_sum = sum(math.exp((s - max_sim) / temperature) for s in sims)
            if pos_sum > 0 and all_sum > 0:
                cwe_loss += -math.log(pos_sum / all_sum)
        cwe_loss /= n

    total = triplet_loss + lambda_arch * arch_loss + lambda_cwe * cwe_loss

    # 监控指标
    pos_dists = [_euclidean(s.anchor_embedding, s.positive_embedding)
                 for s in batch.samples]
    neg_dists = [_euclidean(s.anchor_embedding, s.negative_embedding)
                 for s in batch.samples]
    hard_samples = [s for s in batch.samples if s.is_hard_negative]
    hard_pushed = sum(1 for s in hard_samples
                      if _euclidean(s.anchor_embedding, s.negative_embedding) >
                      _euclidean(s.anchor_embedding, s.positive_embedding))

    return ContrastiveLoss(
        triplet_loss=round(triplet_loss, 6),
        arch_invariance_loss=round(arch_loss, 6),
        cwe_contrast_loss=round(cwe_loss, 6),
        total_loss=round(total, 6),
        mean_pos_dist=round(sum(pos_dists) / max(n, 1), 4),
        mean_neg_dist=round(sum(neg_dists) / max(n, 1), 4),
        hard_neg_recall=round(hard_pushed / max(len(hard_samples), 1), 3),
        active_triplets_ratio=round(active_count / max(n, 1), 3))


# 嵌入投影器 - 架构解耦


class ArchitectureProjector:
    """架构解耦投影器 - 将架构相关维度映射至共享子空间。

    方法: 学习架构特定的线性投影矩阵W_a，使:
      ||W_a^T * embed_a - W_b^T * embed_b|| 最小化
      （同一函数不同架构的嵌入距离）

    实现: 轻量PCA-like投影 - 计算跨架构嵌入对的主成分差异方向，
    将嵌入减去这些方向上的投影分量。
    """

    def __init__(self, projection_dim: int = 128, shared_dim: int = 96):
        self._proj_dim = projection_dim
        self._shared_dim = shared_dim
        self._arch_components: Dict[str, List[List[float]]] = {}
        self._fitted = False

    def fit(self, pairs: List[Tuple[str, str, List[float], List[float]]]):
        """用跨架构嵌入对拟合投影方向。

        参数:
          pairs: [(arch_a, arch_b, embed_a, embed_b), ...]
            同函数不同架构的嵌入对 - 来自编译器自动生成。
        """
        # 收集每个架构的差异向量
        arch_diffs: Dict[str, List[List[float]]] = defaultdict(list)
        for arch_a, arch_b, emb_a, emb_b in pairs:
            diff = [ea - eb for ea, eb in zip(emb_a, emb_b)]
            arch_diffs[arch_a].append(diff)
            # 反向差异
            rev_diff = [-d for d in diff]
            arch_diffs[arch_b].append(rev_diff)

        # 对每个架构计算主差异方向（简化PCA: 均值方向）
        for arch, diffs in arch_diffs.items():
            if not diffs:
                continue
            dim = len(diffs[0])
            mean_diff = [sum(d[i] for d in diffs) / len(diffs) for i in range(dim)]
            # 归一化 - 单位方向向量
            norm = math.sqrt(sum(m * m for m in mean_diff))
            if norm > 1e-10:
                mean_diff = [m / norm for m in mean_diff]
            self._arch_components[arch] = [mean_diff]
        self._fitted = True

    def project(self, embedding: List[float], arch: str) -> List[float]:
        """将嵌入投影至架构无关的共享子空间。

        原理: 减去嵌入在架构主差异方向上的投影分量。
        结果: 同函数不同架构的投影后嵌入几何距离显著缩小。
        """
        if not self._fitted or arch not in self._arch_components:
            return embedding

        result = list(embedding)
        for component in self._arch_components[arch]:
            # 标量投影 = embed · component
            dot = sum(e * c for e, c in zip(result, component))
            # 减去投影分量
            result = [r - dot * c for r, c in zip(result, component)]
        return result


# 辅助


def _euclidean(a: List[float], b: List[float]) -> float:
    """欧几里得距离"""
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))


__all__ = [
    "ContrastiveLoss",
    "compute_contrastive_loss",
    "ArchitectureProjector",
]
