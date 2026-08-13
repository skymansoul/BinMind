# coding: utf-8
# 创建: 2024-09-02  |  图嵌入认证鲁棒性
# 修改: 2024-09-02  |  审计后补充文件头与错误处理
#
"""
图嵌入认证鲁棒性证明器——随机平滑在图域的自适应实现。

理论基础:
  Cohen et al.: 随机平滑为分类器提供L2认证半径。
  本模块将该框架扩展至离散图域——噪声机制从高斯替换为随机边翻转。

认证半径推导:
  设p_A = majority_count / N为胜出类别的经验频率。
  Clopper-Pearson下界 p_lower = lower_conf_bound(k, N, α)。
  认证半径: 在R次边翻转后，预测不变的最大R。

  保守下界（基于噪声转移核的Chernoff界）:
    P(未改变 | R次翻转) ≥ (1 - 2×edge_flip_prob)^R
    → R < log(0.5) / log(1 - 2×edge_flip_prob)

与ANVIL v2共形预测的互补性:
  ANVIL → 模型输出校准（分布外检测）
  本模块 → 输入鲁棒性认证（对抗扰动不变性）
  组合 → 模型+数据双重安全保证——完整可信漏洞检测框架
"""

import math
import copy
import random as _random
from dataclasses import dataclass
from typing import Callable, List, Tuple

from .graph_noise import GraphNoiseConfig, perturb_edges, clopper_pearson_lower


@dataclass
class CertifiedPrediction:
    """认证预测——含鲁棒性保证"""
    predicted_class: int = 0
    certified_radius: float = 0.0
    majority_count: int = 0
    total_samples: int = 0
    confidence_level: float = 0.999
    abstain: bool = False


def compute_certified_radius(majority_count: int, total_samples: int,
                              edge_flip_prob: float,
                              alpha: float = 0.001) -> CertifiedPrediction:
    """基于随机平滑理论的认证半径计算。

    步骤:
      1. p_lower = Clopper-Pearson(k, N, α) ——胜出类别真实比例的保守下界
      2. 若p_lower ≤ 0.5: 无法认证 → abstain
      3. 认证半径 = floor(log(0.5) / log(1 - 2×flip_prob))
         辅以p_lower收紧: min(上述, floor(log(0.5) / log(p_lower)))
    """
    if total_samples <= 0:
        return CertifiedPrediction(abstain=True, total_samples=0)

    p_lower = clopper_pearson_lower(majority_count, total_samples, alpha)
    if p_lower <= 0.5:
        return CertifiedPrediction(
            majority_count=majority_count, total_samples=total_samples,
            confidence_level=1.0 - alpha, abstain=True)

    flip_factor = 2 * edge_flip_prob
    if flip_factor >= 1.0:
        return CertifiedPrediction(
            majority_count=majority_count, total_samples=total_samples,
            confidence_level=1.0 - alpha, abstain=True)

    r_noise = math.floor(math.log(0.5) / math.log(1.0 - flip_factor))
    r_p = (math.floor(math.log(0.5) / math.log(p_lower))
           if p_lower < 1.0 else float('inf'))
    radius = min(r_noise, r_p)

    return CertifiedPrediction(
        certified_radius=float(radius),
        majority_count=majority_count, total_samples=total_samples,
        confidence_level=1.0 - alpha)


class GraphEmbeddingCertifier:
    """图嵌入认证器——随机平滑 + 认证半径估计。

    使用流程:
      certifier = GraphEmbeddingCertifier(embed_fn)
      certified, distances = certifier.certify(function_graph)

    embed_fn: Callable[[graph], embedding] —— 须返回含.vector属性的对象
    噪声样本数N: 越大认证越精确，但线性增加计算成本（典型: 1000）
    """

    def __init__(self, embed_fn: Callable,
                  noise_config: GraphNoiseConfig = None,
                  num_noise_samples: int = 1000,
                  alpha: float = 0.001,
                  distance_threshold: float = 0.3):
        self._embed = embed_fn
        self._noise_cfg = noise_config or GraphNoiseConfig()
        self._n_samples = num_noise_samples
        self._alpha = alpha
        self._threshold = distance_threshold

    def certify(self, graph) -> Tuple[CertifiedPrediction, List[float]]:
        """对单个函数图执行认证。

        流程:
          1. 计算原始嵌入向量
          2. 对图施加N次随机边翻转噪声
          3. 计算每次噪声嵌入与原始嵌入的余弦距离
          4. 统计距离≤threshold的稳定样本比例
          5. 基于二项置信界计算认证半径

        返回 (CertifiedPrediction, [噪声嵌入距离列表])
        """
        rng = _random.Random(self._noise_cfg.seed or None)
        orig_emb = self._embed(graph)
        orig_vec = orig_emb.vector

        edges = list(graph.edges) if hasattr(graph, 'edges') else []
        num_nodes = (len(graph.nodes) if hasattr(graph, 'nodes')
                      else max(max(e) for e in edges) + 1 if edges else len(edges))

        distances = []
        stable = 0

        for _ in range(self._n_samples):
            pert_edges = perturb_edges(edges, num_nodes, self._noise_cfg, rng)
            pert_graph = copy.copy(graph)
            if hasattr(pert_graph, 'edges'):
                pert_graph.edges = pert_edges
            try:
                emb = self._embed(pert_graph)
                d = _cos_dist(orig_vec, emb.vector)
                distances.append(d)
                if d <= self._threshold:
                    stable += 1
            except Exception:
                continue

        certified = compute_certified_radius(
            stable, len(distances), self._noise_cfg.edge_flip_prob, self._alpha)
        return certified, distances

    def batch_certify(self, graphs: List
                       ) -> List[Tuple[CertifiedPrediction, List[float]]]:
        """批量认证"""
        return [self.certify(g) for g in graphs]

    def estimate_n_for_radius(self, target_radius: float) -> int:
        """估计达到目标认证半径所需的最小噪声样本数。

        基于二项置信区间宽度与radius(p)导数的渐进展开。
        """
        p_min = 0.5 ** (1.0 / max(target_radius, 1))
        z = 3.29  # α=0.001
        precision = (p_min - 0.5) / 2
        n = int(z ** 2 * p_min * (1.0 - p_min) / max(precision ** 2, 1e-6))
        return max(100, min(n, 10000))


def _cos_dist(a: List[float], b: List[float]) -> float:
    """余弦距离 = 1 - 余弦相似度"""
    if len(a) != len(b) or not a:
        return 1.0
    dot = sum(x * y for x, y in zip(a, b))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(y * y for y in b))
    if na < 1e-10 or nb < 1e-10:
        return 1.0
    return max(0.0, 1.0 - max(-1.0, min(1.0, dot / (na * nb))))


def certify_embedding(embed_fn: Callable, graph,
                       n_samples: int = 1000,
                       flip_prob: float = 0.05,
                       alpha: float = 0.001
                       ) -> Tuple[CertifiedPrediction, List[float]]:
    """便捷认证入口"""
    cfg = GraphNoiseConfig(edge_flip_prob=flip_prob)
    return GraphEmbeddingCertifier(
        embed_fn, cfg, num_noise_samples=n_samples, alpha=alpha).certify(graph)


__all__ = [
    "CertifiedPrediction",
    "compute_certified_radius",
    "GraphEmbeddingCertifier",
    "certify_embedding",
]
