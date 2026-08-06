# 拓扑感知图增强策略网络 + 策略蒸馏
#
# 核心组件:
#   AugmentParams — 增强操作的分布参数
#   AugmentPolicyNetwork — 2层MLP: 拓扑特征 → 增强参数分布
#   PolicyDistiller — 策略网络蒸馏为O(1)查找表
#
# 架构选择:
#   2层MLP: 输入仅11维，更深网络过拟合风险高
#   输出mean+log_std: 支持重参数化采样
#   参数量 ~600: 可在单batch内训练完成

from __future__ import annotations

import math
import logging
from typing import Dict, List, Tuple, Any
from dataclasses import dataclass

import numpy as np

from .topology import TopologyProfile

logger = logging.getLogger(__name__)


@dataclass
class AugmentParams:
    """增强操作的分布参数（mean + log-std）。

    输出分布参数而非具体值——同一图每次采样产生不同增强，
    天然支持对比学习的多视图生成。
    """
    node_drop_mean: float
    edge_drop_mean: float
    edge_add_mean: float
    feature_mask_mean: float
    subgraph_ratio_mean: float
    node_drop_log_std: float
    edge_drop_log_std: float
    feature_mask_log_std: float

    def to_prob_dict(self) -> Dict[str, float]:
        return {
            'node_drop_p': float(1.0 / (1.0 + math.exp(-self.node_drop_mean))),
            'edge_drop_p': float(1.0 / (1.0 + math.exp(-self.edge_drop_mean))),
            'edge_add_p': float(1.0 / (1.0 + math.exp(-self.edge_add_mean))),
            'feature_mask_p': float(1.0 / (1.0 + math.exp(-self.feature_mask_mean))),
            'subgraph_ratio': float(1.0 / (1.0 + math.exp(-self.subgraph_ratio_mean))),
        }


class AugmentPolicyNetwork:
    """2层MLP策略网络: 拓扑特征 → 增强参数分布。

    INPUT_DIM=11, HIDDEN_DIM=32, OUTPUT_MEAN_DIM=5, OUTPUT_STD_DIM=3
    参数量: 11×32 + 32 + 5×32 + 5 + 3×32 + 3 ≈ 664
    """

    INPUT_DIM = 11
    HIDDEN_DIM = 32
    OUTPUT_MEAN_DIM = 5
    OUTPUT_STD_DIM = 3

    def __init__(self):
        rng = np.random.RandomState(42)
        s1 = math.sqrt(2.0 / self.INPUT_DIM)
        s2 = math.sqrt(2.0 / self.HIDDEN_DIM)
        self.W1 = rng.randn(self.HIDDEN_DIM, self.INPUT_DIM) * s1
        self.b1 = np.zeros(self.HIDDEN_DIM)
        self.W2_mean = rng.randn(self.OUTPUT_MEAN_DIM, self.HIDDEN_DIM) * s2
        self.b2_mean = np.zeros(self.OUTPUT_MEAN_DIM)
        self.W2_std = rng.randn(self.OUTPUT_STD_DIM, self.HIDDEN_DIM) * s2
        self.b2_std = np.full(self.OUTPUT_STD_DIM, -1.0)  # 初始低方差

    def forward(self, topology_vec: np.ndarray) -> AugmentParams:
        x = topology_vec[:self.INPUT_DIM]
        h = np.maximum(0, x @ self.W1.T + self.b1)
        means = h @ self.W2_mean.T + self.b2_mean
        log_stds = np.clip(h @ self.W2_std.T + self.b2_std, -3.0, 1.0)
        return AugmentParams(
            node_drop_mean=float(means[0]), edge_drop_mean=float(means[1]),
            edge_add_mean=float(means[2]), feature_mask_mean=float(means[3]),
            subgraph_ratio_mean=float(means[4]),
            node_drop_log_std=float(log_stds[0]),
            edge_drop_log_std=float(log_stds[1]),
            feature_mask_log_std=float(log_stds[2]),
        )

    def sample_params(self, topology_vec: np.ndarray
                      ) -> Tuple[AugmentParams, Dict[str, float]]:
        """重参数化采样: z = μ + σ·ε"""
        dist = self.forward(topology_vec)
        node_drop = dist.node_drop_mean + math.exp(dist.node_drop_log_std) * np.random.randn()
        edge_drop = dist.edge_drop_mean + math.exp(dist.edge_drop_log_std) * np.random.randn()
        feat_mask = dist.feature_mask_mean + math.exp(dist.feature_mask_log_std) * np.random.randn()

        sampled = AugmentParams(
            node_drop_mean=node_drop, edge_drop_mean=edge_drop,
            edge_add_mean=dist.edge_add_mean, feature_mask_mean=feat_mask,
            subgraph_ratio_mean=dist.subgraph_ratio_mean,
            node_drop_log_std=dist.node_drop_log_std,
            edge_drop_log_std=dist.edge_drop_log_std,
            feature_mask_log_std=dist.feature_mask_log_std,
        )
        probs = sampled.to_prob_dict()
        for k in probs:
            probs[k] = max(0.01, min(0.60, probs[k]))
        return sampled, probs

    def get_parameters(self) -> List[np.ndarray]:
        return [self.W1, self.b1, self.W2_mean, self.b2_mean, self.W2_std, self.b2_std]

    def set_parameters(self, params: List[np.ndarray]):
        self.W1, self.b1, self.W2_mean, self.b2_mean, self.W2_std, self.b2_std = params


class PolicyDistiller:
    """策略蒸馏: 策略网络 → O(1)查找表。

    拓扑空间离散化为 3×3×3 = 27 个网格:
      size: small(<50) / medium(50-200) / large(>200)
      density: sparse(avg<3) / medium(3-10) / dense(>10)
      clustering: low(<0.1) / medium(0.1-0.3) / high(>0.3)

    查找表 < 1KB，查表O(1)。
    """

    @staticmethod
    def discretize_topology(profile: TopologyProfile) -> Tuple[int, int, int]:
        sz = 0 if profile.n_nodes < 50 else 1 if profile.n_nodes < 200 else 2
        dn = 0 if profile.avg_degree < 3 else 1 if profile.avg_degree < 10 else 2
        cl = (0 if profile.clustering_coeff < 0.1
              else 1 if profile.clustering_coeff < 0.3 else 2)
        return sz, dn, cl

    @staticmethod
    def distill(policy: AugmentPolicyNetwork,
                n_samples_per_cell: int = 20
                ) -> Dict[Tuple[int, int, int], Dict[str, float]]:
        lookup = {}
        for sz in range(3):
            for dn in range(3):
                for cl in range(3):
                    cell = (sz, dn, cl)
                    all_probs = []
                    for _ in range(n_samples_per_cell):
                        profile = PolicyDistiller._dummy_profile(sz, dn, cl)
                        _, probs = policy.sample_params(profile.to_vector())
                        all_probs.append(probs)
                    avg = {}
                    for key in all_probs[0]:
                        vals = [p[key] for p in all_probs if key in p]
                        avg[key] = float(np.mean(vals)) if vals else 0.1
                    lookup[cell] = avg
        return lookup

    @staticmethod
    def _dummy_profile(sz: int, dn: int, cl: int) -> TopologyProfile:
        sizes = [30, 100, 350]
        densities = [2.0, 6.0, 15.0]
        clusters = [0.05, 0.2, 0.45]
        n = sizes[sz]
        avg_d = densities[dn]
        edges = int(n * avg_d)
        return TopologyProfile(
            n_nodes=n, n_edges=edges, avg_degree=avg_d,
            degree_variance=avg_d * 2.0,
            clustering_coeff=clusters[cl],
            avg_path_length=math.log(n)/math.log(avg_d) if avg_d > 1 else n,
            degree_entropy=math.log(avg_d + 1),
            n_connected_components=max(1, n // (5 + sz * 5)),
            leaf_ratio=0.3 - sz * 0.08,
            max_degree=int(avg_d * 3),
            diameter=int(math.log(n) * 3),
        )
