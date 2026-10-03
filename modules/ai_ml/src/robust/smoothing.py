# 离散域随机平滑 - 为二进制代码GNN嵌入提供可认证对抗鲁棒性
#
# 核心算法:
#   1. 对输入图采样噪声版本，构造平滑分类器
#   2. 二阶段认证: n0采样确定top-1类别 → n采样估计pA下界
#   3. 若pA > 0.5，certified radius = σ·Φ^{-1}(pA)
#   4. 拓扑自适应噪声: 噪声水平与图局部复杂度成比例
#
# 标准引用:
#   随机平滑的认证鲁棒性方法
#   图扰动下的可证鲁棒性

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from collections import deque
from dataclasses import dataclass, field

import numpy as np
from scipy.stats import norm as _norm
from scipy.stats import beta as _beta

logger = logging.getLogger(__name__)


@dataclass
class GraphNoiseConfig:
    edge_flip_p: float = 0.02
    feature_noise_std: float = 0.05
    adaptive_scale: bool = True
    min_local_noise: float = 0.005
    max_local_noise: float = 0.15


class DiscreteGraphNoise:
    """离散图域噪声注入。

    两层噪声:
      1. 结构噪声: 每条边以概率p独立翻转（Bernoulli）
      2. 特征噪声: 节点特征加自适应σ的高斯噪声

    自适应尺度逻辑: 高度数节点更稳定（需更小噪声），低度数节点更敏感。
    这避免了全局均匀噪声对稀疏子图的过度破坏。
    """

    def __init__(self, config: GraphNoiseConfig = None):
        self.config = config or GraphNoiseConfig()

    def sample_noisy_graph(self,
                           adjacency: List[List[int]],
                           node_features: List[List[float]],
                           node_degrees: Optional[List[int]] = None
                           ) -> Tuple[List[List[int]], List[List[float]]]:
        n = len(adjacency)
        if node_degrees is None:
            node_degrees = [sum(row) for row in adjacency]

        noisy_adj = [row[:] for row in adjacency]
        noisy_feat = [row[:] for row in node_features]

        for i in range(n):
            for j in range(n):
                if i == j:
                    continue
                if self.config.adaptive_scale:
                    deg_factor = 1.0 / math.sqrt(
                        max(1, (node_degrees[i] + node_degrees[j]) / 2))
                    local_p = float(np.clip(
                        self.config.edge_flip_p * deg_factor,
                        self.config.min_local_noise,
                        self.config.max_local_noise))
                else:
                    local_p = self.config.edge_flip_p
                if np.random.random() < local_p:
                    noisy_adj[i][j] = 1 - noisy_adj[i][j]

        if node_features and len(node_features) > 0 and len(node_features[0]) > 0:
            dim = len(node_features[0])
            for i in range(n):
                if i >= len(node_features):
                    continue
                deg = max(1, node_degrees[i]) if i < len(node_degrees) else 1
                local_std = self.config.feature_noise_std
                if self.config.adaptive_scale:
                    local_std *= 1.0 / math.sqrt(deg)
                noise = np.random.randn(dim) * local_std
                for d in range(min(dim, len(noisy_feat[i]))):
                    noisy_feat[i][d] += noise[d]

        return noisy_adj, noisy_feat

    def sample_batch(self,
                     adjacency: List[List[int]],
                     node_features: List[List[float]],
                     n_samples: int,
                     node_degrees: Optional[List[int]] = None
                     ) -> List[Tuple[List[List[int]], List[List[float]]]]:
        if node_degrees is None:
            node_degrees = [sum(row) for row in adjacency]
        return [self.sample_noisy_graph(adjacency, node_features, node_degrees)
                for _ in range(n_samples)]


@dataclass
class CertifiedRadius:
    certified_l1_radius: float
    certified_l2_radius: float
    certified_radius_combined: float
    prediction: int
    confidence: float
    n_samples: int
    abstain: bool = False

    def to_dict(self) -> dict:
        return {
            'l1_radius': self.certified_l1_radius,
            'l2_radius': self.certified_l2_radius,
            'combined_radius': self.certified_radius_combined,
            'prediction': self.prediction,
            'confidence': self.confidence,
            'n_samples': self.n_samples,
            'abstain': self.abstain,
        }


class CertifiedBinaryRobustness:
    """离散域随机平滑-为二进制GNN嵌入提供可认证鲁棒性。

    对二分类漏洞检测(benign/vulnerable)，认证半径公式:
      R = σ/2 · (Φ^{-1}(p_benign) - Φ^{-1}(p_vuln))
    """

    def __init__(self,
                 model_fn: Callable,
                 noise_config: Optional[GraphNoiseConfig] = None,
                 n0: int = 100,
                 n: int = 10000,
                 alpha: float = 0.001):
        self._model = model_fn
        self._noise = DiscreteGraphNoise(noise_config or GraphNoiseConfig())
        self._n0 = n0
        self._n = n
        self._alpha = alpha

    def _safe_predict(self, feats, adj, target_node: int) -> int:
        try:
            logits = self._model(feats, adj)
            if hasattr(logits, '__len__') and len(logits) > target_node:
                scores = logits[target_node]
                if hasattr(scores, '__len__') and len(scores) >= 2:
                    return int(np.argmax(scores))
                return int(float(scores) > 0.5)
            return 0
        except Exception:
            return 0

    def _extract_subgraph(self, adjacency, node_features, center_node, radius=2):
        n = len(adjacency)
        visited = {center_node}
        frontier = {center_node}
        for _ in range(radius):
            new_frontier = set()
            for u in frontier:
                for v in range(n):
                    if adjacency[u][v] or adjacency[v][u]:
                        if v not in visited:
                            new_frontier.add(v)
                            visited.add(v)
            frontier = new_frontier
        nodes = sorted(visited)
        remap = {old: new for new, old in enumerate(nodes)}
        sub_n = len(nodes)
        sub_adj = [[0] * sub_n for _ in range(sub_n)]
        sub_feat = [[0.0] * len(node_features[0]) for _ in range(sub_n)]
        for ni, oi in enumerate(nodes):
            for nj, oj in enumerate(nodes):
                sub_adj[ni][nj] = adjacency[oi][oj]
            sub_feat[ni] = node_features[oi][:]
        return sub_adj, sub_feat, remap

    @staticmethod
    def _lower_confidence_bound(k: int, n: int, alpha: float) -> float:
        if k == 0:
            return 0.0
        if k > n:
            return 1.0
        return float(_beta.ppf(alpha, k, n - k + 1))

    @staticmethod
    def _certified_l1_radius(p_lower: float, sigma: float, n_nodes: int) -> float:
        z = _norm.ppf(p_lower)
        scale = sigma * math.sqrt(max(1, n_nodes))
        return max(0.0, z * scale)

    @staticmethod
    def _certified_l2_radius(p_lower: float, sigma: float) -> float:
        z = _norm.ppf(p_lower)
        return max(0.0, sigma * z)

    def certify(self,
                adjacency: List[List[int]],
                node_features: List[List[float]],
                node_degrees: Optional[List[int]] = None,
                target_node: Optional[int] = None) -> CertifiedRadius:
        n_nodes = len(adjacency)

        if target_node is not None and n_nodes > 20:
            working_adj, working_feat, remap = self._extract_subgraph(
                adjacency, node_features, target_node, radius=2)
            local_target = remap.get(target_node, 0)
        else:
            working_adj = adjacency
            working_feat = node_features
            local_target = target_node or 0

        if node_degrees is None:
            node_degrees = [sum(row) for row in working_adj]

        # Phase 1: n0 samples — 确定top-1类别
        counts0 = np.zeros(2, dtype=np.int64)
        for _ in range(self._n0):
            adj_n, feat_n = self._noise.sample_noisy_graph(
                working_adj, working_feat, node_degrees)
            counts0[self._safe_predict(feat_n, adj_n, local_target)] += 1
        c_hat = int(np.argmax(counts0))

        # Phase 2: n samples — 精确估计pA下界
        counts = np.zeros(2, dtype=np.int64)
        for _ in range(self._n):
            adj_n, feat_n = self._noise.sample_noisy_graph(
                working_adj, working_feat, node_degrees)
            counts[self._safe_predict(feat_n, adj_n, local_target)] += 1

        n_A = int(counts[c_hat])
        p_A_lower = self._lower_confidence_bound(n_A, self._n, self._alpha)

        if p_A_lower <= 0.5:
            return CertifiedRadius(0.0, 0.0, 0.0, c_hat,
                                  1.0 - self._alpha, self._n0 + self._n, abstain=True)

        sigma_e = self._noise.config.edge_flip_p
        sigma_f = self._noise.config.feature_noise_std

        cert_l1 = self._certified_l1_radius(p_A_lower, sigma_e, n_nodes)
        cert_l2 = self._certified_l2_radius(p_A_lower, sigma_f)
        combined = math.sqrt(
            (cert_l1 / max(1, n_nodes)) ** 2 +
            (cert_l2 / max(0.01, sigma_f * 5)) ** 2
        )

        return CertifiedRadius(cert_l1, cert_l2, combined, c_hat,
                              1.0 - self._alpha, self._n0 + self._n)

    def batch_certify(self,
                      graphs: List[Tuple[List[List[int]], List[List[float]]]],
                      target_nodes: Optional[List[int]] = None,
                      verbose: bool = False) -> List[CertifiedRadius]:
        results = []
        for idx, (adj, feats) in enumerate(graphs):
            target = target_nodes[idx] if target_nodes else None
            result = self.certify(adj, feats, target_node=target)
            results.append(result)
            if verbose and idx % 10 == 0:
                logger.info(
                    f"certified {idx}/{len(graphs)}: "
                    f"pred={result.prediction}, L1={result.certified_l1_radius:.3f}, "
                    f"abstain={result.abstain}")
        return results
