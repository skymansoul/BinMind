# 拓扑感知的自适应图增强策略网络
#
# 核心问题: 现有图对比学习的增强策略（GraphCL风格）使用全局固定参数，
# 忽略不同图拓扑对增强的敏感性差异。稀疏CFG和密集循环体需不同增强强度-
# 均匀增强要么破坏稀疏图语义，要么对密集图不够充分。
#
# 技术方案:
#   1. 轻量策略网络: 图拓扑特征、增强参数分布（非具体值，避免过拟合）
#   2. 双目标RL训练: 对比损失 + 语义保持正则
#   3. 策略蒸馏: 训练后蒸馏为O(1)查找表，推理零开销
#
# 核心实现在 src/augment/policy_network.py
# 本文件提供便捷入口 AdaptiveAugmentPolicy + PolicyTrainer

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Tuple, Any, Callable
from dataclasses import dataclass

import numpy as np

from .src.augment.topology import TopologyProfile, TopologyAnalyzer
from .src.augment.policy_network import (
    AugmentParams,
    AugmentPolicyNetwork,
    PolicyDistiller,
)

logger = logging.getLogger(__name__)


# 策略训练器

class PolicyTrainer:
    # 双目标RL训练: 对比损失最小化 + 语义保持正则.
    # 训练信号: 对比奖励(正负样本对相似度) + 语义保持(增强前后嵌入余弦相似度) + 多样性奖励(两视图增强参数方差).

    def __init__(self,
                 encoder_fn: Callable,
                 learning_rate: float = 0.001,
                 temperature: float = 0.1,
                 semantic_weight: float = 0.3,
                 diversity_weight: float = 0.05):
        self._encoder = encoder_fn
        self._lr = learning_rate
        self._temp = temperature
        self._semantic_weight = semantic_weight
        self._diversity_weight = diversity_weight
        self._policy = AugmentPolicyNetwork()
        self._analyzer = TopologyAnalyzer()

    @property
    def policy(self) -> AugmentPolicyNetwork:
        return self._policy

    def train_step(self,
                   anchor_graphs: List[Tuple[List[List[float]], List[List[int]]]],
                   positive_graphs: List[Tuple[List[List[float]], List[List[int]]]],
                   n_augment_samples: int = 4) -> Dict[str, float]:
        total_reward = 0.0
        gradients = [np.zeros_like(p) for p in self._policy.get_parameters()]
        batch_size = len(anchor_graphs)
        if batch_size == 0:
            return {'loss': 0.0, 'reward': 0.0}

        for idx in range(batch_size):
            anchor_feat, anchor_adj = anchor_graphs[idx]
            pos_feat, pos_adj = positive_graphs[idx]
            topo_vec = self._analyzer.analyze(anchor_adj).to_vector()

            for _ in range(n_augment_samples):
                params, probs = self._policy.sample_params(topo_vec)
                aug_adj1, aug_feat1 = self._apply_augment(anchor_adj, anchor_feat, probs)
                aug_adj2, aug_feat2 = self._apply_augment(anchor_adj, anchor_feat, probs)

                try:
                    emb_anchor = self._encoder(anchor_feat, anchor_adj)
                    emb_v1 = self._encoder(aug_feat1, aug_adj1)
                    emb_v2 = self._encoder(aug_feat2, aug_adj2)
                    emb_pos = self._encoder(pos_feat, pos_adj)
                except Exception:
                    continue

                sim_v1v2 = self._cosine(emb_v1, emb_v2)
                sim_ap = self._cosine(emb_anchor, emb_pos)
                cont_reward = (sim_v1v2 + sim_ap) / 2.0

                sem_reward = (self._cosine(emb_anchor, emb_v1) +
                             self._cosine(emb_anchor, emb_v2)) / 2.0

                div_reward = 1.0 - abs(sim_v1v2)

                combined = (cont_reward + self._semantic_weight * sem_reward +
                           self._diversity_weight * div_reward)
                total_reward += combined

                # REINFORCE梯度
                for gi, param in enumerate(self._policy.get_parameters()):
                    flat = param.flatten()
                    for gi2 in range(min(flat.size, 10)):  # 每步最多10维梯度
                        eps = 1e-4
                        idx_g = gi2
                        flat[idx_g] += eps
                        self._policy.set_parameters(
                            [p.copy() for p in self._policy.get_parameters()])
                        _, pp = self._policy.sample_params(topo_vec)
                        lp_plus = self._log_prob(pp)

                        flat[idx_g] -= 2 * eps
                        self._policy.set_parameters(
                            [p.copy() for p in self._policy.get_parameters()])
                        _, pm = self._policy.sample_params(topo_vec)
                        lp_minus = self._log_prob(pm)

                        flat[idx_g] += eps
                        policy_grad = (lp_plus - lp_minus) / (2 * eps)
                        gradients[gi].flat[idx_g] += policy_grad * combined

        n_total = batch_size * n_augment_samples
        for gi, param in enumerate(self._policy.get_parameters()):
            param -= self._lr * (gradients[gi] / max(1, n_total))

        avg_reward = total_reward / max(1, n_total)
        return {'loss': -avg_reward, 'reward': avg_reward}

    @staticmethod
    def _apply_augment(adjacency, features, probs):
        n = len(adjacency)
        aug_adj = [row[:] for row in adjacency]
        aug_feat = [row[:] for row in features]
        for i in range(n):
            for j in range(n):
                if adjacency[i][j] and np.random.random() < probs.get('edge_drop_p', 0.1):
                    aug_adj[i][j] = 0
        for i in range(n):
            for j in range(n):
                if i != j and not adjacency[i][j] and np.random.random() < probs.get('edge_add_p', 0.02):
                    aug_adj[i][j] = 1
        if features and len(features[0]) > 0:
            dim = len(features[0])
            for i in range(n):
                for d in range(dim):
                    if np.random.random() < probs.get('feature_mask_p', 0.1):
                        aug_feat[i][d] = 0.0
        return aug_adj, aug_feat

    @staticmethod
    def _cosine(a, b):
        dot = sum(x * y for x, y in zip(a, b))
        na = math.sqrt(sum(x * x for x in a))
        nb = math.sqrt(sum(y * y for y in b))
        if na < 1e-12 or nb < 1e-12:
            return 0.0
        return max(-1.0, min(1.0, dot / (na * nb)))

    @staticmethod
    def _log_prob(probs: Dict[str, float]) -> float:
        lp = 0.0
        for key in ['node_drop_p', 'edge_drop_p', 'feature_mask_p']:
            p = np.clip(probs.get(key, 0.5), 0.01, 0.99)
            lp += math.log(p) + math.log(1 - p)
        return lp


# 便捷入口

class AdaptiveAugmentPolicy:
    # 拓扑感知自适应增强策略的便捷入口.
    # 在线模式: get_augment_probs() 直接使用策略网络.
    # 蒸馏模式: distill_and_use_lookup() 后使用O(1)查找表.

    def __init__(self, use_distilled: bool = False):
        self._policy = AugmentPolicyNetwork()
        self._analyzer = TopologyAnalyzer()
        self._use_distilled = use_distilled
        self._lookup: Optional[Dict[Tuple[int, int, int], Dict[str, float]]] = None

    def get_augment_probs(self, adjacency: List[List[int]]) -> Dict[str, float]:
        profile = self._analyzer.analyze(adjacency)
        if self._use_distilled and self._lookup is not None:
            cell = PolicyDistiller.discretize_topology(profile)
            if cell in self._lookup:
                return dict(self._lookup[cell])
        _, probs = self._policy.sample_params(profile.to_vector())
        return probs

    def distill_and_use_lookup(self, n_samples_per_cell: int = 30):
        self._lookup = PolicyDistiller.distill(self._policy, n_samples_per_cell)
        self._use_distilled = True
        logger.info(f"policy distilled to {len(self._lookup)}-cell lookup table")

    def train(self,
              anchor_graphs: List[Tuple[List[List[float]], List[List[int]]]],
              positive_graphs: List[Tuple[List[List[float]], List[List[int]]]],
              steps: int = 50, lr: float = 0.001):
        trainer = PolicyTrainer(encoder_fn=self._passthrough_encoder, learning_rate=lr)
        for step in range(steps):
            metrics = trainer.train_step(anchor_graphs, positive_graphs)
            if step % 10 == 0:
                logger.debug(f"step {step}: reward={metrics['reward']:.4f}")
        self._policy = trainer.policy

    @staticmethod
    def _passthrough_encoder(features, adjacency):
        n = len(adjacency)
        if features and len(features) > 0:
            return list(np.mean(features, axis=0))
        return [float(n)] * 8
