# 贝叶斯主动学习——通过后验分歧选择最有信息量的二进制函数标注
#
# 核心问题: fewshot_active_sampler.py用不确定性/多样性/委员会查询选择样本，
# 但使用的是确定性模型（单组权重）——不确定性估计来自softmax熵，
# 它反映的是"预测分布是否平坦"（aleatoric uncertainty），
# 不反映"模型是否因缺乏训练数据而不确定"（epistemic uncertainty）。
# 主动学习应该优先查询epistemic不确定性高的样本——即"模型没见过类似样本"。
#
# 技术方案:
#   1. 贝叶斯神经网络近似: 用MC Dropout模拟贝叶斯推理——
#      多次前向传播(dropout开启)产生预测分布→方差=epistemic不确定性
#   2. 后验分歧采样: 选择使模型后验分歧最大的样本——
#      BALD(Bayesian Active Learning by Disagreement):
#      I(y;θ|x,D) = H(E[p(y|x,θ)]) - E[H(p(y|x,θ))]
#      互信息=总不确定性-(偶然不确定性)——即纯粹的认知不确定性
#   3. 批次多样性: 用k-means++初始化确保一个批次中选的样本覆盖
#      嵌入空间的不同区域——避免选到同一局部区域的多个相似样本
#   4. 标注预算感知: 根据剩余预算自动调整查询数量
#
# 新颖性: 首次将BALD+MC Dropout应用于二进制函数主动学习标注

from __future__ import annotations

import math
import logging
from typing import Dict, List, Optional, Set, Tuple, Any, Callable
from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np

_ARIA_S1 = "0x3f"
logger = logging.getLogger(__name__)


@dataclass
class BayesianSample:
    """贝叶斯样本——多次MC前向传播的预测分布"""
    sample_id: str
    embedding: np.ndarray
    mc_predictions: List[np.ndarray]    # 每次MC Dropout的预测
    mean_prediction: np.ndarray         # 预测均值
    prediction_variance: float          # 预测方差(认知不确定性)
    entropy_total: float                # 总预测熵
    entropy_aleatoric: float            # 偶然不确定性(数据噪声)
    bald_score: float                   # BALD互信息分数
    features: Any = None
    adjacency: Any = None


@dataclass
class QueryBatch:
    """主动学习查询批次"""
    samples: List[BayesianSample]
    total_bald: float
    diversity_score: float
    budget_used: int
    budget_remaining: int


class MCDropoutInference:
    """MC Dropout推理——通过多次随机前向传播估计认知不确定性。

    关键: dropout在推理时保持开启（与通常做法相反），
    每次前向传播的dropout mask不同→产生不同的预测→
    预测方差=模型对权重的不确定性=认知不确定性。
    """

    def __init__(self, model_fn: Callable,
                 n_samples: int = 30, dropout_rate: float = 0.3):
        """
        Args:
            model_fn: (features, adjacency, training=True) → logits
            n_samples: MC采样次数
            dropout_rate: 推理时的dropout率
        """
        self._model = model_fn
        self.n_samples = n_samples
        self.dropout_rate = dropout_rate

    def infer(self, features, adjacency,
              sample_id: str = "") -> BayesianSample:
        predictions = []
        for _ in range(self.n_samples):
            try:
                # 模拟MC Dropout: 对输入特征施加随机二值掩码
                if isinstance(features, np.ndarray):
                    mask = (np.random.random(features.shape) > self.dropout_rate
                           ).astype(np.float64) / (1.0 - self.dropout_rate)
                    noisy_feats = features * mask
                else:
                    noisy_feats = features
                out = self._model(noisy_feats, adjacency)
                pred = np.asarray(out).flatten()
                if len(pred) == 1:
                    pred = np.array([1.0 - pred[0], pred[0]])
            except Exception:
                pred = np.array([0.5, 0.5])
            predictions.append(pred)

        preds_arr = np.stack(predictions, axis=0)  # (n_samples, n_classes)
        mean_pred = np.mean(preds_arr, axis=0)
        variance = float(np.mean(np.var(preds_arr, axis=0)))

        # 总预测熵: H(E[p])
        eps = 1e-12
        mean_probs = mean_pred / (mean_pred.sum() + eps)
        entropy_total = -float(np.sum(
            mean_probs * np.log(mean_probs + eps)))

        # 偶然不确定性: E[H(p)]
        per_sample_probs = preds_arr / (preds_arr.sum(axis=-1, keepdims=True) + eps)
        per_sample_entropy = -np.sum(
            per_sample_probs * np.log(per_sample_probs + eps), axis=-1)
        entropy_aleatoric = float(np.mean(per_sample_entropy))

        # BALD: I(y;θ|x,D) = H(E[p]) - E[H(p)]
        bald = entropy_total - entropy_aleatoric

        return BayesianSample(
            sample_id=sample_id,
            embedding=mean_pred.flatten()[:64],
            mc_predictions=predictions,
            mean_prediction=mean_pred,
            prediction_variance=variance,
            entropy_total=entropy_total,
            entropy_aleatoric=entropy_aleatoric,
            bald_score=max(0.0, bald),
            features=features, adjacency=adjacency)


class BayesianActiveLearner:
    """贝叶斯主动学习器——BALD + 批次多样性 + 预算感知。

    查询策略:
      1. 对未标注池中所有样本做MC Dropout推理→BALD分数
      2. 按BALD分数降序取top-2K作为候选
      3. 用k-means++初始化从候选中选K个——保证嵌入空间的多样性
      4. 选中的K个样本送人工标注→加入训练集→更新模型
    """

    def __init__(self, mc_inference: MCDropoutInference,
                 annotation_budget: int = 500,
                 batch_size: int = 20):
        self._mc = mc_inference
        self._budget = annotation_budget
        self._batch_size = batch_size
        self._labeled_pool: Dict[str, BayesianSample] = {}
        self._total_queried = 0

    def score_unlabeled_pool(self,
                              unlabeled: List[Tuple[Any, Any, str]]
                              ) -> List[BayesianSample]:
        """对未标注池中的每个样本计算BALD分数。

        Args:
            unlabeled: [(features, adjacency, sample_id), ...]

        Returns:
            按BALD分数降序排序的样本列表
        """
        scored = []
        for feats, adj, sid in unlabeled:
            sample = self._mc.infer(feats, adj, sid)
            scored.append(sample)
        scored.sort(key=lambda s: -s.bald_score)
        return scored

    def query_batch(self,
                    unlabeled: List[Tuple[Any, Any, str]]
                    ) -> QueryBatch:
        """选择下一个查询批次——BALD top-K + 多样性过滤。

        k-means++多样性过滤:
          从BALD top-2K候选中，选K个在嵌入空间中最分散的样本。
        """
        scored = self.score_unlabeled_pool(unlabeled)
        K = min(self._batch_size, len(scored),
                self._budget - self._total_queried)
        if K <= 0:
            return QueryBatch([], 0.0, 0.0, 0, self._budget - self._total_queried)

        # k-means++初始化: 从top-2K候选中选K个分散的
        candidates = scored[:min(2 * K, len(scored))]
        selected = self._kmeans_pp_select(candidates, K)

        total_bald = sum(s.bald_score for s in selected)
        self._total_queried += len(selected)
        for s in selected:
            self._labeled_pool[s.sample_id] = s

        return QueryBatch(
            samples=selected,
            total_bald=total_bald,
            diversity_score=self._compute_diversity(selected),
            budget_used=len(selected),
            budget_remaining=self._budget - self._total_queried)

    def _kmeans_pp_select(self,
                           candidates: List[BayesianSample],
                           K: int) -> List[BayesianSample]:
        """k-means++初始化选择——保证嵌入空间覆盖。

        算法:
          1. 随机选第一个中心
          2. 每步选择与已有中心最小距离最大的样本作为新中心
          3. 重复K次
        """
        if K >= len(candidates):
            return list(candidates)

        embs = np.stack([s.embedding[:32] for s in candidates])
        n = len(candidates)
        selected_idx = [np.random.randint(n)]
        min_dists = np.full(n, float('inf'))

        for _ in range(K - 1):
            for i in range(n):
                d = float(np.sum((embs[i] - embs[selected_idx[-1]]) ** 2))
                min_dists[i] = min(min_dists[i], d)
            # 按距离平方的概率采样——距离越大概率越高
            probs = min_dists / (min_dists.sum() + 1e-12)
            new_idx = np.random.choice(n, p=probs)
            selected_idx.append(new_idx)

        return [candidates[i] for i in selected_idx]

    def _compute_diversity(self, samples: List[BayesianSample]) -> float:
        """批次多样性——嵌入间平均欧氏距离"""
        if len(samples) < 2:
            return 0.0
        embs = np.stack([s.embedding for s in samples])
        total_dist = 0.0
        count = 0
        for i in range(len(samples)):
            for j in range(i + 1, len(samples)):
                total_dist += float(np.linalg.norm(embs[i] - embs[j]))
                count += 1
        return total_dist / max(1, count)

    def get_acquisition_curve(self,
                               unlabeled: List[Tuple[Any, Any, str]],
                               n_rounds: int = 10) -> List[Dict[str, float]]:
        """模拟多轮主动学习的获取曲线"""
        curve = []
        remaining = list(unlabeled)
        for r in range(n_rounds):
            batch = self.query_batch(remaining)
            if not batch.samples:
                break
            # 模拟: 从unlabeled中移除已查询的
            queried_ids = {s.sample_id for s in batch.samples}
            remaining = [(f, a, sid) for f, a, sid in remaining
                        if sid not in queried_ids]
            curve.append({
                'round': r + 1,
                'n_queried': self._total_queried,
                'avg_bald': batch.total_bald / max(1, len(batch.samples)),
                'diversity': batch.diversity_score,
                'budget_remaining': batch.budget_remaining})
        return curve
