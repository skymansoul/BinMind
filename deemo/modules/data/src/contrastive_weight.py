# 无网络对比特征加权 (Contrastive Feature Weighting without Neural Networks)
#
# 核心问题: 去重流水线产生多个相似度评分 (SimHash, MinHash, 图评分, 向量),
#   各评分基于不同的特征子集. 如何融合这些评分以最大化"相同对"与
#   "不同对"之间的区分度? 标准做法是手动加权或简单平均.
#
# 创新点:
#   1. Exponentiated Gradient Descent on Simplex: 将特征权重向量 w
#      约束在概率单纯形上 (Σw_i=1, w_i≥0). 用对比损失:
#        L(w) = Σ_{(a,b)∈same_pairs} (1 - score_w(a,b))² +
#               Σ_{(a,b)∈diff_pairs} score_w(a,b)²
#      对 w 求梯度后用 EG 更新: w_i ← w_i·exp(-η·∇_i L) / Z.
#      收敛保证: O(√(log d / T)) regret bound (EGD on simplex).
#   2. 弱监督信号构造: 不需要人工标注. 用以下启发式自动生成训练对:
#       same_pairs: 两方法同时给出 high similarity (>0.9)
#       diff_pairs: 两方法同时给出 low similarity (<0.1)
#       uncertain: 方法间矛盾 (一个高一个低) → 不参与训练
#   3. 在线更新: 每处理 N 个二进制对后, 用累积的 same/diff pairs
#      做一次 EG 更新. 特征权重随时间自适应数据分布变化.
#   4. 权重可解释性: 学习到的权重向量直接反映哪些特征维度对区分
#      相同/不同二进制最有信息量. 可导出为人类可读的特征重要性排名.
#
# 与现有工作:
#   - SimCLR/MoCo: 需要神经网络 + 大量负样本. 本方案 O(d) 在线更新.
#   - Bin2vec/HermesSim: 需要 GNN 预训练. 本方案无模型.
#   - 标准特征融合: 平均或固定权重. 本方案在线对比学习最优权重.

import math
import random
from collections import deque
from typing import Callable, Dict, List, Optional, Tuple


class ContrastiveWeightLearner:
    """对比特征加权学习器: EGD on simplex.

    参数:
      d: 特征维度数
      learning_rate: EG 学习率 η (默认 0.1)
      pair_buffer_size: same/diff pairs 缓冲区大小
      update_every: 每 N 个新 pair 更新一次权重
      l2_reg: L2 正则化系数

    用法:
      cwl = ContrastiveWeightLearner(d=10)
      for (feats_a, feats_b, label) in stream:
          cwl.add_pair(feats_a, feats_b, label)  # label: +1=same, -1=diff
      weights = cwl.weights  # 学习到的特征权重
      score = cwl.score(feats_a, feats_b)  # 加权余弦相似度
    """

    def __init__(self, d: int, learning_rate: float = 0.1,
                 pair_buffer_size: int = 500, update_every: int = 50,
                 l2_reg: float = 0.001):
        self.d = d
        self.lr = learning_rate
        self.l2 = l2_reg
        self.update_every = update_every

        self._w = [1.0 / d] * d
        self._same_pairs: deque = deque(maxlen=pair_buffer_size)
        self._diff_pairs: deque = deque(maxlen=pair_buffer_size)
        self._pair_count = 0
        self._update_count = 0
        # AdaGrad: 每维度累计梯度平方和
        self._grad_sq_sum = [1e-8] * d  # 初始化为小值避免除零

    @property
    def weights(self) -> List[float]:
        return list(self._w)

    def add_pair(self, feats_a: List[float], feats_b: List[float],
                  label: int):
        """添加一对特征向量 + 标签.

        label: +1 = same pair (应得高分), -1 = diff pair (应得低分).
        """
        n = min(len(feats_a), len(feats_b), self.d)
        pair = (feats_a[:n], feats_b[:n])
        if label > 0:
            self._same_pairs.append(pair)
        else:
            self._diff_pairs.append(pair)

        self._pair_count += 1
        if self._pair_count % self.update_every == 0:
            self._update_weights()

    def add_auto_labeled(self, feats_a: List[float], feats_b: List[float],
                          scores: Dict[str, float],
                          high_threshold: float = 0.9,
                          low_threshold: float = 0.1):
        """自动标注: 基于多个相似度评分的一致性."""
        values = list(scores.values())
        if not values:
            return

        n_high = sum(1 for v in values if v >= high_threshold)
        n_low = sum(1 for v in values if v <= low_threshold)

        if n_high >= 2:
            self.add_pair(feats_a, feats_b, label=+1)
        elif n_low >= 2:
            self.add_pair(feats_a, feats_b, label=-1)
        # else: uncertain, skip

    def score(self, feats_a: List[float], feats_b: List[float]) -> float:
        """加权余弦相似度."""
        n = min(len(feats_a), len(feats_b), self.d)
        dot = sum(self._w[i] * feats_a[i] * feats_b[i] for i in range(n))
        na = math.sqrt(sum(self._w[i] * feats_a[i]**2 for i in range(n)))
        nb = math.sqrt(sum(self._w[i] * feats_b[i]**2 for i in range(n)))
        denom = na * nb
        return dot / denom if denom > 1e-9 else 0.0

    def feature_importance(self) -> List[Tuple[int, float]]:
        """返回特征重要性排名: [(feature_index, weight), ...] 降序."""
        ranked = sorted(enumerate(self._w), key=lambda x: x[1], reverse=True)
        return [(i, round(w, 6)) for i, w in ranked]

    def reset(self):
        self._w = [1.0/self.d] * self.d
        self._grad_sq_sum = [1e-8] * self.d
        self._same_pairs.clear(); self._diff_pairs.clear()
        self._pair_count = 0; self._update_count = 0

    def _update_weights(self):
        """EGD on simplex: 计算梯度 → 指数更新 → 归一化."""
        if not self._same_pairs and not self._diff_pairs:
            return

        # 计算各维度的平均梯度
        grad = [0.0] * self.d
        n_samples = 0

        # Same pairs: 梯度 = -2·(1-score)·∂score/∂w_i
        for fa, fb in self._same_pairs:
            s = self._weighted_cosine(fa, fb)
            if s >= 1.0:
                continue
            ds = self._cosine_gradient(fa, fb)
            for i in range(self.d):
                grad[i] += -2.0 * (1.0 - s) * ds[i]
            n_samples += 1

        # Diff pairs: 梯度 = 2·score·∂score/∂w_i
        for fa, fb in self._diff_pairs:
            s = self._weighted_cosine(fa, fb)
            if s <= 0.0:
                continue
            ds = self._cosine_gradient(fa, fb)
            for i in range(self.d):
                grad[i] += 2.0 * s * ds[i]
            n_samples += 1

        if n_samples == 0:
            return

        # 平均梯度 + L2 正则化
        for i in range(self.d):
            grad[i] = grad[i] / n_samples + 2.0 * self.l2 * self._w[i]
            # AdaGrad: 累积梯度平方和
            self._grad_sq_sum[i] += grad[i] ** 2

        # EG 更新 with AdaGrad per-dimension learning rate
        new_w = [0.0] * self.d
        total = 0.0
        for i in range(self.d):
            # η_i = lr / sqrt(G_i + ε), 频繁更新的维度自动降速
            adaptive_lr = self.lr / math.sqrt(self._grad_sq_sum[i])
            new_w[i] = self._w[i] * math.exp(-adaptive_lr * grad[i])
            total += new_w[i]

        if total > 1e-12:
            for i in range(self.d):
                self._w[i] = new_w[i] / total

        self._update_count += 1

    def _weighted_cosine(self, a: List[float], b: List[float]) -> float:
        n = min(len(a), len(b), self.d)
        dot = sum(self._w[i] * a[i] * b[i] for i in range(n))
        na = math.sqrt(sum(self._w[i] * a[i]**2 for i in range(n)))
        nb = math.sqrt(sum(self._w[i] * b[i]**2 for i in range(n)))
        return dot / (na * nb) if (na * nb) > 1e-9 else 0.0

    def _cosine_gradient(self, a: List[float], b: List[float]) -> List[float]:
        """∂(weighted_cosine)/∂w_i."""
        n = min(len(a), len(b), self.d)
        dot = sum(self._w[i] * a[i] * b[i] for i in range(n))
        na = math.sqrt(sum(self._w[i] * a[i]**2 for i in range(n)))
        nb = math.sqrt(sum(self._w[i] * b[i]**2 for i in range(n)))

        if na * nb < 1e-9:
            return [0.0] * self.d

        ds = [0.0] * self.d
        for i in range(n):
            # ∂/∂w_i [dot / (na*nb)] = (a_i*b_i)/(na*nb) - dot*(a_i²/(2*na³*nb) + b_i²/(2*na*nb³))
            term1 = (a[i] * b[i]) / (na * nb)
            term2_a = (a[i]**2) / (2.0 * na**3 * nb) if na > 1e-9 else 0
            term2_b = (b[i]**2) / (2.0 * na * nb**3) if nb > 1e-9 else 0
            ds[i] = term1 - dot * (term2_a + term2_b)

        return ds


# ---------------------------------------------------------------------------
# 批量特征权重学习器: 从历史签名对中学习
# ---------------------------------------------------------------------------

class BatchFeatureOptimizer:
    """批量特征优化器: 从签名数据库中采样 same/diff pairs 并学习权重.

    用法:
      bfo = BatchFeatureOptimizer(feature_extractor_fn, d=15)
      bfo.sample_pairs(db, n_pairs=500)
      bfo.optimize(epochs=10)
      weights = bfo.weights
    """

    def __init__(self, feature_extractor: Callable, d: int,
                 learning_rate: float = 0.05):
        self._extract = feature_extractor
        self._learner = ContrastiveWeightLearner(d=d, learning_rate=learning_rate)

    def sample_pairs(self, db, n_pairs: int = 500):
        """从 DB 中采样训练对.

        策略: 随机采样 + 用 SimHash 相似度作为弱标签.
        """
        sigs = db.list_signatures(limit=max(n_pairs * 3, 100))
        if len(sigs) < 2:
            return

        indices = list(range(len(sigs)))
        random.shuffle(indices)

        sampled = 0
        for i in range(0, min(len(indices)-1, n_pairs*2), 2):
            if sampled >= n_pairs:
                break
            a = sigs[indices[i]]
            b = sigs[indices[i+1]]
            fa = self._extract(a)
            fb = self._extract(b)

            # 弱标签: 同 stage → same, 不同 stage → diff
            label = 1 if a.get("stage") == b.get("stage") else -1
            self._learner.add_pair(fa, fb, label)
            sampled += 1

    def optimize(self, epochs: int = 10):
        for _ in range(epochs):
            self._learner._update_weights()

    @property
    def weights(self) -> List[float]:
        return self._learner.weights

    def feature_ranking(self) -> List[Tuple[int, float]]:
        return self._learner.feature_importance()


__all__ = [
    "ContrastiveWeightLearner",
    "BatchFeatureOptimizer",
]
