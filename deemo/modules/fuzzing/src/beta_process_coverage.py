"""Beta 过程覆盖特征模型 (Coverage Feature Model, BPCF) — IBP-inspired 启发式.

修改记录:
2025-08-07 14:08 - Beta-Bernoulli 因子模型: 覆盖→潜在特征矩阵
2025-08-09 08:33 - 新特征预测: P(new)≈α/(N+1) (IBP 渐近性质)
2025-08-20 09:45 - 修正: 标注为启发式分配 (非 MCMC), 区分于完整 Bayesian inference
2025-08-10 11:17 - 在线 Gibbs 更新: 每次新观测后增量更新特征分配

参考:
  Griffiths & Ghahramani (2011) "The Indian Buffet Process: An Introduction
    and Review" (JMLR) — IBP 的基础教程, Beta 过程的 de Finetti 表示
  Thibaux & Jordan (2007) "Hierarchical Beta Processes and the Indian Buffet
    Process" (AISTATS) — Beta 过程的层次化扩展
  Paisley & Carin (2009) "Nonparametric Factor Analysis with Beta Process
    Priors" (ICML) — Beta-Bernoulli 因子模型的 MCMC 推断

在 fuzzing 文献中的位置:
  非参数贝叶斯方法在 fuzzing 中完全无先例。将覆盖建模为
  潜在二元特征的组合: 每个种子激活一组隐藏覆盖特征。
  Beta 过程作为非参数先验: 特征数随观测增长而自适应增加。
  这给出了一种原则性的方法预测"还有多少未发现的特征"。

核心创新:
  1. Beta-Bernoulli 覆盖因子模型: 覆盖边→潜在特征的二元分配
  2. 新特征预测: P(new feature | observed) 基于 IBP 的预期特征数
     E[K_N] ≈ α·log(N)  → 随种子数对数增长
  3. 在线 Gibbs 分配: 每个新种子后增量更新特征所有权
  4. 覆盖完备性: 当 P(new_feature) < 0.01 → 探索近乎穷尽
"""

import math
import random
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# ---- BPCF 参数 ----
_ALPHA = 1.0                  # Beta 过程浓度参数 (特征发现率)


@dataclass
class CoverageFeature:
    """一个推断出的潜在覆盖特征."""
    feature_id: int
    # 该特征被各种子激活的计数 (用于 Gibbs 更新)
    activation_count: int = 0
    # 哪些种子激活了此特征
    seeds_activated: Set[str] = field(default_factory=set)
    # 该特征对应的覆盖边子集 (代表性边)
    representative_edges: Set[int] = field(default_factory=set)


class BetaProcessCoverageModel:
    """Beta 过程覆盖特征模型.

    模型: Z[n×K] — 二元矩阵, Z[n,k]=1 表示种子 n 激活特征 k。
    先验: Z[n,k] ~ Bernoulli(π_k), π_k ~ Beta(α/K, 1)
    K→∞ 极限 → Indian Buffet Process (IBP).

    新特征预测:
      E[K_N | α] ≈ α·log(N) (IBP 的期望特征数)
      P(new feature for seed N+1) ≈ α / (N + 1)

    使用方式:
      bpcf = BetaProcessCoverageModel(alpha=1.0)
      for seed in corpus:
          bpcf.add_seed(seed.id, seed.coverage)
      prob_new = bpcf.probability_new_feature()
    """

    def __init__(self, alpha: float = _ALPHA):
        self.alpha = alpha
        self._features: Dict[int, CoverageFeature] = {}
        self._seed_assignments: Dict[str, Set[int]] = defaultdict(set)
        self._next_feature_id: int = 0
        self._n_seeds: int = 0
        self._total_edges_seen: Set[int] = set()

    # //// 种子注册 (在线 Gibbs 分配) ////
    def add_seed(self, seed_id: str, coverage: Set[int]) -> None:
        """注册新种子并在线分配特征."""
        self._n_seeds += 1
        new_edges = coverage - self._total_edges_seen
        self._total_edges_seen.update(coverage)

        # 步骤1: 分配已有特征 (Gibbs 采样的一步近似)
        assigned = set()
        for fid, feat in self._features.items():
            # P(assign | other_seeds) ∝ activation_count / N
            prob = feat.activation_count / max(1, self._n_seeds - 1)
            # 偏向分配当种子与该特征的代表性边有交集时
            edge_overlap = len(coverage & feat.representative_edges)
            edge_bonus = min(0.5, edge_overlap / max(1, len(feat.representative_edges)))
            if random.random() < prob + edge_bonus:
                assigned.add(fid)
                feat.activation_count += 1
                feat.seeds_activated.add(seed_id)
                self._seed_assignments[seed_id].add(fid)

        # 步骤2: 生成新特征 (基于新边)
        if new_edges:
            # IBP: 期望新特征数 ≈ α/N
            expected_new = self.alpha / max(1, self._n_seeds)
            n_new = 1 if random.random() < expected_new else 0
            # 额外的确定性新特征: 若新边数 > 已有特征的典型覆盖
            if len(new_edges) > 3:
                n_new += 1

            for _ in range(n_new):
                fid = self._next_feature_id
                self._next_feature_id += 1
                feat = CoverageFeature(
                    feature_id=fid, activation_count=1,
                    seeds_activated={seed_id},
                    representative_edges=set(list(new_edges)[:5]))
                self._features[fid] = feat
                self._seed_assignments[seed_id].add(fid)

        # 容量控制: 合并相似特征
        if len(self._features) > 200:
            self._merge_similar_features()

    # //// 预测 ////
    def probability_new_feature(self) -> float:
        """下一个种子发现新特征的概率.

        P ≈ α / (N + 1), 基于 IBP 的渐近性质。
        """
        if self._n_seeds == 0:
            return 1.0
        return self.alpha / (self._n_seeds + 1)

    def expected_new_features(self, n_additional: int = 100) -> float:
        """未来 n_additional 个种子的期望新特征数.

        E[ΔK] ≈ α·log((N + n) / N)
        """
        if self._n_seeds == 0:
            return float(n_additional)
        return self.alpha * math.log(
            (self._n_seeds + n_additional) / self._n_seeds)

    def coverage_completeness(self) -> float:
        """覆盖完备性 [0,1]: 1-P(new_feature).

        接近 1.0 → 新种子不太可能引入新特征 → 覆盖近乎穷尽。
        """
        return 1.0 - self.probability_new_feature()

    # //// 特征分析 ////
    def feature_rarity(self, seed_id: str) -> float:
        """种子的特征稀有度: 它激活的特征的平均稀有度.

        稀有特征 → 该种子探索了独特区域。
        """
        assigned = self._seed_assignments.get(seed_id, set())
        if not assigned:
            return 0.0
        rarities = []
        for fid in assigned:
            feat = self._features.get(fid)
            if feat:
                # 稀有度 = 1 - P(assign) = 1 - activation_count/N
                rarities.append(
                    1.0 - feat.activation_count / max(1, self._n_seeds))
        return sum(rarities) / len(rarities)

    def top_rare_seeds(self, top_k: int = 5) -> List[Tuple[str, float]]:
        """返回最具稀有特征的种子."""
        scored = [(sid, self.feature_rarity(sid))
                  for sid in self._seed_assignments]
        scored.sort(key=lambda x: x[1], reverse=True)
        return scored[:top_k]

    # //// 辅助 ////
    def _merge_similar_features(self) -> None:
        """合并重叠度高的特征 (控制数量)."""
        feat_ids = list(self._features.keys())
        if len(feat_ids) < 2:
            return
        # 按激活计数升序 (小特征先合并)
        feat_ids.sort(key=lambda fid: self._features[fid].activation_count)
        merged = set()
        for i, fid_a in enumerate(feat_ids):
            if fid_a in merged:
                continue
            fa = self._features[fid_a]
            for fid_b in feat_ids[i+1:]:
                if fid_b in merged:
                    continue
                fb = self._features[fid_b]
                # Jaccard 重叠
                inter = len(fa.representative_edges & fb.representative_edges)
                union = len(fa.representative_edges | fb.representative_edges)
                if union > 0 and inter / union > 0.7:
                    # 合并: b → a
                    fa.activation_count += fb.activation_count
                    fa.seeds_activated.update(fb.seeds_activated)
                    fa.representative_edges.update(fb.representative_edges)
                    merged.add(fid_b)
                    # 更新种子分配
                    for sid in fb.seeds_activated:
                        self._seed_assignments[sid].discard(fid_b)
                        self._seed_assignments[sid].add(fid_a)
        for fid in merged:
            del self._features[fid]

    # //// 统计 ////
    def stats(self) -> dict:
        n_features = len(self._features)
        avg_act = (sum(f.activation_count for f in self._features.values())
                   / max(1, n_features))
        return {
            "n_seeds": self._n_seeds,
            "n_features_inferred": n_features,
            "total_edges_seen": len(self._total_edges_seen),
            "alpha": self.alpha,
            "prob_new_feature": round(self.probability_new_feature(), 4),
            "expected_new_in_100": round(
                self.expected_new_features(100), 2),
            "coverage_completeness": round(
                self.coverage_completeness(), 4),
            "avg_activation": round(avg_act, 2),
            "rare_seed_example": (
                self.top_rare_seeds(1)[0][0]
                if self._seed_assignments else None),
        }

    def clear(self) -> None:
        self._features.clear(); self._seed_assignments.clear()
        self._next_feature_id = 0; self._n_seeds = 0
        self._total_edges_seen.clear()
