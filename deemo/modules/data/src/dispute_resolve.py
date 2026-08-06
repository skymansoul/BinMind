# 上下文相关争议裁决 (Context-Dependent Disagreement Resolution)
#
# 核心问题: 多种去重/相似度方法常对同一二进制对给出矛盾判定:
#   SimHash=0.92 (高度相似), MinHash=0.45 (中等), 图评分=0.15 (不相似).
#   争议根源: 各方法对不同二进制类型敏感度不同.
#     - stripped binary: 图评分噪声大, SimHash 更可靠
#     - 大文件 (>100MB): MinHash CDC 粒度粗, SimHash 更可靠
#     - 有丰富 CFG: 图评分精度最高
#   现有方法 (bandit_router, adversarial_consistency) 仅选择或检测,
#   不解决"信哪个"的问题.
#
# 创新点:
#   1. 上下文分区 (Contextual Partitioning): 将二进制特征空间按
#      file_size, stripped, entropy, has_cfg 四个维度量化为网格.
#      每个网格单元维护独立的方法可信度统计 (Win/Loss 计数).
#   2. Bradley-Terry 排序模型在线估计: 每个网格单元内,
#      将方法间比较建模为 Bradley-Terry pairwise 排序:
#        P(method_i beats method_j) = exp(θ_i) / (exp(θ_i) + exp(θ_j))
#      其中 θ_i 是方法 i 的"可信度评分". 用 online MM (Minorization-
#      Maximization) 算法增量更新 θ 向量. O(K²) per update.
#   3. 争议裁决: 输入 (context, method_scores) →
#      输出 weighted_score = Σ_i w_i(ctx)·score_i,
#      其中 w_i(ctx) = exp(θ_i) / Σ_j exp(θ_j) (softmax over trust).
#      可信度高的方法获得更高聚合权重.
#   4. 冷启动平滑: 新上下文网格 (未充分观察) 回退到全局统计,
#      用 Bayesian shrinkage: θ_partition = (n_local·θ_local + α·θ_global)/(n_local+α).
#
# 与现有工作:
#   - bandit_router: 选择方法子集 (二元: 执行/跳过). 本方案加权融合所有方法.
#   - adversarial_consistency: 检测不一致. 本方案解决不一致.
#   - Bradley-Terry: 面向体育/游戏排名. 本方案首次应用于去重方法可信度排序.
#   - 无已知论文将上下文相关的 Bradley-Terry 模型用于多方法争议裁决.

import math
from collections import defaultdict
from typing import Dict, List, Optional, Tuple


class ContextDiscretizer:
    """四维上下文空间量化为网格.

    维度: file_size (log), entropy (linear), has_cfg (binary), stripped (binary).
    网格: 3×3×2×2 = 36 个单元.
    """

    def __init__(self, file_bins: int = 3, entropy_bins: int = 3):
        self.fb = file_bins; self.eb = entropy_bins

    def discretize(self, context: List[float]) -> int:
        """返回网格单元索引 0..35."""
        fs = min(self.fb-1, int(context[0] * self.fb))
        en = min(self.eb-1, int(context[1] * self.eb))
        cfg = 1 if context[4] > 0.5 else 0
        stp = 1 if context[5] > 0.5 else 0
        return ((fs * self.eb + en) * 2 + cfg) * 2 + stp

    @property
    def n_cells(self) -> int:
        return self.fb * self.eb * 2 * 2


class DisputeResolver:
    """上下文相关争议裁决器: Bradley-Terry + 网格统计.

    用法:
      dr = DisputeResolver(method_names=['simhash','minhash','graph','vector'])
      scores = {'simhash':0.92, 'minhash':0.45, 'graph':0.15, 'vector':0.80}
      context = [0.3, 0.7, 0.0, 0.5, 1.0, 0.0]  # 6-d context vector
      resolved = dr.resolve(scores, context)
      dr.feedback(context, winner='simhash', loser='graph')
    """

    def __init__(self, method_names: List[str],
                 prior_strength: float = 5.0,
                 shrinkage_alpha: float = 10.0):
        self.methods = method_names
        self.K = len(method_names)
        self._disc = ContextDiscretizer()
        self._prior = prior_strength
        self._alpha = shrinkage_alpha

        # 全局 Bradley-Terry: 方法对比较计数
        # _wins[i][j] = method_i 被选为优于 method_j 的次数
        self._global_wins: List[List[int]] = [
            [0]*self.K for _ in range(self.K)]
        self._global_theta = [0.0] * self.K

        # 网格单元级统计
        self._cell_wins: Dict[int, List[List[int]]] = {}
        self._cell_theta: Dict[int, List[float]] = {}

    def resolve(self, scores: Dict[str, float],
                context: List[float]) -> Tuple[float, Dict[str, float]]:
        """争议裁决: 返回 (加权分数, {method: trust_weight}).

        权重 = softmax(θ_i) over 方法的可信度评分.
        """
        cell = self._disc.discretize(context)
        theta = self._get_theta(cell)

        # Softmax → weights
        max_theta = max(theta)
        exp_sum = sum(math.exp(t - max_theta) for t in theta)
        weights = {}
        for i, method in enumerate(self.methods):
            weights[method] = math.exp(theta[i] - max_theta) / max(exp_sum, 1e-9)

        # 加权聚合
        weighted = sum(weights.get(m, 0.0) * scores.get(m, 0.0)
                       for m in self.methods)

        return weighted, weights

    def feedback(self, context: List[float],
                  winner: str, loser: str):
        """反馈: 在给定上下文中, winner 方法优于 loser 方法.

        更新全局 + 网格单元的 win/loss 计数, 触发增量 θ 重算.
        """
        wi = self.methods.index(winner)
        li = self.methods.index(loser)

        # 全局更新
        self._global_wins[wi][li] += 1
        self._global_theta = self._bradley_terry_mm(self._global_wins, self._global_theta)

        # 网格单元更新
        cell = self._disc.discretize(context)
        if cell not in self._cell_wins:
            self._cell_wins[cell] = [[0]*self.K for _ in range(self.K)]
            self._cell_theta[cell] = list(self._global_theta)  # 从全局继承
        self._cell_wins[cell][wi][li] += 1
        self._cell_theta[cell] = self._bradley_terry_mm(
            self._cell_wins[cell], self._cell_theta[cell])

    def trust_ranking(self, context: List[float] = None) -> List[Tuple[str, float]]:
        """返回方法可信度排序."""
        if context is not None:
            cell = self._disc.discretize(context)
            theta = self._get_theta(cell)
        else:
            theta = self._global_theta

        ranked = sorted(enumerate(theta), key=lambda x: x[1], reverse=True)
        return [(self.methods[i], round(t, 4)) for i, t in ranked]

    def _get_theta(self, cell: int) -> List[float]:
        """获取网格单元的 θ 估计 (含 Bayesian shrinkage)."""
        local = self._cell_theta.get(cell)
        if local is None:
            return list(self._global_theta)

        wins = self._cell_wins.get(cell)
        n_local = sum(sum(row) for row in wins) if wins else 0

        # Bayesian shrinkage: θ_cell = (n_local·θ_local + α·θ_global)/(n_local+α)
        theta = [0.0] * self.K
        for i in range(self.K):
            theta[i] = (n_local * local[i] + self._alpha * self._global_theta[i]) / \
                       max(n_local + self._alpha, 1)
        return theta

    def _bradley_terry_mm(self, wins: List[List[int]],
                           prev_theta: List[float]) -> List[float]:
        """Bradley-Terry MM 算法: 一轮迭代更新 θ.

        更新公式 (MM algorithm):
          θ_i_new = log(W_i / Σ_{j≠i} (W_ij+W_ji)/(exp(θ_i)+exp(θ_j)))
        其中 W_i = Σ_{j≠i} W_ij (method i 的总胜场).
        """
        K = len(wins)
        theta = list(prev_theta)
        if all(sum(row) == 0 for row in wins):
            return [0.0] * K  # 无数据

        for i in range(K):
            total_wins_i = sum(wins[i])
            if total_wins_i == 0:
                continue

            denominator = 0.0
            for j in range(K):
                if i == j: continue
                n_ij = wins[i][j] + wins[j][i]
                if n_ij > 0:
                    denominator += n_ij / (math.exp(theta[i]) + math.exp(theta[j]))

            if denominator > 1e-9:
                theta[i] = math.log(max(total_wins_i, 1) / denominator)

        # 中心化: 保证 Σ θ_i = 0
        mean_theta = sum(theta) / K
        return [t - mean_theta for t in theta]

    @property
    def stats(self) -> dict:
        return {
            "methods": self.methods,
            "global_trust": dict(zip(self.methods,
                                      [round(t, 4) for t in self._global_theta])),
            "cells_observed": len(self._cell_wins),
            "total_cells": self._disc.n_cells,
            "total_comparisons": sum(sum(row) for row in self._global_wins),
        }


__all__ = ["DisputeResolver", "ContextDiscretizer"]
