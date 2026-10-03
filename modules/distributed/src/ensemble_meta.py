# 集成元调度器 — 加权多数投票 + 多样性保证的多策略融合
#
# 36 个创新模块提供了丰富的调度策略库。但如何在实际场景中
# 组合它们？单一策略 (如 MixtureOfExperts) 做 soft blending，
# 但可能被一个强但过拟合的策略主导。
#
# 集成方法 (Ensemble) 的核心: 组合多个弱/中策略产生强决策。
# 加权多数投票 (Weighted Majority Algorithm) 的遗憾界:
#   对 K 个专家, 错误数 ≤ (1+ε)·min_i(errors_i) + O(log K / ε)
#   即集成渐近不差于最佳单一策略。
#
# 本模块:
#   1. 维护 K 个调度策略 (专家)
#   2. 每轮各专家产出决策 (任务→机器的分配方案)
#   3. 加权投票: 对每对 (task, machine) 累加专家权重
#   4. 最高分分配当选
#   5. 观测实际 makespan → 更新专家权重 (错者降权)
#   6. 多样性正则: 若两专家高度相关 (决策重叠 > 80%)，其一降权
#      → 鼓励互补策略而非冗余

from __future__ import annotations

import math
import random
from collections import defaultdict
from typing import Optional, List, Dict, Callable, Tuple


class WeightedMajorityEnsemble:
    """加权多数集成 — 多调度策略的投票融合。

    每轮:
      vote(task, machine) = Σ w_k · I[expert_k assigns task→machine]
      w_k: 第 k 个专家的权重 (初始均匀) ∈ [0,1]
    """

    def __init__(self, n_experts: int = 4, epsilon: float = 0.1,
                 diversity_penalty: float = 0.05,
                 seed: Optional[int] = None):
        self._K = n_experts
        self._eps = epsilon
        self._div_penalty = diversity_penalty
        self._rng = random.Random(seed)
        self._weights = [1.0 / n_experts] * n_experts
        self._round: int = 0
        # 追踪每轮各专家的决策 (用于多样性度量)
        self._last_decisions: List[Dict] = [{} for _ in range(n_experts)]

    def aggregate(self, expert_decisions: List[Dict[str, int]],
                  task_ids: List[str],
                  n_machines: int) -> Dict[str, int]:
        """加权多数投票: 对每任务选权重累计最高的机器。

        expert_decisions[k]: {task_id: machine_id}
        返回: 集成决策 {task_id: machine_id}
        """
        self._round += 1
        self._last_decisions = expert_decisions

        result = {}
        for tid in task_ids:
            # 累计各机器的加权票数
            machine_votes = [0.0] * n_machines
            for k, decision in enumerate(expert_decisions):
                if tid in decision:
                    m = decision[tid]
                    if 0 <= m < n_machines:
                        machine_votes[m] += self._weights[k]

            # 最高票当选
            best_m = max(range(n_machines), key=lambda m: machine_votes[m])
            result[tid] = best_m

        return result

    def update_weights(self, expert_losses: List[float]):
        """观测本轮各专家的损失 → 更新权重。

        WMA 规则: w_k ← w_k · (1 - ε)^{loss_k}
        损失大的专家权重指数衰减。
        """
        for k in range(self._K):
            loss = max(0.0, min(1.0, expert_losses[k]))
            self._weights[k] *= (1.0 - self._eps) ** loss

        # 重归一化
        total = sum(self._weights)
        if total > 0:
            self._weights = [w / total for w in self._weights]
        else:
            self._weights = [1.0 / self._K] * self._K

        # 多样性正则: 对高度重叠的专家对降权
        for i in range(self._K):
            for j in range(i + 1, self._K):
                overlap = self._decision_overlap(i, j)
                if overlap > 0.80:
                    # 降权损失较大的那个
                    if expert_losses[i] >= expert_losses[j]:
                        self._weights[i] *= (1.0 - self._div_penalty)
                    else:
                        self._weights[j] *= (1.0 - self._div_penalty)

        total = sum(self._weights)
        if total > 0:
            self._weights = [w / total for w in self._weights]

    def _decision_overlap(self, i: int, j: int) -> float:
        """两专家上一轮决策的 Jaccard 相似度。"""
        di = self._last_decisions[i] if i < len(self._last_decisions) else {}
        dj = self._last_decisions[j] if j < len(self._last_decisions) else {}
        all_keys = set(di.keys()) | set(dj.keys())
        if not all_keys:
            return 0.0
        agree = sum(1 for k in all_keys if di.get(k) == dj.get(k))
        return agree / len(all_keys)

    @property
    def weights(self) -> List[float]:
        return list(self._weights)

    def stats(self) -> dict:
        return {
            "n_experts": self._K,
            "rounds": self._round,
            "weights": [round(w, 4) for w in self._weights],
            "effective_experts": sum(
                1 for w in self._weights if w > 0.05
            ),
            "entropy": round(
                -sum(w * math.log(max(w, 1e-9)) for w in self._weights), 4
            ),
        }
