"""
模态预算优化器 (MBO)。

多模态分析中并非模态越多越好 —— 每个模态消耗不同的计算资源
(静态分析 < 动态trace < 符号执行 < LLM推理), 且边际信息增益递减。
在给定的计算/时间预算下, 如何选择最优模态子集是本模块解决的问题。

与 info_collection 的 BanditCollectorRouter 的结构类比:
- 模态 = 采集器 (arm)
- 信息增益 = 奖励
- 计算成本 = 成本
- 选择算法: 贪心增益/成本比 + 上限约束

差异: BCR 面向采集器选择的在线探索-利用平衡;
MBO 面向模态选择的静态组合优化 —— 模态成本相对稳定,
更接近 0/1 背包问题的变体而非 Bandit 问题。
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ModalityProfile:
    """模态画像: 成本、可靠性、历史贡献。"""
    name: str
    cost: float = 1.0             # 归一化计算成本 [1, 10]
    reliability: float = 0.8      # 该模态的历史准确率
    info_gain_avg: float = 0.5    # 平均信息增益 (来自历史)
    activations: int = 0          # 历史激活次数
    useful_count: int = 0         # 产生有用结果的次数

    @property
    def gain_cost_ratio(self) -> float:
        return self.info_gain_avg / max(0.1, self.cost)

    @property
    def useful_rate(self) -> float:
        return self.useful_count / max(1, self.activations)


@dataclass
class BudgetPlan:
    """预算分配方案。"""
    selected_modalities: List[str]
    excluded_modalities: List[str]
    total_cost: float
    total_gain: float
    budget_used_ratio: float    # 预算使用率
    remaining_budget: float


# 各模态类型的默认成本 —— 反映不同分析方法的相对资源消耗

_DEFAULT_PROFILES: Dict[str, ModalityProfile] = {
    "static_analysis": ModalityProfile("static_analysis", cost=1.5, reliability=0.85, info_gain_avg=0.55),
    "dynamic_trace": ModalityProfile("dynamic_trace", cost=4.0, reliability=0.70, info_gain_avg=0.65),
    "symbolic_execution": ModalityProfile("symbolic_execution", cost=6.0, reliability=0.75, info_gain_avg=0.70),
    "llm_analysis": ModalityProfile("llm_analysis", cost=8.0, reliability=0.80, info_gain_avg=0.75),
    "network_signature": ModalityProfile("network_signature", cost=2.0, reliability=0.90, info_gain_avg=0.50),
    "binary_features": ModalityProfile("binary_features", cost=3.0, reliability=0.88, info_gain_avg=0.60),
    "sandbox_behavior": ModalityProfile("sandbox_behavior", cost=7.0, reliability=0.65, info_gain_avg=0.72),
    "human_feedback": ModalityProfile("human_feedback", cost=10.0, reliability=0.95, info_gain_avg=0.90),
}


class ModalBudgetOptimizer:
    """
    模态预算优化器。

    贪心选择: 按 gain/cost 比值降序, 在预算内选取。
    此贪心策略对 0/1 背包问题是近似最优的 (当 gain/cost 比值排序后),
    且 O(n log n) 的复杂度适合实时决策场景。
    """

    def __init__(
        self,
        profiles: Optional[Dict[str, ModalityProfile]] = None,
        default_budget: float = 15.0,
    ):
        self._profiles = profiles or _DEFAULT_PROFILES
        self._default_budget = default_budget
        self._history: List[Tuple[str, bool, float]] = []
        # (modality_name, was_useful, observed_gain)

    def register(self, name: str, cost: float, reliability: float = 0.8) -> None:
        if name not in self._profiles:
            self._profiles[name] = ModalityProfile(name=name, cost=cost, reliability=reliability)

    def optimize(
        self,
        budget: Optional[float] = None,
        mandatory: Optional[Set[str]] = None,
        excluded: Optional[Set[str]] = None,
    ) -> BudgetPlan:
        """
        在给定预算下选择最优模态子集。

        mandatory: 强制包含的模态 (不计入预算优化, 但消耗预算)
        excluded: 强制排除的模态
        """
        budget = budget or self._default_budget
        mandatory = mandatory or set()
        excluded = excluded or set()

        remaining = budget
        selected: List[str] = []
        excluded_final: List[str] = []

        # 强制模态先分配预算
        for name in mandatory:
            if name in self._profiles:
                remaining -= self._profiles[name].cost
                selected.append(name)

        # 候选模态按 gain/cost 排序
        candidates = [
            (name, p) for name, p in self._profiles.items()
            if name not in mandatory and name not in excluded
        ]
        candidates.sort(key=lambda x: x[1].gain_cost_ratio, reverse=True)

        for name, profile in candidates:
            if profile.cost <= remaining + 0.001:
                remaining -= profile.cost
                selected.append(name)
            else:
                excluded_final.append(name)

        total_cost = budget - remaining
        total_gain = sum(
            self._profiles[n].info_gain_avg * self._profiles[n].reliability
            for n in selected
        )

        return BudgetPlan(
            selected_modalities=selected,
            excluded_modalities=[n for n, _ in candidates if n in excluded_final],
            total_cost=round(total_cost, 2),
            total_gain=round(total_gain, 4),
            budget_used_ratio=round(total_cost / budget, 4) if budget > 0 else 0.0,
            remaining_budget=round(remaining, 2),
        )

    def observe(self, modality_name: str, useful: bool, observed_gain: float = 0.0) -> None:
        """记录模态的实际表现, 更新画像。"""
        p = self._profiles.get(modality_name)
        if p is None:
            return
        p.activations += 1
        if useful:
            p.useful_count += 1
        # 指数滑动平均更新增益估计
        alpha = 0.15
        p.info_gain_avg = alpha * observed_gain + (1 - alpha) * p.info_gain_avg
        # 可靠性同样用 EMA 更新
        p.reliability = alpha * (1.0 if useful else 0.0) + (1 - alpha) * p.reliability
        self._history.append((modality_name, useful, observed_gain))

    def get_profile(self, name: str) -> Optional[ModalityProfile]:
        return self._profiles.get(name)

    def list_profiles(self) -> List[ModalityProfile]:
        return sorted(
            self._profiles.values(),
            key=lambda p: p.gain_cost_ratio, reverse=True,
        )

    def reset(self) -> None:
        self._profiles = dict(_DEFAULT_PROFILES)
        self._history.clear()


__all__ = [
    "ModalityProfile",
    "BudgetPlan",
    "ModalBudgetOptimizer",
]
