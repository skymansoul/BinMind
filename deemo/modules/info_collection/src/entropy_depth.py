"""
熵引导的自适应采集深度控制器 (EGACD)。

背景: 安全采集的深度参数 (shallow/standard/deep/exhaustive) 传统上
由用户静态指定或在配置中硬编码。这导致两类资源错配:
  · 浅层采集在信息密度高的类别 (INTEL_CORRELATION) 过早终止, 丢失关键关联
  · 深层采集在信息密度低的类别 (FILE_ANALYSIS) 过度展开, 收集大量重复数据

机制: 将采集过程建模为序贯信息获取。每阶段完成后计算类别条件熵
(category-conditional entropy) 的当前值及投影值, 边际增益低于自适应阈值
时终止当前深度。阈值按意图类别差异化 —— 情报关联的长尾分布需要更小的
终止阈值以允许更深展开。

与 AutoML 早停的差异: 早停基于全局损失函数的梯度消失;
本方法基于特定意图域的类别条件熵饱和度, 且阈值由经验 profile 驱动
而非全局超参数。
"""

from __future__ import annotations

import math
from collections import Counter
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from .intent_route import IntentCategory


class DepthLevel(Enum):
    """采集深度级别。"""
    SHALLOW = 0     # 仅元数据 / 摘要
    STANDARD = 1    # 结构化数据全量
    DEEP = 2        # 关联展开 + 递归子项
    EXHAUSTIVE = 3  # 所有可达引用 + 多源交叉验证


@dataclass
class DepthDecision:
    """单步深度决策。"""
    current_depth: DepthLevel
    next_depth: DepthLevel
    entropy_current: float
    entropy_projected: float
    marginal_gain: float
    threshold: float
    terminate: bool = False
    reason: str = ""


@dataclass
class CollectionState:
    """采集状态快照, 用于熵值计算。"""
    category: IntentCategory
    items_collected: int = 0
    unique_keys: int = 0
    duplicate_keys: int = 0
    null_results: int = 0
    error_results: int = 0
    field_coverage: Dict[str, float] = field(default_factory=dict)

    @property
    def total_attempts(self) -> int:
        return self.items_collected + self.null_results + self.error_results

    @property
    def uniqueness_ratio(self) -> float:
        """唯一键占比, 1.0 表示无重复, 趋近 0 表示高度冗余。"""
        if self.items_collected <= 0:
            return 0.0
        return self.unique_keys / self.items_collected

    @property
    def error_rate(self) -> float:
        if self.total_attempts <= 0:
            return 0.0
        return self.error_results / self.total_attempts


# 类别条件熵的基准参数
# 不同意图类别的信息密度差异显著:
# FILE_ANALYSIS: 文件结构层次分明, 浅层即可获取大量结构化信息
#   - INTEL_CORRELATION: 情报关联具有长尾分布, 深层展开收益递减更慢
#   - STATIC_COLLECTION: 主机信息采集通常在 standard 深度触及饱和
# 以下参数通过经验数据估计, 可按需校准。

_CATEGORY_ENTROPY_PROFILES: Dict[IntentCategory, Dict[str, float]] = {
    IntentCategory.STATIC_COLLECTION: {
        "base_entropy": 3.2,       # 初始熵估计 (bits)
        "decay_rate": 0.55,        # 每深度级别熵衰减率
        "saturation_threshold": 0.12,  # 边际增益低于此值视为饱和
        "error_penalty": 1.5,      # 错误率的熵惩罚系数
    },
    IntentCategory.DYNAMIC_INTERACTION: {
        "base_entropy": 4.5,
        "decay_rate": 0.40,
        "saturation_threshold": 0.18,
        "error_penalty": 2.0,      # 动态交互的失败代价更高
    },
    IntentCategory.INTEL_CORRELATION: {
        "base_entropy": 5.8,
        "decay_rate": 0.30,        # 情报关联信息量衰减最慢
        "saturation_threshold": 0.08,
        "error_penalty": 1.2,
    },
    IntentCategory.FILE_ANALYSIS: {
        "base_entropy": 2.8,
        "decay_rate": 0.65,
        "saturation_threshold": 0.10,
        "error_penalty": 1.0,
    },
    IntentCategory.UNKNOWN: {
        "base_entropy": 6.0,       # 未知类别保守估计高熵
        "decay_rate": 0.25,
        "saturation_threshold": 0.15,
        "error_penalty": 1.0,
    },
}


class EntropyDepthController:
    """
    熵引导深度控制器。

    工作流:
    1. 接收当前采集状态快照
    2. 计算类别条件熵与边际信息增益
    3. 与自适应阈值比较, 输出深度决策
    4. 对 INTEL_CORRELATION 和 DYNAMIC_INTERACTION 类别,
       阈值的自适应幅度更大, 反映其信息密度变化范围更宽。
    """

    def __init__(
        self,
        profiles: Optional[Dict[IntentCategory, Dict[str, float]]] = None,
    ):
        self._profiles = profiles or _CATEGORY_ENTROPY_PROFILES

    def _estimate_entropy(self, state: CollectionState) -> float:
        """
        从采集状态估计当前熵值。

        算法: 以类别基准熵为起点, 按已观测的唯一性和覆盖率衰减。
        唯一性高 → 仍在发现新信息 → 熵降低缓慢。
        唯一性低 → 信息冗余 → 熵快速衰减。
        """
        profile = self._profiles.get(
            state.category,
            _CATEGORY_ENTROPY_PROFILES[IntentCategory.UNKNOWN],
        )
        base = profile["base_entropy"]
        decay = profile["decay_rate"]

        u = state.uniqueness_ratio
        # 使用指数衰减: entropy = base * exp(-decay * items * uniqueness)
        # 唯一性高时, items 的衰减效应被部分抵消
        decay_factor = decay * max(1, state.items_collected) * (u + 0.1)
        entropy = base * math.exp(-decay_factor)

        if state.field_coverage:
            avg_coverage = sum(state.field_coverage.values()) / len(state.field_coverage)
            coverage_penalty = (1.0 - avg_coverage) * 0.5
            entropy *= (1.0 + coverage_penalty)

        penalty = profile.get("error_penalty", 1.0)
        entropy *= (1.0 + state.error_rate * penalty)

        return max(0.01, entropy)

    def _project_entropy(self, state: CollectionState, depth: DepthLevel) -> float:
        """
        投影到指定深度的熵值估计。

        深度每增加一级, 预期熵值按衰减率降低。
        SHALLOW → STANDARD → DEEP → EXHAUSTIVE, 衰减累乘。
        """
        profile = self._profiles.get(
            state.category,
            _CATEGORY_ENTROPY_PROFILES[IntentCategory.UNKNOWN],
        )
        decay = profile["decay_rate"]
        current_entropy = self._estimate_entropy(state)
        steps = depth.value
        projected = current_entropy * (decay ** steps)
        return max(0.005, projected)

    def decide(
        self,
        state: CollectionState,
        current_depth: DepthLevel = DepthLevel.STANDARD,
        min_items: int = 3,
    ) -> DepthDecision:
        """
        输出深度调整决策。

        min_items: 最少采集条目数, 低于此值不触发加深 (样本不足无法可靠估计熵)。
        """
        profile = self._profiles.get(
            state.category,
            _CATEGORY_ENTROPY_PROFILES[IntentCategory.UNKNOWN],
        )
        threshold = profile["saturation_threshold"]

        entropy_current = self._estimate_entropy(state)

        # 考察下一深度级别的投影熵
        next_levels: List[Tuple[DepthLevel, str]] = []
        if current_depth == DepthLevel.SHALLOW:
            next_levels = [
                (DepthLevel.STANDARD, "升入标准深度"),
                (DepthLevel.DEEP, "跳升深层采集"),
            ]
        elif current_depth == DepthLevel.STANDARD:
            next_levels = [
                (DepthLevel.DEEP, "升入深层采集"),
                (DepthLevel.SHALLOW, "降为浅层采集"),
            ]
        elif current_depth == DepthLevel.DEEP:
            next_levels = [
                (DepthLevel.EXHAUSTIVE, "升入穷举采集"),
                (DepthLevel.STANDARD, "降为标准深度"),
            ]
        else:  # EXHAUSTIVE
            next_levels = [
                (DepthLevel.DEEP, "降为深层采集"),
                (DepthLevel.STANDARD, "降为标准深度"),
            ]

        best_decision = DepthDecision(
            current_depth=current_depth,
            next_depth=current_depth,
            entropy_current=entropy_current,
            entropy_projected=entropy_current,
            marginal_gain=0.0,
            threshold=threshold,
            terminate=True,
            reason="已达穷举深度, 无更高级别可升",
        )

        for next_depth, label in next_levels:
            entropy_projected = self._project_entropy(state, next_depth)
            marginal_gain = entropy_current - entropy_projected

            if next_depth.value > current_depth.value:
                # 加深决策: 增益需超过阈值 且 样本量充足
                if state.items_collected < min_items:
                    continue
                if marginal_gain > threshold:
                    best_decision = DepthDecision(
                        current_depth=current_depth,
                        next_depth=next_depth,
                        entropy_current=entropy_current,
                        entropy_projected=entropy_projected,
                        marginal_gain=marginal_gain,
                        threshold=threshold,
                        reason=f"{label}: 边际增益 {marginal_gain:.4f} > 阈值 {threshold:.4f}",
                    )
                    break
                else:
                    best_decision = DepthDecision(
                        current_depth=current_depth,
                        next_depth=current_depth,
                        entropy_current=entropy_current,
                        entropy_projected=entropy_projected,
                        marginal_gain=marginal_gain,
                        threshold=threshold,
                        terminate=True,
                        reason=f"饱和终止: 边际增益 {marginal_gain:.4f} ≤ 阈值 {threshold:.4f}",
                    )
            else:
                # 降级决策: 增益过低且当前深度过量
                if marginal_gain < threshold * 0.3 and state.items_collected >= min_items:
                    best_decision = DepthDecision(
                        current_depth=current_depth,
                        next_depth=next_depth,
                        entropy_current=entropy_current,
                        entropy_projected=entropy_projected,
                        marginal_gain=marginal_gain,
                        threshold=threshold,
                        reason=f"{label}: 边际增益过低 {marginal_gain:.4f}",
                    )
                    break

        return best_decision

    def should_continue(self, state: CollectionState, depth: DepthLevel) -> bool:
        """快速检查: 当前深度下是否应继续采集。"""
        decision = self.decide(state, depth)
        return not decision.terminate


__all__ = [
    "DepthLevel",
    "DepthDecision",
    "CollectionState",
    "EntropyDepthController",
]
