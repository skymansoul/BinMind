"""
意图分类法自动精化 (ATR)。

现有五分类体系 (static/dynamic/intel/file/unknown) 对所有部署环境
使用统一粒度, 但真实场景中某些类别可能过度聚合或过度细分。

本模块监控分类器的输出分布, 识别:
1. 过度聚合: 类别内置信度分布呈多模态 → 建议拆分
2. 过度细分: 两个类别的分类边界模糊 → 建议合并
3. 冷类别: 某类别长期无请求 → 建议降级

方法:
- 拆分检测: Gaussian KDE + Silverman 带宽 + 峰值计数
- 合并检测: 类别对 JS 散度 EWMA 收敛分析
- 冷检测: 样本计数阈值

与 NSRE (规则提取) 的差异: NSRE 优化规则关键词,
本模块优化分类法结构本身 —— 改变的是类别定义空间。
"""

# File: taxonomy_refine.py  |  2026-08-01 create ATR; 2026-08-04 audit: real KDE impl

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory


@dataclass
class CategoryStats:
    """单个类别的统计信息。"""
    category: IntentCategory
    sample_count: int = 0
    confidence_sum: float = 0.0
    confidence_sq_sum: float = 0.0
    confidences: List[float] = field(default_factory=list)
    last_seen: float = 0.0

    @property
    def mean_confidence(self) -> float:
        return self.confidence_sum / self.sample_count if self.sample_count > 0 else 0.0

    @property
    def variance(self) -> float:
        if self.sample_count < 2:
            return 0.0
        mean = self.mean_confidence
        return self.confidence_sq_sum / self.sample_count - mean * mean

    @property
    def std(self) -> float:
        return math.sqrt(max(0, self.variance))


@dataclass
class RefinementSuggestion:
    """一条分类法精化建议。"""
    action: str  # "split" | "merge" | "demote" | "promote"
    targets: List[IntentCategory]
    reason: str
    confidence: float
    suggested_subcategories: List[str] = field(default_factory=list)


@dataclass
class TaxonomyReport:
    """分类法精化报告。"""
    suggestions: List[RefinementSuggestion]
    category_stats: Dict[IntentCategory, CategoryStats]
    overall_quality: float


class TaxonomyRefiner:
    """
    分类法自动精化器。

    多模态检测:
    使用 Gaussian KDE + Silverman 带宽准则估计置信度分布,
    通过一阶导数符号变化计数检测多峰。若峰值数 ≥ 2 → 建议拆分。

    Silverman 带宽: h = 1.06 * σ * n^(-1/5)
    这是 MSE-最优带宽的一阶近似, 适合近似正态的数据。
    """

    def __init__(
        self,
        min_samples_per_category: int = 20,
        split_std_threshold: float = 0.18,
        merge_js_threshold: float = 0.15,
        kde_grid_points: int = 100,
    ):
        self._stats: Dict[IntentCategory, CategoryStats] = {
            cat: CategoryStats(cat) for cat in IntentCategory
        }
        self._min_samples = min_samples_per_category
        self._split_std = split_std_threshold
        self._merge_js = merge_js_threshold
        self._kde_grid = kde_grid_points
        self._pairwise_js_ewma: Dict[Tuple[IntentCategory, IntentCategory], float] = {}
        self._js_alpha = 0.1

    def feed(self, category: IntentCategory, confidence: float, timestamp: float) -> None:
        st = self._stats[category]
        st.sample_count += 1
        st.confidence_sum += confidence
        st.confidence_sq_sum += confidence * confidence
        st.confidences.append(confidence)
        st.last_seen = timestamp
        if len(st.confidences) > 200:
            st.confidences = st.confidences[-200:]

    def feed_pair(self, cat_a: IntentCategory, cat_b: IntentCategory, js_divergence: float) -> None:
        key = tuple(sorted([cat_a, cat_b], key=lambda c: c.value))
        if key not in self._pairwise_js_ewma:
            self._pairwise_js_ewma[key] = js_divergence
        else:
            self._pairwise_js_ewma[key] = (
                self._js_alpha * js_divergence
                + (1 - self._js_alpha) * self._pairwise_js_ewma[key]
            )

    def analyze(self) -> TaxonomyReport:
        suggestions: List[RefinementSuggestion] = []

        for cat, st in self._stats.items():
            if cat == IntentCategory.UNKNOWN:
                continue
            if st.sample_count < self._min_samples:
                continue
            if st.std > self._split_std:
                subcats = self._suggest_split(cat, st)
                suggestions.append(RefinementSuggestion(
                    action="split",
                    targets=[cat],
                    reason=(
                        f"类别 {cat.value} 内置信度标准差 {st.std:.3f} > "
                        f"阈值 {self._split_std}, 可能存在子类聚集"
                    ),
                    confidence=min(0.9, st.std / 0.30),
                    suggested_subcategories=subcats,
                ))

        for (cat_a, cat_b), js_ewma in self._pairwise_js_ewma.items():
            if js_ewma < self._merge_js:
                st_a = self._stats[cat_a]
                st_b = self._stats[cat_b]
                if min(st_a.sample_count, st_b.sample_count) >= self._min_samples:
                    suggestions.append(RefinementSuggestion(
                        action="merge",
                        targets=[cat_a, cat_b],
                        reason=(
                            f"类别 {cat_a.value} 与 {cat_b.value} 的 "
                            f"JS 散度 EWMA={js_ewma:.4f} < {self._merge_js}"
                        ),
                        confidence=1.0 - js_ewma / self._merge_js,
                    ))

        max_last_seen = max((s.last_seen for s in self._stats.values()), default=0.0)
        for cat, st in self._stats.items():
            if cat == IntentCategory.UNKNOWN:
                continue
            if st.sample_count < 3 and max_last_seen > 0:
                suggestions.append(RefinementSuggestion(
                    action="demote",
                    targets=[cat],
                    reason=f"类别 {cat.value} 仅 {st.sample_count} 条样本",
                    confidence=0.7,
                ))

        non_unknown = [s for c, s in self._stats.items() if c != IntentCategory.UNKNOWN]
        total_samples = sum(s.sample_count for s in non_unknown)
        n_cats = max(1, len(non_unknown))
        coverage_score = min(1.0, (total_samples / n_cats) / 50.0)
        avg_variance = sum(s.variance for s in non_unknown) / n_cats
        variance_penalty = min(1.0, avg_variance / 0.05)
        overall = 0.6 * coverage_score + 0.4 * (1.0 - variance_penalty)

        return TaxonomyReport(
            suggestions=suggestions,
            category_stats=dict(self._stats),
            overall_quality=round(overall, 4),
        )

    # ------------------------------------------------------------------
    # Gaussian KDE + Silverman 带宽 + 峰值检测
    # ------------------------------------------------------------------

    @staticmethod
    def _silverman_bandwidth(data: List[float]) -> float:
        """Silverman 规则: h = 1.06 * σ * n^(-1/5)。"""
        n = len(data)
        if n < 2:
            return 0.05
        mean = sum(data) / n
        var = sum((x - mean) ** 2 for x in data) / (n - 1)
        sigma = math.sqrt(max(1e-6, var))
        return 1.06 * sigma * (n ** (-0.2))

    @staticmethod
    def _gaussian_kernel(u: float) -> float:
        return math.exp(-0.5 * u * u) / math.sqrt(2 * math.pi)

    def _kde_estimate(self, data: List[float], h: float) -> Tuple[List[float], List[float]]:
        """在 [min, max] 区间上计算 KDE, 返回 (grid_points, density_values)。"""
        if not data or h <= 0:
            return [0.0, 1.0], [0.0, 0.0]
        lo, hi = min(data), max(data)
        margin = 0.1 * (hi - lo) if hi > lo else 0.05
        lo -= margin
        hi += margin
        n_points = self._kde_grid
        grid = [lo + (hi - lo) * i / (n_points - 1) for i in range(n_points)]
        n = len(data)
        density = []
        for x in grid:
            d = sum(self._gaussian_kernel((x - xi) / h) for xi in data)
            d /= (n * h)
            density.append(d)
        return grid, density

    @staticmethod
    def _count_peaks(grid: List[float], density: List[float]) -> int:
        """通过一阶导数符号变化计数峰值: + → − 为一个峰值。"""
        if len(density) < 3:
            return 1
        peaks = 0
        for i in range(1, len(density) - 1):
            left = density[i] - density[i - 1]
            right = density[i + 1] - density[i]
            if left > 0 and right < 0:
                peaks += 1
        return max(1, peaks)

    def _suggest_split(self, category: IntentCategory, st: CategoryStats) -> List[str]:
        """
        Gaussian KDE + Silverman 带宽 → 峰值检测 → 子类别建议。

        仅当 KDE 显示 ≥ 2 个显著峰值时建议拆分。
        子类别命名依据峰值位置 (低置信度峰 → 边界模糊子类,
        高置信度峰 → 明确识别子类)。
        """
        if not st.confidences or len(st.confidences) < 10:
            return []
        h = self._silverman_bandwidth(st.confidences)
        grid, density = self._kde_estimate(st.confidences, h)
        n_peaks = self._count_peaks(grid, density)

        if n_peaks < 2:
            return []

        # 找峰值对应的置信度位置
        peak_positions: List[float] = []
        for i in range(1, len(density) - 1):
            if density[i] - density[i - 1] > 0 and density[i + 1] - density[i] < 0:
                peak_positions.append(grid[i])

        subcats: List[str] = []
        base = category.value
        for i, pos in enumerate(peak_positions[:3]):
            if pos > 0.7:
                subcats.append(f"{base}_high_conf")
            elif pos > 0.4:
                subcats.append(f"{base}_mid_conf")
            else:
                subcats.append(f"{base}_low_conf")

        return subcats

    def reset(self) -> None:
        self._stats = {cat: CategoryStats(cat) for cat in IntentCategory}
        self._pairwise_js_ewma.clear()


__all__ = [
    "CategoryStats",
    "RefinementSuggestion",
    "TaxonomyReport",
    "TaxonomyRefiner",
]
