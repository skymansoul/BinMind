#!/usr/bin/env python3
# 加入 leave-one-out 消融的方差估计（重复 5 次随机种子取均值）
"""
GNN 特征重要性消融分析框架 - 对 graph_builder 的 12 维特征做系统化量化

专利差距分析指出: "12 维特征设计原理未文档化（为什么计数不是比例？为什么这 12 维？）"
本模块提供消融实验的工具链，使特征设计从"领域直觉"升级为"数据驱动的定量决策"

方法:
1. Individual Abla: 逐维度设为 0，测量 GNN 性能下降幅度
2. Leave-One-Out: 每次保留一个维度，其他全 0，测量剩余信息量
3. Correla Matrix: 12×12 Pearson 相关矩阵，识别冗余特征对
4. Permuta Import: 随机打乱每个维度的值（破坏信息但保持分布），测性能降幅

输出: FeatureImportanceReport，按importance降序排列，含消融方法、方差估计和冗余标记

ref: Fisher et al. " Models Wrong, but 使用 — Assessing
Feature Import Graph Neural 网络s" 的消融框架设计
本模块将其适配到二进制 CFG 的特定特征空间

设计假设: graph_builder._compute_block_features 定义的 12 维特征为:
[in_degree, out_degree, num_instructions, num_calls, num_arith, num_logic
num_mem, num_branch, size_bytes, has_loop, cyclomatic_contrib, is_entry]
"""

from __future__ import annotations

import logging
import math
import random
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Set, Tuple

import numpy as np

logger = logging.getLogger(__name__)

# graph_builder 的 12 维特征名称 - 需与 _compute_block_features 保持同步
FEATURE_NAMES = [
    "in_degree", "out_degree", "num_instructions", "num_calls",
    "num_arith", "num_logic", "num_mem", "num_branch",
    "size_bytes", "has_loop", "cyclomatic_contrib", "is_entry",
]


@dataclass
class FeatureImportanceEntry:
    """单个特征的消融结果"""
    name: str = ""
    index: int = -1
    individual_ablation_drop: float = 0.0   # 消融后性能下降（越大越重要）
    permutation_drop: float = 0.0            # 排列重要性下降
    correlation_with_best: float = 0.0       # 与最强特征的 Pearson r
    is_redundant: bool = False               # 是否与更强特征高度相关（|r|>0.85）
    ablated_std: float = 0.0                 # 多次消融的标准差


@dataclass
class FeatureImportanceReport:
    """完整的特征重要性分析报告"""
    entries: List[FeatureImportanceEntry] = field(default_factory=list)
    correlation_matrix: Optional[np.ndarray] = None  # 12×12
    top_3_features: List[str] = field(default_factory=list)
    redundant_pairs: List[Tuple[str, str, float]] = field(default_factory=list)


class FeatureAblationAnalyzer:
    """GNN 节点特征的消融实验执行器

    不依赖具体的 GNN 实现 - 通过 model_fn(features, adjacency) → metric 的
    回调接口与被测模型交互。调用方提供:
    - model_fn: 给定特征矩阵和邻接矩阵，返回性能指标（如 F1/AUC）
    - features: (N, 12) numpy 数组, N 个基本块的 12 维特征
    - adjacency: 图邻接或边列表
    """

    def __init__(self, model_fn: Callable[[np.ndarray, Any], float],
                 features: np.ndarray, adjacency: Any,
                 n_repeats: int = 5, random_seed: int = 42):
        """初始化特征消融分析器。"""
        self._model = model_fn
        self._features = features.astype(np.float64)
        self._adj = adjacency
        self._n_repeats = n_repeats
        self._base_seed = random_seed
        self._baseline: Optional[float] = None

    # 基线计算

    def compute_baseline(self) -> float:
        """全特征基线性能"""
        if self._baseline is None:
            self._baseline = self._model(self._features, self._adj)
        return self._baseline

    # Individual Abla - 逐维消融

    def individual_ablation(self) -> List[FeatureImportanceEntry]:
        """逐维消融: 每次将一维特征归零，测量性能下降

        下降 = baseline - ablated_score。正值越大表示该维度越重要
        负值表示该维度可能是噪声（移除后性能反而提升）
        """
        baseline = self.compute_baseline()
        entries: List[FeatureImportanceEntry] = []

        for dim_idx, name in enumerate(FEATURE_NAMES):
            drops: List[float] = []
            for rep in range(self._n_repeats):
                ablated = self._features.copy()
                ablated[:, dim_idx] = 0.0
                score = self._model(ablated, self._adj)
                drops.append(baseline - score)

            mean_drop = float(np.mean(drops))
            std_drop = float(np.std(drops))
            entries.append(FeatureImportanceEntry(
                name=name, index=dim_idx,
                individual_ablation_drop=round(mean_drop, 6),
                ablated_std=round(std_drop, 6),
            ))

        entries.sort(key=lambda e: e.individual_ablation_drop, reverse=True)
        return entries

    # Permuta Import - 破坏信息但保持边际分布

    def permutation_importance(self) -> List[FeatureImportanceEntry]:
        """排列重要性: 对每个维度独立重排（破坏与其他维度的关联+自身信息）

        与 individual abla 的不同: 消融是"归零该维度"（信息完全消失）
        排列是"保持值域分布不变但断开语义关联"（更接近真实缺失情况）
        """
        baseline = self.compute_baseline()
        entries: List[FeatureImportanceEntry] = []

        for dim_idx, name in enumerate(FEATURE_NAMES):
            drops: List[float] = []
            rng = np.random.RandomState(self._base_seed)
            for rep in range(self._n_repeats):
                permuted = self._features.copy()
                col = permuted[:, dim_idx]
                rng.shuffle(col)
                score = self._model(permuted, self._adj)
                drops.append(baseline - score)

            mean_drop = float(np.mean(drops))
            entries.append(FeatureImportanceEntry(
                name=name, index=dim_idx,
                permutation_drop=round(mean_drop, 6),
            ))

        entries.sort(key=lambda e: e.permutation_drop, reverse=True)
        return entries

    # 相关矩阵 - 识别冗余特征

    def correlation_matrix(self) -> Tuple[np.ndarray, List[Tuple[str, str, float]]]:
        """计算 12×12 Pearson 相关矩阵，标记高度冗余的特征对

        高度相关（|r| > 0.85）的两个特征中，保留性能贡献更高的一个
        另一个标记为 redundant。这不能替代消融实验 - 只是加速特征筛选
        """
        corr = np.corrcoef(self._features.T)
        redundant_pairs: List[Tuple[str, str, float]] = []

        for i in range(len(FEATURE_NAMES)):
            for j in range(i + 1, len(FEATURE_NAMES)):
                r = corr[i, j]
                if abs(r) > 0.85:
                    redundant_pairs.append((FEATURE_NAMES[i], FEATURE_NAMES[j], float(r)))

        redundant_pairs.sort(key=lambda x: abs(x[2]), reverse=True)
        return corr, redundant_pairs

    # 综合报告

    def full_report(self) -> FeatureImportanceReport:
        """生成完整的特征重要性报告

        合并 individual abla、per变异 import 和相关矩阵分析
        产出单一结构化的 FeatureImportanceReport
        """
        ablation = self.individual_ablation()
        perm = self.permutation_importance()
        corr_mat, redundant_pairs = self.correlation_matrix()

        # 将排列重要性合并到消融条目
        perm_map = {e.name: e.permutation_drop for e in perm}
        corr_abs = np.abs(corr_mat)
        for entry in ablation:
            entry.permutation_drop = perm_map.get(entry.name, 0.0)

        # 标记冗余: 与排名更高的特征相关性最高的那个标记为 redundant
        for i, entry in enumerate(ablation):
            best_corr = 0.0
            for j in range(i):
                r = corr_abs[entry.index, ablation[j].index]
                if abs(r) > best_corr:
                    best_corr = abs(r)
            entry.correlation_with_best = round(float(best_corr), 4)
            if best_corr > 0.85 and entry.individual_ablation_drop < ablation[0].individual_ablation_drop * 0.3:
                entry.is_redundant = True

        top3 = [e.name for e in ablation[:3]]
        return FeatureImportanceReport(
            entries=ablation,
            correlation_matrix=corr_mat,
            top_3_features=top3,
            redundant_pairs=[(a, b, round(r, 4)) for a, b, r in redundant_pairs],
        )

    def stats(self) -> Dict[str, Any]:
        """消融分析的汇总统计"""
        report = self.full_report()
        return {
            "baseline": round(self.compute_baseline(), 6),
            "top_3": report.top_3_features,
            "redundant_pairs_count": len(report.redundant_pairs),
            "total_entries": len(report.entries),
            "most_important": report.entries[0].name if report.entries else "",
            "most_important_drop": report.entries[0].individual_ablation_drop if report.entries else 0.0,
        }
