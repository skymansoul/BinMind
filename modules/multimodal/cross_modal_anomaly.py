"""
跨模态异常检测 (CMAD) —— 模态间不一致性作为安全信号。

多模态安全分析中, 各模态应对同一威胁产生一致的结论。
当某模态的输出显著偏离其他模态的共识时, 该偏离本身就是信号:
可能是该模态被对抗攻击、数据损坏、或模型退化。

与 cross_modal_hallucination 的差异:
幻觉检测专注于单模态内部的虚构内容 (如 LLM 编造 API 名称);
本模块检测模态间输出分布的结构性偏离 —— 模态 A 说 "恶意",
模态 B 说 "良性", 模态 C 说 "可疑" —— 这种 vote 不一致
在安全决策中需要被显式量化和追踪。

方法: 对每对模态计算其输出分布的 JS 散度, 构建偏离矩阵,
取任意模态与其他所有模态的偏离中位数作为其异常评分。
偏离超过阈值的模态被标记为 "outlier", 在融合时降权或排除。
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple


@dataclass
class ModalitySignal:
    """单个模态的输出信号。"""
    modality_name: str
    label: str                    # 分类标签 (如 "malicious", "benign")
    confidence: float             # 该模态自身的置信度 [0,1]
    embedding: Optional[List[float]] = None  # 可选的嵌入向量
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class AnomalyReport:
    """跨模态异常检测报告。"""
    outlier_modalities: List[str]          # 被标记为异常的模态
    deviation_scores: Dict[str, float]     # 各模态的偏离评分 [0,1]
    pairwise_matrix: Dict[Tuple[str, str], float]  # 两两 JS 散度
    consensus_label: str                   # 排除异常后的共识标签
    consensus_confidence: float            # 共识置信度
    recommendation: str                    # "exclude" | "downweight" | "all_consistent"


class CrossModalAnomalyDetector:
    """
    跨模态异常检测器。

    不依赖模态内部的可信度指标, 纯基于模态间的一致性建模异常。
    这种 "共识即正确" 的假设在高可靠性安全场景中适用:
    对抗攻击通常只能污染单一模态, 无法同时欺骗所有模态。
    """

    def __init__(self, deviation_threshold: float = 0.35):
        self._threshold = deviation_threshold

    def detect(self, signals: List[ModalitySignal]) -> AnomalyReport:
        """
        检测跨模态异常。

        signals: 来自各模态的输出信号列表, 至少需要 2 个模态。
        """
        if len(signals) < 2:
            return AnomalyReport(
                outlier_modalities=[], deviation_scores={},
                pairwise_matrix={}, consensus_label=signals[0].label if signals else "",
                consensus_confidence=0.5, recommendation="all_consistent",
            )

        n = len(signals)
        pairwise: Dict[Tuple[str, str], float] = {}
        deviation_scores: Dict[str, List[float]] = defaultdict(list)

        for i in range(n):
            for j in range(i + 1, n):
                a, b = signals[i], signals[j]
                js = self._js_divergence_labels(a, b)
                pairwise[(a.modality_name, b.modality_name)] = js
                deviation_scores[a.modality_name].append(js)
                deviation_scores[b.modality_name].append(js)

        # 对每个模态, 取其与其他模态的最小偏离 ——
        # 只要与至少一个模态一致, 就不应被标记为异常
        min_dev: Dict[str, float] = {}
        for name, scores in deviation_scores.items():
            min_dev[name] = min(scores) if scores else 0.0

        # 识别异常模态: 与所有其他模态的偏离都超过阈值
        outliers = [
            name for name, score in min_dev.items()
            if score > self._threshold
        ]

        # 排除异常模态后计算共识
        inliers = [s for s in signals if s.modality_name not in outliers]
        if not inliers:
            inliers = signals  # 全部异常时保守回退

        consensus = self._compute_consensus(inliers)

        if not outliers:
            rec = "all_consistent"
        elif len(inliers) >= 2:
            rec = "exclude"
        else:
            rec = "downweight"

        return AnomalyReport(
            outlier_modalities=outliers,
            deviation_scores={k: round(v, 4) for k, v in min_dev.items()},
            pairwise_matrix={k: round(v, 4) for k, v in pairwise.items()},
            consensus_label=consensus[0],
            consensus_confidence=round(consensus[1], 4),
            recommendation=rec,
        )

    def _js_divergence_labels(self, a: ModalitySignal, b: ModalitySignal) -> float:
        """基于标签分布的 JS 散度。如标签不同, 直接取最大散度。"""
        if a.label == b.label:
            # 同标签, 散度由置信度差异决定
            diff = abs(a.confidence - b.confidence)
            return diff / 2.0  # 归一化到 [0, 0.5]
        else:
            # 不同标签, 高散度
            base = 0.5
            # 置信度越高, 冲突越严重
            base += 0.3 * (a.confidence + b.confidence) / 2.0
            return min(1.0, base)

    def _compute_consensus(self, signals: List[ModalitySignal]) -> Tuple[str, float]:
        """加权投票计算共识标签和置信度。"""
        label_votes: Dict[str, float] = defaultdict(float)
        total_weight = 0.0

        for s in signals:
            w = s.confidence
            label_votes[s.label] += w
            total_weight += w

        if total_weight == 0:
            return ("unknown", 0.0)

        ranked = sorted(label_votes.items(), key=lambda x: x[1], reverse=True)
        top_label, top_votes = ranked[0]
        consensus_conf = top_votes / total_weight
        return (top_label, consensus_conf)


__all__ = [
    "ModalitySignal",
    "AnomalyReport",
    "CrossModalAnomalyDetector",
]
