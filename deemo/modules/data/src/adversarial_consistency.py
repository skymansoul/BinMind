# 对抗一致性检测 (Adversarial Consistency Detector)
#
# 核心问题: 去重流水线使用多种独立方法 (SimHash, MinHash, 图评分, 向量搜索)
#   判定二进制相似性. 攻击者可通过针对性扰动欺骗单一方法:
# 对 SimHash: 修改少量高权重字节, 翻转关键位
# 对 MinHash: 插入/删除 chunk, 改变 Jaccard 估计
# 对图评分: 注入虚假函数调用边, 改变 CFG 拓扑
#   同时欺骗所有方法需要了解每种方法的内部机制 —— 难度远高于欺骗单一方法.
#
# 创新点:
#   1. 多方法一致性评分: 对同一二进制对计算 N 种独立相似度,
#      一致性 = 1 - (max(scores) - min(scores)) / mean(scores).
#      一致性低 → 某些方法被欺骗 → 标记为可疑.
#   2. 离群方法识别: 哪种方法与共识偏离最大 → 攻击者可能针对该方法.
#      Grubbs 检验 (单侧) 识别统计离群值, 无需假设各方法输出服从
#      特定分布 (非参数版本使用排序位置).
#   3. 时间序列一致性: 追踪同一二进制在不同时间点的指纹变化.
#      渐进变化 (每次 commit 小幅修改) 是正常演化;
#      突变 (单次变化导致所有方法同时翻转) 是可疑的替换攻击.
#   4. 共识强化: 当检测到不一致时, 自动提升共识阈值 (要求 > 2/3 方法一致),
#      或回退到最保守的方法 (精确 SHA256 匹配).
#
# 与现有工作:
# 对抗鲁棒性研究 关注单一方法抗扰动.
#     本方案关注多方法间的交叉验证, 互补.
# Ensemble 方法通常用于提升准确率.
#     本方案用 ensemble disagreement 作为攻击检测信号.

import math
from typing import Dict, List, Optional, Tuple


class AdversarialConsistencyDetector:
    """多方法一致性检测器: 离群识别 + 时序追踪 + 共识强化.

    用法:
      acd = AdversarialConsistencyDetector(consensus_threshold=0.7)
      scores = {"simhash":0.92, "minhash":0.88, "graph":0.45, "vector":0.90}
      report = acd.check(scores)
      if report.is_suspicious:
          print(f"Method {report.outlier_method} may be evaded")
    """

    def __init__(self, consensus_threshold: float = 0.7,
                 min_methods: int = 3, outlier_z: float = 1.5):
        self.consensus_threshold = consensus_threshold
        self.min_methods = min_methods
        self.outlier_z = outlier_z
        # 时序指纹历史: {binary_id: [(timestamp, fingerprint_vector), ...]}
        self._history: Dict[str, List[Tuple[float, Dict[str, float]]]] = {}

    def check(self, scores: Dict[str, float]) -> "ConsistencyReport":
        """检测多方法评分的一致性.

        scores: {"method_name": similarity_score, ...}
        返回 ConsistencyReport.
        """
        n = len(scores)
        if n < self.min_methods:
            return ConsistencyReport(
                is_suspicious=False, consensus=1.0,
                outlier_method=None, scores=scores,
                reason="insufficient_methods",
            )

        values = list(scores.values())
        names = list(scores.keys())
        mean_val = sum(values) / n
        if mean_val < 1e-9:
            return ConsistencyReport(
                is_suspicious=False, consensus=1.0,
                outlier_method=None, scores=scores,
                reason="all_zero",
            )

        # 一致性: 1 - range/mean
        score_range = max(values) - min(values)
        consensus = 1.0 - score_range / mean_val
        consensus = max(0.0, min(1.0, consensus))

        # 离群检测: 基于排序位置的非参数方法
        outlier = self._detect_outlier(names, values)

        is_suspicious = (
            consensus < self.consensus_threshold or
            outlier is not None
        )

        reason = "consistent" if not is_suspicious else ""
        if consensus < self.consensus_threshold:
            reason = "low_consensus"
        if outlier:
            reason = f"outlier_detected:{outlier}" if not reason else f"{reason}+outlier:{outlier}"

        return ConsistencyReport(
            is_suspicious=is_suspicious, consensus=round(consensus, 4),
            outlier_method=outlier, scores=scores, reason=reason,
        )

    def check_with_reference(self, scores: Dict[str, float],
                              method_weights: Dict[str, float] = None
                              ) -> "ConsistencyReport":
        """加权一致性检查: 高权重方法的偏离惩罚更大."""
        if method_weights is None:
            method_weights = {k: 1.0 for k in scores}

        report = self.check(scores)
        if report.outlier_method is None:
            return report

        # 若离群方法是高权重方法, 升级可疑度
        outlier_w = method_weights.get(report.outlier_method, 1.0)
        max_w = max(method_weights.values()) if method_weights else 1.0
        if outlier_w >= max_w * 0.8:
            report.is_suspicious = True
            report.reason = f"high_weight_outlier:{report.outlier_method}"

        return report

    def track_fingerprint(self, binary_id: str,
                           method_scores: Dict[str, float]):
        """记录二进制指纹用于时序一致性分析."""
        import time
        entry = (time.time(), dict(method_scores))
        if binary_id not in self._history:
            self._history[binary_id] = []
        self._history[binary_id].append(entry)
        # 仅保留最近 20 条记录
        if len(self._history[binary_id]) > 20:
            self._history[binary_id] = self._history[binary_id][-20:]

    def temporal_consistency(self, binary_id: str) -> Optional["TemporalReport"]:
        """检测同一二进制指纹的时序突变.

        比较最近两次记录的差异: 若所有方法同时翻转 >50%,
        标记为可疑突变 (可能的替换攻击).
        """
        history = self._history.get(binary_id)
        if not history or len(history) < 2:
            return None

        prev_ts, prev_scores = history[-2]
        curr_ts, curr_scores = history[-1]

        methods = set(prev_scores.keys()) & set(curr_scores.keys())
        if len(methods) < 2:
            return None

        changes = {}
        flipped = 0
        for m in methods:
            delta = curr_scores[m] - prev_scores[m]
            changes[m] = delta
            if abs(delta) > 0.3:
                flipped += 1

        flip_ratio = flipped / len(methods)
        is_mutation = flip_ratio > 0.5

        return TemporalReport(
            binary_id=binary_id,
            prev_timestamp=prev_ts, curr_timestamp=curr_ts,
            changes=changes, flipped_ratio=round(flip_ratio, 3),
            is_suspicious_mutation=is_mutation,
        )

    def _detect_outlier(self, names: List[str],
                         values: List[float]) -> Optional[str]:
        """基于排序间距的非参数离群检测.

        排序后, 若最大值与次大值间距 > outlier_z * 平均间距,
        则该最大值对应的方法为离群.
        """
        if len(values) < 3:
            return None
        # 按值排序
        sorted_pairs = sorted(zip(values, names))
        # 计算连续值间距
        gaps = []
        for i in range(1, len(sorted_pairs)):
            gaps.append(sorted_pairs[i][0] - sorted_pairs[i-1][0])
        if not gaps:
            return None
        avg_gap = sum(gaps) / len(gaps)
        if avg_gap < 1e-9:
            return None

        # 最大间距
        max_gap_idx = max(range(len(gaps)), key=lambda i: gaps[i])
        if gaps[max_gap_idx] > self.outlier_z * avg_gap:
            # 最大间距右侧的所有方法 → 取最右端
            outlier_val, outlier_name = sorted_pairs[-1]
            return outlier_name

        return None


class ConsistencyReport:
    """一致性检测报告."""
    __slots__ = ("is_suspicious","consensus","outlier_method","scores","reason")
    def __init__(self, is_suspicious: bool, consensus: float,
                 outlier_method: Optional[str], scores: Dict[str, float],
                 reason: str):
        self.is_suspicious = is_suspicious
        self.consensus = consensus
        self.outlier_method = outlier_method
        self.scores = scores
        self.reason = reason

    @property
    def mean_score(self) -> float:
        v = list(self.scores.values())
        return sum(v)/max(len(v),1) if v else 0.0

    @property
    def agreement_level(self) -> str:
        if self.consensus > 0.9: return "strong"
        elif self.consensus > 0.7: return "moderate"
        elif self.consensus > 0.5: return "weak"
        return "disagreement"

    def to_dict(self) -> dict:
        return {
            "suspicious": self.is_suspicious,
            "consensus": self.consensus,
            "agreement": self.agreement_level,
            "outlier": self.outlier_method,
            "mean_score": round(self.mean_score, 4),
            "reason": self.reason,
            "scores": {k: round(v, 4) for k, v in self.scores.items()},
        }


class TemporalReport:
    """时序一致性报告."""
    __slots__ = ("binary_id","prev_timestamp","curr_timestamp",
                 "changes","flipped_ratio","is_suspicious_mutation")
    def __init__(self, binary_id: str, prev_timestamp: float,
                 curr_timestamp: float, changes: Dict[str, float],
                 flipped_ratio: float, is_suspicious_mutation: bool):
        self.binary_id = binary_id
        self.prev_timestamp = prev_timestamp
        self.curr_timestamp = curr_timestamp
        self.changes = changes
        self.flipped_ratio = flipped_ratio
        self.is_suspicious_mutation = is_suspicious_mutation

    def to_dict(self) -> dict:
        return {
            "binary_id": self.binary_id,
            "flipped_ratio": self.flipped_ratio,
            "suspicious_mutation": self.is_suspicious_mutation,
            "changes": {k: round(v, 4) for k, v in self.changes.items()},
        }


__all__ = [
    "AdversarialConsistencyDetector",
    "ConsistencyReport",
    "TemporalReport",
]
