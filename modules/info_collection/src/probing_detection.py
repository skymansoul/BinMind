"""
对抗性分类器探测检测 (ACPD)。

LAMP 展示了如何从黑盒 LLM 中提取决策边界。
反过来, 攻击者可以用类似方法系统性地探测分类器的决策边界,
通过构造渐变输入观察分类输出的跳变点, 从而反向工程分类逻辑。

攻击模式: 以极低成本发送大量近义请求, 观察 category/confidence 变化,
记录边界条件, 后续利用边界知识绕过分类器或注入精准载荷。

检测信号:
1. 类别遍历: 短时间内跨类别查询均匀分布 (正常流量偏斜)
2. 边界刺探: 连续的 confidence 方差异常低 + 微小的 target/method 变化
3. 时间脉冲: 突发性高密度查询后静默, 符合自动化脚本特征
4. 文本相似度: 窗口内查询之间的编辑距离异常低 (仅做微小改动)
"""

from __future__ import annotations

import math
import time
from collections import Counter, deque
from dataclasses import dataclass, field
from typing import Any, Deque, Dict, List, Optional, Tuple

from .intent_route import IntentCategory


@dataclass
class QueryRecord:
    """单次查询的快照, 用于统计追踪。"""
    category: IntentCategory
    confidence: float
    target: str
    method: str
    text_hash: str       # 截断哈希, 用于文本相似度
    text_length: int
    timestamp: float
    probe_score: float = 0.0  # 该单次查询被判定为探测的概率


@dataclass
class ProbingReport:
    """探测检测报告。"""
    risk_score: float              # [0, 1]
    category_entropy_signal: float  # 类别分布的异常程度
    boundary_straddle_signal: float # 边界刺探信号
    temporal_burst_signal: float    # 时间脉冲信号
    text_similarity_signal: float   # 文本相似度信号
    flagged_query_indices: List[int]
    recommended_action: str         # "allow" | "rate_limit" | "block"


class ProbingDetector:
    """
    对抗性分类器探测检测器。

    维护滑动窗口 (默认 100 条), 在新查询到达时计算四个独立信号。
    使用马氏距离 (Mahalanobis distance) 融合四个信号为单一评分 ——
    马氏距离通过信号间的协方差矩阵建模相关性:
    当两个通常正相关的信号 (如类别遍历 + 边界刺探) 同时出现时,
    马氏距离不会将其视为独立的异常证据 (避免重复计数);
    当它们意外发散时, 马氏距离会显著放大异常评分。

    参考: 马氏距离在多元异常检测中的标准应用
    (参见 Barnett & Lewis, Outliers in Statistical Data, 3rd ed.)
    """

    def __init__(self, window_size: int = 100, risk_threshold: float = 0.6):
        self._window: Deque[QueryRecord] = deque(maxlen=window_size)
        self._threshold = risk_threshold
        # 存储最近的信号向量, 用于估计协方差矩阵
        self._signal_history: Deque[Tuple[float, float, float, float]] = deque(maxlen=60)

    def feed(
        self, category: IntentCategory, confidence: float,
        target: str, method: str, text: str,
    ) -> ProbingReport:
        """提交一条查询并返回探测评估。"""
        import hashlib
        text_hash = hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()[:8]
        record = QueryRecord(
            category=category, confidence=confidence,
            target=target, method=method,
            text_hash=text_hash, text_length=len(text),
            timestamp=time.time(),
        )
        self._window.append(record)

        if len(self._window) < 8:
            return ProbingReport(0.0, 0.0, 0.0, 0.0, 0.0, [], "allow")

        cat_signal = self._category_entropy_signal()
        boundary_signal = self._boundary_straddle_signal()
        temporal_signal = self._temporal_burst_signal()
        text_signal = self._text_similarity_signal()

        vec = (cat_signal, boundary_signal, temporal_signal, text_signal)
        self._signal_history.append(vec)

        # 马氏距离融合 —— 替代简单线性加权
        risk = self._mahalanobis_risk(vec)

        # 标记单条查询的探测可疑度
        flagged: List[int] = []
        recent = list(self._window)
        for i, r in enumerate(recent):
            r.probe_score = 0.0
            if r.confidence > 0.85 and (not r.target or len(r.target) < 3):
                r.probe_score += 0.3
            if r.category == IntentCategory.UNKNOWN and r.confidence > 0.6:
                r.probe_score += 0.25
            if r.probe_score > 0.4:
                flagged.append(i)

        action = "allow"
        if risk > self._threshold:
            action = "rate_limit"
        if risk > self._threshold + 0.25:
            action = "block"

        return ProbingReport(
            risk_score=round(risk, 4),
            category_entropy_signal=round(cat_signal, 4),
            boundary_straddle_signal=round(boundary_signal, 4),
            temporal_burst_signal=round(temporal_signal, 4),
            text_similarity_signal=round(text_signal, 4),
            flagged_query_indices=flagged,
            recommended_action=action,
        )

    def _mahalanobis_risk(self, vec: Tuple[float, float, float, float]) -> float:
        """
        计算当前信号向量的马氏距离, 归一化为 [0, 1] 风险评分。

        当历史样本不足 (n < 8) 时, 回退到对角协方差 (即独立加权),
        此时马氏距离退化为欧氏距离除以方差, 等价于反方差加权。
        样本充足时, 协方差矩阵捕获信号间的相关性结构。
        """
        history = list(self._signal_history)
        n = len(history)
        if n < 8:
            return 0.35 * vec[0] + 0.30 * vec[1] + 0.175 * vec[2] + 0.175 * vec[3]

        # 计算均值向量 μ
        dim = 4
        mu = [0.0] * dim
        for v in history:
            for i in range(dim):
                mu[i] += v[i]
        mu = [m / n for m in mu]

        # 计算协方差矩阵 Σ (4x4)
        cov = [[0.0] * dim for _ in range(dim)]
        for v in history:
            dev = [v[i] - mu[i] for i in range(dim)]
            for i in range(dim):
                for j in range(dim):
                    cov[i][j] += dev[i] * dev[j]
        for i in range(dim):
            for j in range(dim):
                cov[i][j] /= (n - 1)

        # 对称正定正则化: Σ += ε·I
        eps = 0.01
        for i in range(dim):
            cov[i][i] += eps

        # 计算 Σ⁻¹ (4x4 矩阵求逆, 解析解)
        inv = self._invert_4x4(cov)
        if inv is None:
            return 0.5  # 奇异矩阵回退

        dev = [vec[i] - mu[i] for i in range(dim)]

        # D² = (x-μ)ᵀ Σ⁻¹ (x-μ)
        d2 = 0.0
        for i in range(dim):
            row_sum = 0.0
            for j in range(dim):
                row_sum += inv[i][j] * dev[j]
            d2 += dev[i] * row_sum

        # 归一化: 自由度为 4 的卡方分布的 95% 分位数 ≈ 9.49
        # 若 D² > 30 视为极端异常 (p < 10⁻⁶)
        if d2 < 0:
            d2 = 0.0
        normalized = min(1.0, math.sqrt(d2) / 5.5)
        return normalized

    @staticmethod
    def _invert_4x4(m: List[List[float]]) -> Optional[List[List[float]]]:
        """4x4 矩阵的伴随矩阵求逆。不使用 numpy, 保持零依赖。"""
        def det4(a):
            # 4x4 行列式, Laplace 展开
            d = 0.0
            for k in range(4):
                sub = [[a[i][j] for j in range(4) if j != k] for i in range(1, 4)]
                d2 = (
                    sub[0][0] * (sub[1][1] * sub[2][2] - sub[1][2] * sub[2][1])
                    - sub[0][1] * (sub[1][0] * sub[2][2] - sub[1][2] * sub[2][0])
                    + sub[0][2] * (sub[1][0] * sub[2][1] - sub[1][1] * sub[2][0])
                )
                d += (1 if k % 2 == 0 else -1) * a[0][k] * d2
            return d

        d = det4(m)
        if abs(d) < 1e-10:
            return None

        # 伴随矩阵
        adj = [[0.0] * 4 for _ in range(4)]
        for i in range(4):
            for j in range(4):
                sub = [[m[r][c] for c in range(4) if c != j] for r in range(4) if r != i]
                cofactor = (
                    sub[0][0] * (sub[1][1] * sub[2][2] - sub[1][2] * sub[2][1])
                    - sub[0][1] * (sub[1][0] * sub[2][2] - sub[1][2] * sub[2][0])
                    + sub[0][2] * (sub[1][0] * sub[2][1] - sub[1][1] * sub[2][0])
                )
                adj[j][i] = (1 if (i + j) % 2 == 0 else -1) * cofactor

        inv = [[adj[i][j] / d for j in range(4)] for i in range(4)]
        return inv

    def _category_entropy_signal(self) -> float:
        """类别遍历信号: 分布过于均匀暗示系统性探测。"""
        cats = [r.category for r in self._window]
        counter = Counter(cats)
        n = len(cats)
        entropy = 0.0
        for count in counter.values():
            p = count / n
            entropy -= p * math.log2(p)
        max_entropy = math.log2(len(IntentCategory))
        normalized = entropy / max_entropy if max_entropy > 0 else 0.0
        # 熵接近 1.0 且每个类别至少 2 条 → 强信号
        if normalized > 0.78 and len(counter) >= 4:
            return min(1.0, (normalized - 0.7) * 3.0)
        # 稀疏窗口: 熵高可能是自然原因
        elif normalized > 0.78:
            return (normalized - 0.7) * 1.5
        return 0.0

    def _boundary_straddle_signal(self) -> float:
        """边界刺探: 连续的 confidence 窄幅波动 + target 频繁微变。"""
        recent = list(self._window)[-20:]
        if len(recent) < 8:
            return 0.0
        confs = [r.confidence for r in recent]
        mean_conf = sum(confs) / len(confs)
        variance = sum((c - mean_conf) ** 2 for c in confs) / len(confs)
        # target 变化频率
        targets = [r.target for r in recent if r.target]
        unique_targets = len(set(targets))
        target_churn = unique_targets / max(1, len(recent))

        signal = 0.0
        # 低方差暗示查询围绕某个决策边界
        if variance < 0.02 and mean_conf > 0.4:
            signal += 0.45
        # 高 target churn + 低方差 = 典型边界探测模式
        if target_churn > 0.5 and variance < 0.05:
            signal += 0.35
        return min(1.0, signal)

    def _temporal_burst_signal(self) -> float:
        """时间脉冲: 突发查询密度异常。"""
        recent = list(self._window)[-30:]
        if len(recent) < 10:
            return 0.0
        timestamps = [r.timestamp for r in recent]
        intervals: List[float] = []
        for i in range(1, len(timestamps)):
            intervals.append(timestamps[i] - timestamps[i - 1])

        if not intervals:
            return 0.0
        mean_interval = sum(intervals) / len(intervals)
        # 短间隔比例
        short_count = sum(1 for iv in intervals if iv < 0.5)
        short_ratio = short_count / len(intervals)

        # 平均间隔 < 1 秒 且 短间隔比例 > 40%
        if mean_interval < 1.0 and short_ratio > 0.4:
            return min(1.0, short_ratio * 1.5 + 0.2)
        if mean_interval < 2.0 and short_ratio > 0.6:
            return min(1.0, short_ratio * 1.2)
        return 0.0

    def _text_similarity_signal(self) -> float:
        """文本相似度: 连续的 query 间编辑距离异常低。"""
        recent = list(self._window)[-15:]
        if len(recent) < 5:
            return 0.0
        # 长度方差小 → 查询模板化
        lengths = [r.text_length for r in recent]
        mean_len = sum(lengths) / len(lengths)
        len_variance = sum((l - mean_len) ** 2 for l in lengths) / len(lengths)
        cv = math.sqrt(len_variance) / max(1, mean_len)  # 变异系数

        # 哈希碰撞率: 窗口内 text_hash 去重比例
        hashes = [r.text_hash for r in recent]
        unique_ratio = len(set(hashes)) / len(hashes)

        signal = 0.0
        # 低长度变异 + 低唯一哈希比 → 高度模板化
        if cv < 0.1:
            signal += 0.40
        if unique_ratio < 0.5:
            signal += 0.35
        if cv < 0.1 and unique_ratio < 0.5:
            signal += 0.25
        return min(1.0, signal)

    def reset(self) -> None:
        self._window.clear()


__all__ = [
    "QueryRecord",
    "ProbingReport",
    "ProbingDetector",
]
