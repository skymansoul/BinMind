"""
语义意图指纹与时间衰减追踪 (SIFT-D)。

技术问题: 安全分析会话中, 连续查询之间存在语义关联, 但现有系统
将每次查询视为独立事件, 丢失了:
  1. 意图漂移信号 (从侦察 → 利用 → 持久化 的渐进式意图转变)
  2. 重复查询的无效重路由
  3. 跨会话的攻击模式聚集

解决方案: 为每个意图构建紧凑的语义指纹 (SemanticFingerprint),
通过指数时间衰减维持滑动窗口内的意图分布记忆,
使用 JS 散度检测概念漂移, 达到阈值时触发会话边界划分。

新颖性: 将 NLP 中的 "概念漂移检测" 应用于安全采集路由,
用时间衰减替代固定窗口, 使得近期意图对当前路由决策的
影响力随时间平滑衰减而非阶跃归零。
"""

from __future__ import annotations

import math
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

from .intent_route import IntentCategory, IntentResult


@dataclass
class SemanticFingerprint:
    """
    紧凑的语义指纹。

    存储归一化的意图分布向量, 而非原始文本, 保证隐私性和存储效率。
    单条指纹 < 256 bytes, 适合高频查询场景。
    """
    distribution: Dict[IntentCategory, float]  # 归一化意图分布, 和 = 1.0
    dominant_intent: IntentCategory
    entropy: float            # 分布的香农熵
    created_at: float         # POSIX timestamp
    source_text_hash: str     # 原始请求的截断哈希, 用于去重
    depth: str = "standard"   # 关联的采集深度
    target: str = ""          # 关联的采集目标


@dataclass
class DriftAlert:
    """概念漂移告警。"""
    drift_magnitude: float       # JS 散度值
    from_distribution: Dict[IntentCategory, float]
    to_distribution: Dict[IntentCategory, float]
    boundary: bool = False       # 是否触发会话边界
    description: str = ""


@dataclass
class SessionProfile:
    """会话级别意图画像。"""
    fingerprints: List[SemanticFingerprint]
    aggregated_distribution: Dict[IntentCategory, float]
    session_start: float
    session_end: float
    dominant_intent_sequence: List[IntentCategory]
    drift_events: List[DriftAlert]


class SemanticFingerprintTracker:
    """
    语义指纹追踪器。

    机制:
    1. 每条意图结果生成语义指纹
    2. 指纹按时间衰减权重聚合为滑动画像
    3. 相邻时间窗口的画像 JS 散度 → 漂移检测
    4. 漂移超过阈值 → 触发会话边界 → 重置聚合权重

    时间衰减函数: w(t) = exp(-λ * (now - t)), λ 控制衰减速率。
    λ 的选择: 半衰期 30 分钟 → λ = ln(2) / 1800 ≈ 0.000385
    """

    def __init__(
        self,
        half_life_seconds: float = 1800.0,   # 默认 30 分钟半衰
        drift_threshold: float = 0.35,        # JS 散度阈值触发会话边界
        window_size: int = 20,                # 滑动窗口内最大指纹数
    ):
        self._half_life = half_life_seconds
        self._lambda = math.log(2) / half_life_seconds
        self._drift_threshold = drift_threshold
        self._window_size = window_size
        self._fingerprints: List[SemanticFingerprint] = []
        self._fingerprint_set: Set[str] = set()  # 用于快速去重
        self._sessions: List[SessionProfile] = []
        self._current_session_start: float = time.time()

    def _temporal_weight(self, ts: float, now: float) -> float:
        """计算时间衰减权重。"""
        age = max(0.0, now - ts)
        return math.exp(-self._lambda * age)

    def _distribution_entropy(self, dist: Dict[IntentCategory, float]) -> float:
        """计算分布的香农熵。"""
        entropy = 0.0
        for p in dist.values():
            if p > 0:
                entropy -= p * math.log2(p)
        return entropy

    def _hash_text(self, text: str) -> str:
        """生成请求文本的截断哈希, 用于去重。"""
        import hashlib
        return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]

    def fingerprint(self, result: IntentResult, request_text: str = "") -> SemanticFingerprint:
        """
        从意图分类结果生成语义指纹。

        指纹包含归一化的分布向量, 而非仅取最佳类别,
        保留次优类别的信息用于漂移检测。
        """
        dist: Dict[IntentCategory, float] = {}
        if result.matched_categories:
            total_conf = result.confidence
            per_cat = total_conf / len(result.matched_categories)
            for cat in result.matched_categories:
                dist[cat] = per_cat
        else:
            dist[result.category] = 1.0

        # 归一化
        total = sum(dist.values())
        if total > 0:
            dist = {k: v / total for k, v in dist.items()}

        # 补充未出现的类别为 0
        for cat in IntentCategory:
            if cat not in dist:
                dist[cat] = 0.0

        dominant = max(dist, key=dist.get)
        entropy = self._distribution_entropy(dist)
        text_hash = self._hash_text(request_text or result.params.raw_text)

        return SemanticFingerprint(
            distribution=dist,
            dominant_intent=dominant,
            entropy=entropy,
            created_at=time.time(),
            source_text_hash=text_hash,
            depth=result.params.depth,
            target=result.params.target,
        )

    def add(self, fp: SemanticFingerprint) -> Optional[DriftAlert]:
        """
        添加指纹到追踪器, 返回漂移告警 (如果有)。

        去重: 相同 source_text_hash 的指纹在窗口内不重复添加。
        """
        if fp.source_text_hash in self._fingerprint_set:
            return None

        self._fingerprints.append(fp)
        self._fingerprint_set.add(fp.source_text_hash)

        # 维护窗口大小
        while len(self._fingerprints) > self._window_size:
            removed = self._fingerprints.pop(0)
            self._fingerprint_set.discard(removed.source_text_hash)

        # 至少需要 4 个指纹才能可靠检测漂移
        if len(self._fingerprints) < 4:
            return None

        return self._detect_drift()

    def _detect_drift(self) -> Optional[DriftAlert]:
        """
        检测概念漂移: 比较前半窗口和后半窗口的聚合分布。
        """
        n = len(self._fingerprints)
        mid = n // 2
        now = time.time()

        first_half = self._aggregate(self._fingerprints[:mid], now)
        second_half = self._aggregate(self._fingerprints[mid:], now)

        js = self._jensen_shannon(first_half, second_half)

        if js > self._drift_threshold:
            boundary = js > self._drift_threshold * 1.5
            alert = DriftAlert(
                drift_magnitude=js,
                from_distribution=first_half,
                to_distribution=second_half,
                boundary=boundary,
                description=(
                    f"意图漂移检测: JS散度={js:.4f}"
                    + (" (触发会话边界)" if boundary else "")
                ),
            )
            if boundary:
                self._close_current_session()
                self._current_session_start = now
            return alert
        return None

    def _aggregate(
        self, fps: List[SemanticFingerprint], now: float
    ) -> Dict[IntentCategory, float]:
        """
        按时间衰减权重聚合多条指纹的分布。

        权重: 越近的指纹权重越高, 体现时序偏重。
        聚合: 加权平均。
        """
        if not fps:
            return {cat: 0.0 for cat in IntentCategory}

        weighted: Dict[IntentCategory, float] = defaultdict(float)
        weight_sum = 0.0

        for fp in fps:
            w = self._temporal_weight(fp.created_at, now)
            for cat, p in fp.distribution.items():
                weighted[cat] += w * p
            weight_sum += w

        if weight_sum > 0:
            return {cat: weighted[cat] / weight_sum for cat in IntentCategory}
        return {cat: 0.0 for cat in IntentCategory}

    def _jensen_shannon(
        self,
        dist_a: Dict[IntentCategory, float],
        dist_b: Dict[IntentCategory, float],
    ) -> float:
        """JS散度，用于量化两个意图分布的差异。遍历完整类别空间以保持零值项的结构信息。"""
        js = 0.0
        for cat in IntentCategory:
            p = dist_a.get(cat, 0.0)
            q = dist_b.get(cat, 0.0)
            # 零值项在 M=(p+q)/2 中贡献为 0，但维持维度完整性对漂移检测有意义
            m = (p + q) / 2.0
            if m > 0:
                if p > 0:
                    js += p * math.log(p / m)
                if q > 0:
                    js += q * math.log(q / m)
        return js / 2.0

    def current_distribution(self) -> Dict[IntentCategory, float]:
        """返回当前时间衰减聚合分布。"""
        return self._aggregate(self._fingerprints, time.time())

    def dominant_now(self) -> IntentCategory:
        """当前主导意图。"""
        dist = self.current_distribution()
        if not dist:
            return IntentCategory.UNKNOWN
        return max(dist, key=dist.get)

    def is_duplicate(self, text: str) -> bool:
        """检查请求是否为窗口内重复。"""
        h = self._hash_text(text)
        return h in self._fingerprint_set

    def _close_current_session(self) -> None:
        """关闭当前会话, 存储会话画像。"""
        if len(self._fingerprints) < 2:
            return
        now = time.time()
        agg = self._aggregate(self._fingerprints, now)
        dom_seq = [fp.dominant_intent for fp in self._fingerprints]

        # 提取漂移事件
        drift_events: List[DriftAlert] = []
        fps = self._fingerprints
        for i in range(4, len(fps) + 1):
            mid = i // 2
            first = self._aggregate(fps[:mid], now)
            second = self._aggregate(fps[mid:i], now)
            js = self._jensen_shannon(first, second)
            if js > self._drift_threshold * 0.8:
                drift_events.append(DriftAlert(
                    drift_magnitude=js,
                    from_distribution=first,
                    to_distribution=second,
                    boundary=js > self._drift_threshold * 1.5,
                ))

        session = SessionProfile(
            fingerprints=list(self._fingerprints),
            aggregated_distribution=agg,
            session_start=self._current_session_start,
            session_end=now,
            dominant_intent_sequence=dom_seq,
            drift_events=drift_events,
        )
        self._sessions.append(session)

    @property
    def sessions(self) -> List[SessionProfile]:
        return list(self._sessions)

    def clear(self) -> None:
        """重置追踪器状态。"""
        self._fingerprints.clear()
        self._fingerprint_set.clear()
        self._current_session_start = time.time()


__all__ = [
    "SemanticFingerprint",
    "DriftAlert",
    "SessionProfile",
    "SemanticFingerprintTracker",
]
