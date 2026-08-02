"""
Threat Intelligence Aggregator - Aggregates and analyzes threat intelligence feeds.

Provides time-windowed aggregation of threat intelligence data from multiple
sources with severity classification, trend analysis, source reputation
weighting, and deduplication.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import defaultdict
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger(__name__)


class ThreatLevel:
    """Threat severity level using singleton pattern via __new__."""

    _instances: Dict[str, ThreatLevel] = {}

    def __new__(cls, value: str) -> ThreatLevel:
        if value in cls._instances:
            return cls._instances[value]
        obj = super().__new__(cls)
        obj._val = value
        cls._instances[value] = obj
        return obj

    @property
    def value(self) -> str:
        return self._val

    def __str__(self) -> str:
        return self._val

    def __repr__(self) -> str:
        return f"ThreatLevel('{self._val}')"

    def __hash__(self) -> int:
        return hash(self._val)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, ThreatLevel):
            return self._val == other._val
        return NotImplemented

    # 严重性排序权重，用于综合评估时对威胁级别做数值映射
    @property
    def severity_weight(self) -> int:
        _weights = {"low": 1, "medium": 3, "high": 7, "critical": 10}
        return _weights.get(self._val, 1)


# Singleton instances
ThreatLevel.LOW = ThreatLevel("low")
ThreatLevel.MEDIUM = ThreatLevel("medium")
ThreatLevel.HIGH = ThreatLevel("high")
ThreatLevel.CRITICAL = ThreatLevel("critical")


class ThreatType(Enum):
    """Types of threat intelligence."""
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    ATTACK = "attack"
    INDICATOR = "indicator"
    EXPLOIT = "exploit"
    CAMPAIGN = "campaign"
    ACTOR = "actor"
    CVE = "cve"


# 威胁类型的基础风险分数，漏洞和利用的固有风险更高
_THREAT_TYPE_BASE_SCORE: Dict[ThreatType, float] = {
    ThreatType.MALWARE: 5.0,
    ThreatType.VULNERABILITY: 6.0,
    ThreatType.ATTACK: 7.0,
    ThreatType.INDICATOR: 3.0,
    ThreatType.EXPLOIT: 8.0,
    ThreatType.CAMPAIGN: 6.0,
    ThreatType.ACTOR: 4.0,
    ThreatType.CVE: 7.0,
}


class SourceReputation:
    """情报源信誉评分 —— 每个来源有独立的历史准确度与新鲜度权值。

    核心思路：来源的信誉并非静态常量，而是根据其历史贡献动态衰减。
    长期未报告高质量情报的来源，其权重自动下调（新鲜度衰减）。
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # source -> {"score": float, "reports": int, "last_active": float, "hits": int}
        self._registry: Dict[str, Dict[str, Any]] = {}

    def register_report(
        self, source: str, level: ThreatLevel, timestamp: float
    ) -> None:
        """记录一次来源报告，更新其信誉分数。"""
        with self._lock:
            entry = self._registry.setdefault(
                source,
                {"score": 0.5, "reports": 0, "last_active": timestamp, "hits": 0},
            )
            entry["reports"] += 1
            entry["last_active"] = max(entry["last_active"], timestamp)
            # 威胁级别越高，该报告的信息价值越大
            entry["score"] += level.severity_weight * 0.05
            entry["score"] = min(entry["score"], 1.0)

    def register_hit(self, source: str) -> None:
        """情报被验证为真时调用（命中），提升来源权重。"""
        with self._lock:
            entry = self._registry.get(source)
            if entry is None:
                return
            entry["hits"] += 1
            entry["score"] = min(entry["score"] + 0.1, 1.0)

    def get_weight(self, source: str, current_time: Optional[float] = None) -> float:
        """获取某个来源的当前信誉权重（含新鲜度衰减）。

        超过 72 小时无新报告，权重按指数衰减。
        """
        now = current_time or time.time()
        with self._lock:
            entry = self._registry.get(source)
            if entry is None:
                return 0.3  # 未知来源给一个较低的默认信任值
            score = entry["score"]
            hours_since = (now - entry["last_active"]) / 3600.0
            if hours_since > 72.0:
                decay = max(0.01, 1.0 - (hours_since - 72.0) / 168.0)  # 一周内衰减至接近 0
                score *= decay
            return max(0.05, score)

    def get_top_sources(self, n: int = 5) -> List[Tuple[str, float]]:
        """返回当前信誉最高的 N 个来源。"""
        with self._lock:
            ranked = sorted(
                self._registry.items(),
                key=lambda kv: kv[1]["score"],
                reverse=True,
            )
            return [(src, entry["score"]) for src, entry in ranked[:n]]


class ThreatIntelligence:
    """A single threat intelligence entry."""

    _id_counter: int = 0
    _id_lock = threading.Lock()

    def __init__(
        self,
        id: str,
        threat_type: ThreatType,
        level: ThreatLevel,
        timestamp: float,
        source: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> None:
        self.id = id
        self.threat_type = threat_type
        self.level = level
        self.timestamp = timestamp
        self.source = source
        self.data = data or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id,
            'threat_type': self.threat_type.value,
            'level': str(self.level),
            'timestamp': self.timestamp,
            'source': self.source,
            'data': self.data,
        }

    def compute_hash(self) -> str:
        """计算情报内容的确定性哈希，用于去重。

        去重依据：威胁类型 + 严重级别 + 来源 + 数据体序列化值。
        时间戳和 ID 不参与哈希，保证同一事件不会被重复计数。
        """
        # 取 data 的稳定 JSON 表示，键排序以保证确定性
        payload = json.dumps(
            {
                "threat_type": self.threat_type.value,
                "level": str(self.level),
                "source": self.source,
                "data": self.data,
            },
            sort_keys=True,
            default=str,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()


class TimeWindowAggregator:
    """Aggregates threat intelligence within a time window.

    线程安全：所有对 _intelligences 的读写均由 _lock 保护，
    避免在分析期间被外部写入破坏窗口快照。
    """

    def __init__(self, window_size: float = 3600.0) -> None:
        self._window_size = window_size
        self._intelligences: List[ThreatIntelligence] = []
        self._lock = threading.Lock()
        # 去重集合：按内容哈希跳过重复条目
        self._seen_hashes: Set[str] = set()
        self._deduplicate: bool = True

    @property
    def deduplicate(self) -> bool:
        return self._deduplicate

    @deduplicate.setter
    def deduplicate(self, value: bool) -> None:
        self._deduplicate = value
        if not value:
            with self._lock:
                self._seen_hashes.clear()

    def add_intelligence(self, intelligence: ThreatIntelligence) -> bool:
        """Add an intelligence entry and prune old ones.

        Args:
            intelligence: ThreatIntelligence to add.

        Returns:
            True if the entry was actually added (not a duplicate), False otherwise.
        """
        # 先计算哈希，避免持锁期间做 JSON 序列化
        content_hash = intelligence.compute_hash() if self._deduplicate else None

        with self._lock:
            if content_hash is not None:
                if content_hash in self._seen_hashes:
                    return False
                self._seen_hashes.add(content_hash)

            self._intelligences.append(intelligence)
            self._clean_old_intelligences()
            return True

    def _clean_old_intelligences(self) -> None:
        """Remove entries outside the time window.

        调用方必须持有 _lock。
        """
        current = time.time()
        cutoff = current - self._window_size
        # 保留窗口内的条目，同时清理对应的哈希
        kept: List[ThreatIntelligence] = []
        expired_hashes: Set[str] = set()
        for ti in self._intelligences:
            if ti.timestamp >= cutoff:
                kept.append(ti)
            elif self._deduplicate:
                expired_hashes.add(ti.compute_hash())
        self._intelligences = kept
        self._seen_hashes -= expired_hashes

    def get_intelligences_in_window(self) -> List[ThreatIntelligence]:
        """Get all entries within the current window.

        Returns:
            List of ThreatIntelligence entries.
        """
        with self._lock:
            self._clean_old_intelligences()
            return list(self._intelligences)

    def aggregate_by_type(self) -> Dict[str, List[ThreatIntelligence]]:
        """Group intelligence by threat type.

        Returns:
            Dict of type string to list of entries.
        """
        result: Dict[str, List[ThreatIntelligence]] = defaultdict(list)
        for ti in self.get_intelligences_in_window():
            result[ti.threat_type.value].append(ti)
        return dict(result)

    def aggregate_by_level(self) -> Dict[str, List[ThreatIntelligence]]:
        """Group intelligence by threat level.

        Returns:
            Dict of level string to list of entries.
        """
        result: Dict[str, List[ThreatIntelligence]] = defaultdict(list)
        for ti in self.get_intelligences_in_window():
            result[str(ti.level)].append(ti)
        return dict(result)

    def get_threat_count(self) -> int:
        """Get total threat count in window.

        Returns:
            Number of entries.
        """
        return len(self.get_intelligences_in_window())

    @property
    def window_size(self) -> float:
        return self._window_size

    @window_size.setter
    def window_size(self, value: float) -> None:
        self._window_size = max(60.0, min(value, 86400.0))


class ThreatAnalyzer:
    """Analyzes aggregated threat intelligence.

    结合来源信誉对整体威胁态势加权评分，输出比纯计数更准确的态势判断。
    """

    def __init__(self) -> None:
        self._aggregator = TimeWindowAggregator()
        self._reputation = SourceReputation()
        self._lock = threading.Lock()

    @property
    def reputation(self) -> SourceReputation:
        """暴露信誉系统，供外部配置或在验证情报后调用 register_hit。"""
        return self._reputation

    @property
    def aggregator(self) -> TimeWindowAggregator:
        """暴露聚合器，允许外部开关去重或调整窗口。"""
        return self._aggregator

    def analyze(self, window_size: float = 3600.0) -> Dict[str, Any]:
        """Analyze threats within a time window.

        Args:
            window_size: Time window in seconds.

        Returns:
            Analysis result dict.
        """
        self._aggregator.window_size = max(60.0, min(window_size, 86400.0))

        with self._lock:
            aggregated = self._aggregator.aggregate_by_type()
            all_levels: Dict[str, int] = {
                str(level): 0
                for level in ThreatLevel._instances.values()
            }

            # 加权风险分数 —— 不仅看数量，还看来源可信度和威胁类型固有风险
            weighted_risk: float = 0.0

            result: Dict[str, Any] = {
                'window_size': window_size,
                'total_threats': self._aggregator.get_threat_count(),
                'by_type': {},
                'by_level': dict(all_levels),
                'top_sources': {},
                'weighted_risk_score': 0.0,
                'source_trust': {},
            }

            for threat_type, intelligences in aggregated.items():
                result['by_type'][threat_type] = {
                    'count': len(intelligences),
                    'levels': {
                        str(level): sum(
                            1 for ti in intelligences
                            if str(ti.level) == str(level)
                        )
                        for level in ThreatLevel._instances.values()
                    },
                }
                for ti in intelligences:
                    result['by_level'][str(ti.level)] += 1
                    result['top_sources'][ti.source] = (
                        result['top_sources'].get(ti.source, 0) + 1
                    )
                    # 加权风险 = Σ(严重性权重 × 威胁类型基础分 × 来源信誉)
                    src_weight = self._reputation.get_weight(ti.source)
                    base = _THREAT_TYPE_BASE_SCORE.get(ti.threat_type, 3.0)
                    weighted_risk += ti.level.severity_weight * base * src_weight

            # Top 5 sources
            top_sources = sorted(
                result['top_sources'].items(),
                key=lambda x: x[1],
                reverse=True,
            )
            result['top_sources'] = dict(top_sources[:5])

            # 来源信任快照
            result['source_trust'] = {
                src: round(self._reputation.get_weight(src), 3)
                for src, _ in top_sources[:5]
            }

            # 归一化加权风险到 [0, 100] 区间（防止极端值不可读）
            max_possible = len(self._aggregator.get_intelligences_in_window()) * 10.0 * 8.0 * 1.0
            result['weighted_risk_score'] = round(
                (weighted_risk / max(max_possible, 1)) * 100.0, 2
            )

            # Overall threat level —— 用加权分数做更细粒度的判断
            highest_level = max(
                result['by_level'].items(),
                key=lambda x: x[1],
            )
            result['overall_level'] = highest_level[0] if highest_level[1] > 0 else "low"

            return result

    def add_intelligence(
        self,
        threat_type: ThreatType,
        level: ThreatLevel,
        source: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[ThreatIntelligence]:
        """Add a threat intelligence entry.

        Args:
            threat_type: Type of threat.
            level: Severity level.
            source: Intelligence source.
            data: Optional additional data.

        Returns:
            Created ThreatIntelligence, or None if the entry was deduplicated.
        """
        # 使用更细粒度的时间戳避免 ID 冲突
        ts = time.time()
        with ThreatIntelligence._id_lock:
            ThreatIntelligence._id_counter += 1
            unique_id = (
                f"{threat_type.value}_{ThreatIntelligence._id_counter}_{int(ts * 1_000_000)}"
            )

        intelligence = ThreatIntelligence(
            id=unique_id,
            threat_type=threat_type,
            level=level,
            timestamp=ts,
            source=source,
            data=data or {},
        )

        added = self._aggregator.add_intelligence(intelligence)
        if not added:
            return None  # 重复条目，静默丢弃

        # 更新来源信誉
        self._reputation.register_report(source, level, ts)
        return intelligence

    def get_summary(self) -> Dict[str, Any]:
        """Get a quick summary of current threat landscape.

        Returns:
            Summary dict.
        """
        analysis = self.analyze()
        return {
            'total': analysis['total_threats'],
            'overall_level': analysis['overall_level'],
            'weighted_risk_score': analysis['weighted_risk_score'],
            'by_type': {
                t: info['count']
                for t, info in analysis['by_type'].items()
            },
            'top_sources': analysis['top_sources'],
            'source_trust': analysis.get('source_trust', {}),
        }


def aggregate_threats(
    intelligences: List[Dict[str, Any]],
    window_size: float = 3600.0,
) -> Dict[str, Any]:
    """Convenience function for one-shot threat aggregation.

    Args:
        intelligences: List of intelligence dicts with 'type', 'level', 'source' keys.
        window_size: Time window in seconds.

    Returns:
        Analysis result dict.
    """
    analyzer = ThreatAnalyzer()

    for intel in intelligences:
        try:
            threat_type = ThreatType(intel.get("type", "indicator").lower())
        except ValueError:
            threat_type = ThreatType.INDICATOR

        level = ThreatLevel(intel.get("level", "low").lower())

        analyzer.add_intelligence(
            threat_type=threat_type,
            level=level,
            source=intel.get("source", "unknown"),
            data=intel.get("data", {}),
        )

    return analyzer.analyze(window_size=window_size)
