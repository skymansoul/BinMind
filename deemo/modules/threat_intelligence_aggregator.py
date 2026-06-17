"""
基于时间窗口的威胁情报聚合模块

功能：
1. 时间窗口内聚合威胁情报
2. 多源情报关联分析
3. 威胁等级评估

核心组件：
- ThreatIntelligence: 威胁情报
- TimeWindowAggregator: 时间窗口聚合器
- ThreatAnalyzer: 威胁分析器
"""

import os
import time
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ThreatLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ThreatType(Enum):
    MALWARE = "malware"
    VULNERABILITY = "vulnerability"
    ATTACK = "attack"
    INDICATOR = "indicator"


@dataclass
class ThreatIntelligence:
    id: str
    threat_type: ThreatType
    level: ThreatLevel
    timestamp: float
    source: str
    data: Dict[str, Any] = field(default_factory=dict)


class TimeWindowAggregator:

    def __init__(self, window_size: int = 3600):
        self._window_size = window_size
        self._intelligences: List[ThreatIntelligence] = []

    def add_intelligence(self, intelligence: ThreatIntelligence):
        self._intelligences.append(intelligence)
        self._clean_old_intelligences()

    def _clean_old_intelligences(self):
        current_time = time.time()
        self._intelligences = [
            ti for ti in self._intelligences
            if current_time - ti.timestamp <= self._window_size
        ]

    def get_intelligences_in_window(self) -> List[ThreatIntelligence]:
        self._clean_old_intelligences()
        return self._intelligences

    def aggregate_by_type(self) -> Dict[str, List[ThreatIntelligence]]:
        result = {}
        for ti in self.get_intelligences_in_window():
            key = ti.threat_type.value
            if key not in result:
                result[key] = []
            result[key].append(ti)
        return result

    def get_threat_count(self) -> int:
        return len(self.get_intelligences_in_window())


class ThreatAnalyzer:

    def __init__(self):
        self._aggregator = TimeWindowAggregator()

    def analyze(self, window_size: int = 3600) -> Dict[str, Any]:
        self._aggregator._window_size = window_size
        aggregated = self._aggregator.aggregate_by_type()
        
        result = {
            "window_size": window_size,
            "total_threats": self._aggregator.get_threat_count(),
            "by_type": {},
            "by_level": {level.value: 0 for level in ThreatLevel},
            "top_sources": {}
        }

        for threat_type, intelligences in aggregated.items():
            result["by_type"][threat_type] = {
                "count": len(intelligences),
                "levels": {level.value: 0 for level in ThreatLevel}
            }
            
            for ti in intelligences:
                result["by_type"][threat_type]["levels"][ti.level.value] += 1
                result["by_level"][ti.level.value] += 1
                result["top_sources"][ti.source] = result["top_sources"].get(ti.source, 0) + 1

        result["top_sources"] = dict(sorted(result["top_sources"].items(), key=lambda x: x[1], reverse=True)[:5])
        
        highest_level = max(result["by_level"].items(), key=lambda x: x[1])[0]
        result["overall_level"] = highest_level

        return result

    def add_intelligence(self, threat_type: ThreatType, level: ThreatLevel,
                        source: str, data: Dict[str, Any]):
        intelligence = ThreatIntelligence(
            id=f"{threat_type.value}_{int(time.time())}",
            threat_type=threat_type,
            level=level,
            timestamp=time.time(),
            source=source,
            data=data
        )
        self._aggregator.add_intelligence(intelligence)


def aggregate_threats(intelligences: List[Dict[str, Any]]) -> Dict[str, Any]:
    analyzer = ThreatAnalyzer()
    
    for intel in intelligences:
        threat_type = ThreatType[intel["type"].upper()]
        level = ThreatLevel[intel["level"].upper()]
        analyzer.add_intelligence(threat_type, level, intel["source"], intel.get("data", {}))
    
    return analyzer.analyze()