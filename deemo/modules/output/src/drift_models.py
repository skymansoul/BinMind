"""
CVSS 时间漂移的数据模型 — 快照、事件、状态枚举。

从 temporal_cvss_drift.py 拆分以控制单文件在 300 行内。
TemporalDriftTracker 的逻辑保留在原文件中。

修改记录:
  创建 2026-08-01 — 从 temporal_cvss_drift.py 拆分
"""

import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class DriftDirection(Enum):
    DECAY = "decay"
    AMPLIFY = "amplify"
    STABLE = "stable"


@dataclass
class ChecksecSnapshot:
    nx: bool = False
    pie: bool = False
    canary: bool = False
    relro_full: bool = False
    fortify: bool = False
    timestamp: float = 0.0

    def hardening_score(self) -> float:
        s = 0.0
        if self.nx: s += 0.2
        if self.pie: s += 0.2
        if self.canary: s += 0.2
        if self.relro_full: s += 0.2
        if self.fortify: s += 0.2
        return s

    def diff(self, previous: 'ChecksecSnapshot') -> float:
        return self.hardening_score() - previous.hardening_score()


@dataclass
class TemporalEvent:
    event_type: str
    timestamp: float
    magnitude: float
    description: str = ""


@dataclass
class DriftState:
    timestamp: float
    original_temporal_score: float
    drifted_score: float
    direction: DriftDirection
    cumulative_drift: float
    active_amplifications: int
    hardening_diff: float


# 事件类型→默认magnitude (>0=加速衰减, <0=增强威胁)
EVENT_DEFAULT_MAGNITUDE: Dict[str, float] = {
    'patch_released': 0.6,    'poc_published': -0.30,
    'exploit_weaponized': -0.50, 'kev_listed': -0.40,
    'mitigation_deployed': 0.25, 'cve_disputed': -0.10,
    'vendor_advisory': 0.10,
}
