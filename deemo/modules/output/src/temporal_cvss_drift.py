"""
CVSS 时间维度漂移追踪 — checksec 差分修正的衰减/增强双机制模型。

问题定义:
  CVSS 3.1 时间度量 (E/RL/RC) 是静态快照。EP3975080A1 用事件序列
  追踪 E/RL/RC 状态迁移，但未将二进制自身加固演化纳入漂移模型。
  本模块的增量: checksec 差分作为 λ 衰减率的修正因子。

衰减: base_decay(t) = exp(-λ×t)
  λ = λ_base × hardening_factor × exploit_pub_factor × patch_factor
增强: amplification(t) = Π(1 + A_i×(1-exp(-μ×age_i)))

  EP3975080A1 (IBM): CVSS temporal 事件驱动参数化
  checksec 加固检测: pwntools/pwnlib

修改记录:
  创建 2025-03-03 — TemporalDriftTracker 核心
  2025-03-03 — 数据模型拆分至 drift_models.py
"""

import math
import time
from typing import Any, Dict, List, Optional

from modules.output.src.drift_models import (
    ChecksecSnapshot, TemporalEvent, DriftState, DriftDirection,
    EVENT_DEFAULT_MAGNITUDE,
)

class TemporalDriftTracker:
    """
    CVSS 时间评分漂移追踪器。

    维护漏洞从发现时刻起的可利用性时间曲线，受两类因子调制:
      1. 二进制加固演化 (checksec 快照差分)
      2. 外部安全事件 (补丁/PoC/KEV)

    用法:
      tracker = TemporalDriftTracker(base_temporal_score=7.5)
      tracker.record_checksec(current_checksec_dict)
      tracker.record_event('poc_published', 'Exploit-DB #51234')
      current = tracker.drift_score()
    """

    def __init__(self, base_temporal_score: float,
                 base_checksec: Optional[Dict[str, Any]] = None,
                 discovery_time: Optional[float] = None,
                 lambda_base: float = 0.05):
        self.base_score = max(0.0, min(10.0, base_temporal_score))
        self.lambda_base = lambda_base
        self.discovery_time = discovery_time or time.time()

        if base_checksec:
            self._baseline_checksec = ChecksecSnapshot(
                nx=base_checksec.get('NX', False),
                pie=base_checksec.get('PIE', False),
                canary=base_checksec.get('Canary', False),
                relro_full='full' in base_checksec.get('RELRO', '').lower(),
                fortify=base_checksec.get('FORTIFY', False),
                timestamp=self.discovery_time,
            )
        else:
            self._baseline_checksec = ChecksecSnapshot(timestamp=self.discovery_time)

        self._checksec_history: List[ChecksecSnapshot] = [self._baseline_checksec]
        self._events: List[TemporalEvent] = []
        self._drift_history: List[DriftState] = []
        self._last_checksec = self._baseline_checksec

    def record_event(self, event_type: str, description: str = "",
                     magnitude: Optional[float] = None,
                     timestamp: Optional[float] = None):
        if magnitude is None:
            magnitude = EVENT_DEFAULT_MAGNITUDE.get(event_type, 0.0)
        ts = timestamp or time.time()
        self._events.append(TemporalEvent(
            event_type=event_type, timestamp=ts,
            magnitude=magnitude, description=description))

    def record_checksec(self, checksec: Dict[str, Any],
                        timestamp: Optional[float] = None):
        ts = timestamp or time.time()
        snap = ChecksecSnapshot(
            nx=checksec.get('NX', False), pie=checksec.get('PIE', False),
            canary=checksec.get('Canary', False),
            relro_full='full' in checksec.get('RELRO', '').lower(),
            fortify=checksec.get('FORTIFY', False), timestamp=ts)
        self._checksec_history.append(snap)
        self._last_checksec = snap

    def _compute_effective_lambda(self, at_time: float) -> float:
        lam = self.lambda_base
        hw_diff = self._last_checksec.diff(self._baseline_checksec)
        if hw_diff > 0:
            hardening_factor = 1.0 + hw_diff * 2.0
        elif hw_diff < 0:
            hardening_factor = 1.0 + hw_diff * 1.5
        else:
            hardening_factor = 1.0
        lam *= max(0.5, min(2.0, hardening_factor))

        patches = [e for e in self._events
                   if e.event_type == 'patch_released' and e.timestamp <= at_time]
        if patches:
            latest_age = at_time - max(e.timestamp for e in patches)
            patch_maturity = min(latest_age / (90 * 86400), 1.0)
            lam *= max(0.5, min(3.0, 1.0 + patch_maturity * 1.5))
        else:
            lam *= 0.8

        poc_events = [e for e in self._events
                      if e.event_type in ('poc_published', 'exploit_weaponized', 'kev_listed')
                      and e.timestamp <= at_time]
        if poc_events:
            worst = min(e.magnitude for e in poc_events)
            lam *= max(0.4, min(1.5, 1.0 + worst))
        return lam

    def _compute_amplification(self, at_time: float) -> float:
        amp = 1.0
        for evt in self._events:
            if evt.event_type not in ('poc_published', 'exploit_weaponized', 'kev_listed'):
                continue
            if evt.timestamp > at_time: continue
            age = at_time - evt.timestamp
            if age < 0: continue
            A = abs(evt.magnitude)
            amp *= (1.0 + A * (1.0 - math.exp(-2.0 * age / 86400)))
        return amp

    def drift_score(self, at_time: Optional[float] = None) -> DriftState:
        t = at_time or time.time()
        elapsed_days = max(0.0, (t - self.discovery_time) / 86400.0)
        lam = self._compute_effective_lambda(t)
        decay = math.exp(-lam * elapsed_days)
        amplification = self._compute_amplification(t)
        drifted = max(0.0, min(10.0, self.base_score * decay * amplification))

        if drifted < self.base_score - 0.3:
            direction = DriftDirection.DECAY
        elif drifted > self.base_score + 0.3:
            direction = DriftDirection.AMPLIFY
        else:
            direction = DriftDirection.STABLE

        cumulative = drifted - self.base_score
        active_amps = sum(1 for e in self._events
                          if e.event_type in ('poc_published', 'exploit_weaponized', 'kev_listed')
                          and e.timestamp <= t)
        hw_diff = self._last_checksec.diff(self._baseline_checksec)

        state = DriftState(
            timestamp=t, original_temporal_score=self.base_score,
            drifted_score=round(drifted, 1), direction=direction,
            cumulative_drift=round(cumulative, 1),
            active_amplifications=active_amps, hardening_diff=round(hw_diff, 2))
        self._drift_history.append(state)
        return state

    def prediction(self, days_ahead: int = 30) -> float:
        future = time.time() + days_ahead * 86400
        return self.drift_score(at_time=future).drifted_score

    def time_to_threshold(self, threshold: float) -> Optional[float]:
        t = time.time()
        lam = self._compute_effective_lambda(t)
        if lam <= 0: return None
        elapsed = (t - self.discovery_time) / 86400.0
        current = self.base_score * math.exp(-lam * elapsed)
        if current <= threshold: return 0.0
        days = -math.log(threshold / current) / lam
        return round(days, 1) if days > 0 else None

    @property
    def event_count(self) -> int: return len(self._events)

    @property
    def checksec_snapshots(self) -> int: return len(self._checksec_history)
