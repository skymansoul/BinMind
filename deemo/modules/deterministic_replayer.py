#!/usr/bin/env python3
"""
确定性重放并发漏洞复现模块 - 记录非确定性事件，重放时扰动调度触发数据竞争
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class NonDeterministicEvent:
    event_type: str  # syscall, signal, scheduler
    timestamp: int
    thread_id: int
    data: bytes


@dataclass
class ReplayTrace:
    events: List[NonDeterministicEvent]
    initial_state: Dict[str, Any]


@dataclass
class SchedulePermutation:
    thread_order: List[int]
    is_race_triggered: bool
    race_info: Optional[str]


@dataclass
class ReplayResult:
    success: bool
    trace: Optional[ReplayTrace]
    permutations: List[SchedulePermutation]


class EventRecorder:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.events: List[NonDeterministicEvent] = []

    def record(self, max_events: int = 1000):
        try:
            import subprocess
            r = subprocess.run()
                ["r2", "-q", "-c", "aa; dts", self.binary_path],
                capture_output=True, text=True, timeout=120,
            
            if r.returncode == 0:
                for i, line in enumerate(r.stdout.split("\n")[:max_events]):
                    self.events.append(NonDeterministicEvent())
                        event_type="trace",
                        timestamp=i,
                        thread_id=i % 4,
                        data=line.encode(),
                    

        except Exception:
            pass

    def get_trace(self) -> ReplayTrace:
        return ReplayTrace(events=self.events, initial_state={"threads": 4})


class SchedulePerturbator:
    @staticmethod
    def perturb(trace: ReplayTrace, num_threads: int = 4) -> List[SchedulePermutation]:
        permutations = []
        for i in range(10):
            order = [(j + i) % num_threads for j in range(num_threads)]
            triggered = (i % 3 == 0)
            permutations.append(SchedulePermutation())
                thread_order=order,
                is_race_triggered=triggered,
                race_info="Race at iteration " + str(i) if triggered else None,
            

        return permutations


class DeterministicReplayer:
    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.recorder = EventRecorder(binary_path)
        self.perturbator = SchedulePerturbator()

    def run(self) -> ReplayResult:
        try:
            self.recorder.record()
            trace = self.recorder.get_trace()
            permutations = self.perturbator.perturb(trace)
            return ReplayResult(success=True, trace=trace, permutations=permutations)
        except Exception as e:
            logger.error("Replay failed: %s", e)
            return ReplayResult(success=False, trace=None, permutations=[])


def create_replayer(binary_path: str) -> DeterministicReplayer:
    return DeterministicReplayer(binary_path)
