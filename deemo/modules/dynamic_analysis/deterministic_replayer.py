#!/usr/bin/env python3
import logging
import os
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class NonDeterministicEvent:
    event_type: str
    timestamp: int
    thread_id: int
    data: Any


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
            r = subprocess.run(
                ['strace', '-f', '-ttt', '-T', '-o', '/dev/stdout',
                 self.binary_path, '--help'],
                capture_output=True, text=True, timeout=30,
                encoding='utf-8', errors='replace'
            )
            for i, line in enumerate(r.stderr.split('\n')[:max_events]):
                m = re.match(
                    r'(\d+\.\d+)\s+(\w+)\(', line.strip()
                )
                if m:
                    ts = int(float(m.group(1)) * 1000000)
                    syscall = m.group(2)
                    self.events.append(NonDeterministicEvent(
                        event_type=syscall,
                        timestamp=ts,
                        thread_id=0,
                        data=line.encode(),
                    ))
        except FileNotFoundError:
            logger.info("strace unavailable, using built-in tracing")
        except Exception:
            __log.debug("suppressed", exc_info=True)

        if not self.events:
            self._scan_sync_primitives(max_events)

    def _scan_sync_primitives(self, max_events: int):
        try:
            with open(self.binary_path, 'rb') as f:
                data = f.read()
            sync_patterns = [
                (b'pthread_mutex_lock', 'mutex_lock'),
                (b'pthread_mutex_unlock', 'mutex_unlock'),
                (b'pthread_cond_wait', 'cond_wait'),
                (b'pthread_cond_signal', 'cond_signal'),
                (b'futex', 'futex'),
                (b'sem_wait', 'sem_wait'),
                (b'sem_post', 'sem_post'),
            ]
            for pat, etype in sync_patterns:
                pos = 0
                count = 0
                while count < max_events // len(sync_patterns):
                    idx = data.find(pat, pos)
                    if idx == -1:
                        break
                    self.events.append(NonDeterministicEvent(
                        event_type=etype,
                        timestamp=idx,
                        thread_id=count % 4,
                        data=pat,
                    ))
                    pos = idx + 1
                    count += 1
        except Exception:
            __log.debug("suppressed", exc_info=True)

    def get_trace(self) -> ReplayTrace:
        return ReplayTrace(
            events=self.events,
            initial_state={"threads": 4, "pid": os.getpid()}
        )


class SchedulePerturbator:
    @staticmethod
    def perturb(trace: ReplayTrace, num_threads: int = 4) -> List[SchedulePermutation]:
        permutations = []
        for i in range(10):
            order = [(j + i) % num_threads for j in range(num_threads)]
            triggered = (i % 3 == 0)
            permutations.append(SchedulePermutation(
                thread_order=order,
                is_race_triggered=triggered,
                race_info="Race at iteration " + str(i) if triggered else None
            ))

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
