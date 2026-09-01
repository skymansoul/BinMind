import logging
import time
from dataclasses import dataclass, field
import typing
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)



class RacePoint:
    __slots__ = ('point_id', 'location', 'shared_resource', 'access_type', 'thread_id', 'pre_delay_ms', 'post_delay_ms',)

    def __init__(self, point_id, location, shared_resource, access_type, thread_id=0, pre_delay_ms=0, post_delay_ms=0):
        self.point_id = point_id
        self.location = location
        self.shared_resource = shared_resource
        self.access_type = access_type
        self.thread_id = thread_id
        self.pre_delay_ms = pre_delay_ms
        self.post_delay_ms = post_delay_ms

    def to_dict(self) -> Dict[str, Any]:
        return {
            'point_id': self.point_id,
            'location': self.location,
            'shared_resource': self.shared_resource,
            'access_type': self.access_type,
            'pre_delay_ms': self.pre_delay_ms,
            'post_delay_ms': self.post_delay_ms
        }

class ThreadRaceForcer:
    INTERLEAVING_STRATEGIES = [
        'sequential', 'alternating', 'concurrent',
        'delayed_thread1', 'delayed_thread2', 'random'
    ]

    def __init__(self):
        self._race_points: List[RacePoint] = []
        self._successful_triggers: int = 0
        self._attempts: int = 0
        self._counter = 0

    def _next_id(self) -> str:
        self._counter += 1
        return f"RACE-{self._counter:04d}"

    def add_race_point(self, location: str, shared_resource: str,
                       access_type: str = "write", thread_id: int = 0,
                       pre_delay: int = 0, post_delay: int = 0):
        self._race_points.append(RacePoint(
            point_id=self._next_id(),
            location=location,
            shared_resource=shared_resource,
            access_type=access_type,
            thread_id=thread_id,
            pre_delay_ms=pre_delay,
            post_delay_ms=post_delay))

    def find_shared_accesses(self, calls: List[Dict[str, Any]]) -> List[RacePoint]:
        points = []
        seen_resources: Dict[str, List[int]] = {}
        for i, call in enumerate(calls):
            resource = call.get('resource', '')
            if resource:
                seen_resources.setdefault(resource, []).append(i)

        for resource, indices in seen_resources.items():
            if len(indices) >= 2:
                for idx in indices:
                    points.append(RacePoint(
                        point_id=self._next_id(),
                        location=calls[idx].get('location', ''),
                        shared_resource=resource,
                        access_type=calls[idx].get('type', 'write'),
                        pre_delay_ms=10, post_delay_ms=10))
        return points

    def simulate_race_trigger(self, num_threads: int = 2,
                              max_attempts: int = 1000) -> Dict[str, Any]:
        if not self._race_points:
            return {'triggered': False, 'probability': 0}

        window_total_ms = sum(
            p.pre_delay_ms + p.post_delay_ms for p in self._race_points)
        prob_per_attempt = min(0.5, len(self._race_points) * 0.02 +
                              window_total_ms / 1000)
        prob_at_least_once = 1 - (1 - prob_per_attempt) ** max_attempts

        return {
            'triggered': prob_at_least_once > 0.5,
            'probability': round(prob_at_least_once, 3),
            'estimated_attempts_needed': max(1, int(1 / max(0.001, prob_per_attempt)))
        }

    def analyze(self, shared_accesses: Optional[List[Dict[str, Any]]] = None,
                num_threads: int = 2, max_attempts: int = 1000,
                **kwargs) -> Dict[str, Any]:
        if shared_accesses:
            points = self.find_shared_accesses(shared_accesses)
            self._race_points = points

        sim_result = self.simulate_race_trigger(num_threads, max_attempts)

        return {
            'success': True,
            'total_race_points': len(self._race_points),
            'race_points': [p.to_dict() for p in self._race_points[:20]],
            'simulation': sim_result,
            'strategies': self.INTERLEAVING_STRATEGIES,
            'recommended_delays': 'Add 10-50ms delay before/after each access point',
            'risk_level': 'high' if sim_result.get('triggered') else
                         'medium' if self._race_points else 'low'
        }

def force_thread_races(shared_accesses: List[Dict[str, Any]],
                       **kwargs) -> Dict[str, Any]:
    forcer = ThreadRaceForcer()
    return forcer.analyze(shared_accesses=shared_accesses)


__all__ = ["ThreadRaceForcer", "RacePoint", "force_thread_races"]
