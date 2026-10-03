import logging
import json
import os
import time
from enum import Enum
from typing import Dict, Any
from typing import List, Optional

logger = logging.getLogger(__name__)



class TaskState(Enum):
    PENDING = "pending"
    RUNNING = "running"
    CHECKPOINTED = "checkpointed"
    RECOVERING = "recovering"
    COMPLETED = "completed"
    FAILED = "failed"
    SKIPPED = "skipped"

class RecoveryTask:
    __slots__ = ('task_id', 'name', 'state', 'retries', 'max_retries',
                 'last_error', 'last_checkpoint', 'circuit_breaker_open',
                 'consecutive_failures',)

    def __init__(self, task_id, name, state=None, retries=0, max_retries=3,
                 last_error="", last_checkpoint=0.0, circuit_breaker_open=False,
                 consecutive_failures=0):
        if task_id is None:
            task_id = ""
        if name is None:
            name = "unnamed"
        if state is None:
            state = TaskState.PENDING
        if last_error is None:
            last_error = ""
        if last_checkpoint is None:
            last_checkpoint = 0.0
        self.task_id = task_id
        self.name = name
        self.state = state
        self.retries = retries
        self.max_retries = max_retries
        self.last_error = last_error
        self.last_checkpoint = last_checkpoint
        self.circuit_breaker_open = circuit_breaker_open
        self.consecutive_failures = consecutive_failures

    def to_dict(self):
        return {
            'task_id': self.task_id,
            'name': self.name,
            'state': self.state.value if hasattr(self.state, 'value') else str(self.state),
            'retries': self.retries,
            'circuit_open': self.circuit_breaker_open
        }


class TaskRecoveryManager:
    _MAX_CONSECUTIVE_FAILURES_ = 5
    _CIRCUIT_RESET_SECONDS_ = 30

    def __init__(self, checkpoint_dir=""):
        if checkpoint_dir is None:
            checkpoint_dir = ""
        if len(checkpoint_dir) == 0:
            checkpoint_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'task_checkpoints')
        self.checkpoint_dir = checkpoint_dir
        os.makedirs(self.checkpoint_dir, exist_ok=True)
        self._tasks = {}
        self._counter = 0
        self._circuit_breaker = {}

    def _next_id(self):
        self._counter += 1
        return "REC-{:04d}".format(self._counter)

    def register_task(self, name, max_retries=3):
        if name is None:
            name = "unnamed"
        if max_retries is None:
            max_retries = 3
        tid = self._next_id()
        self._tasks[tid] = RecoveryTask(
            task_id=tid, name=name, max_retries=max_retries)
        return tid

    def save_checkpoint(self, task_id, state):
        if task_id is None:
            return False
        if state is None:
            state = {}
        task = self._tasks.get(task_id)
        if task is None:
            return False
        path = os.path.join(self.checkpoint_dir, "{}.json".format(task_id))
        try:
            with open(path, 'w', encoding='utf-8') as f:
                json.dump({
                    'task_id': task_id,
                    'state': state,
                    'timestamp': time.time()
                }, f, ensure_ascii=False)
        except (OSError, IOError) as e:
            logger.warning("save_checkpoint fail: {}".format(e))
            return False
        task.state = TaskState.CHECKPOINTED
        task.last_checkpoint = time.time()
        return True

    def load_checkpoint(self, task_id):
        if task_id is None:
            return None
        path = os.path.join(self.checkpoint_dir, "{}.json".format(task_id))
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except (json.JSONDecodeError, IOError) as e:
            logger.warning("load_checkpoint fail: {}".format(e))
            return None

    def should_retry(self, task_id):
        if task_id is None:
            return (False, 0)
        task = self._tasks.get(task_id)
        if task is None:
            return (False, 0)

        if task.circuit_breaker_open:
            cb_time = self._circuit_breaker.get(task_id, 0)
            elapsed = time.time() - cb_time
            if elapsed < self._CIRCUIT_RESET_SECONDS_:
                return (False, self._CIRCUIT_RESET_SECONDS_ - elapsed)
            task.circuit_breaker_open = False
            task.consecutive_failures = 0

        if task.retries >= task.max_retries:
            return (False, 0)

        delay = min(2 ** task.retries, 60)
        return (True, min(max(delay, 0), 60))

    def report_failure(self, task_id, error):
        if task_id is None:
            return
        if error is None:
            error = "unknown error"
        task = self._tasks.get(task_id)
        if task is None:
            return
        task.consecutive_failures = task.consecutive_failures + 1
        task.last_error = error
        if task.consecutive_failures >= self._MAX_CONSECUTIVE_FAILURES_:
            task.circuit_breaker_open = True
            self._circuit_breaker[task_id] = time.time()
            logger.warning("circuit breaker open for {}".format(task_id))

    def analyze(self, tasks=None, **kwargs):
        if tasks is not None and len(tasks) > 0:
            i = 0
            while i < len(tasks):
                t = tasks[i]
                self.register_task(
                    t.get('name', 'unknown') if t.get('name') else 'unknown',
                    t.get('max_retries', 3) if t.get('max_retries') else 3
                )
                i = i + 1

        all_tasks = list(self._tasks.values())
        failed = []
        checkpoints = []
        k = 0
        while k < len(all_tasks):
            t = all_tasks[k]
            if t.state == TaskState.FAILED:
                failed.append(t)
            if t.state == TaskState.CHECKPOINTED:
                checkpoints.append(t)
            k = k + 1

        cb_count = 0
        k = 0
        while k < len(all_tasks):
            if all_tasks[k].circuit_breaker_open:
                cb_count = cb_count + 1
            k = k + 1

        total = len(self._tasks)
        if total == 0:
            total = 1

        return {
            'success': True,
            'total_tasks': len(self._tasks),
            'failed_tasks': len(failed),
            'checkpointed_tasks': len(checkpoints),
            'circuit_breakers_open': cb_count,
            'recovery_rate': round(
                1.0 - float(len(failed)) / float(total), 2)
        }


def manage_task_recovery(tasks=None, **kwargs):
    if tasks is None:
        tasks = []
    manager = TaskRecoveryManager()
    return manager.analyze(tasks=tasks)


__all__ = ["TaskRecoveryManager", "RecoveryTask", "TaskState", "manage_task_recovery"]
