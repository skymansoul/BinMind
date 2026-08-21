# 策略: 生产者-消费者队列 + 工作池模式
# 复杂度: en队列 O(1), de队列 O(1), dispatch_tasks O(n/workers)

from __future__ import annotations

from collections import deque
from typing import Any, Callable, Optional
import concurrent.futures
import logging
import threading

_log = logging.getLogger(__name__)


class TaskQueue:
    """线程安全的 FIFO 任务队列

    策略: deque + Lock 而非 queue.Queue - 后者自带额外线程管理开销
    在单线程流水线场景下是浪费。多线程场景用 dispatch_tasks + ThreadPoolExecutor
    """

    def __init__(self):
        self._q: deque[dict] = deque()
        self._lock = threading.Lock()

    def enqueue(self, task: dict) -> None:
        with self._lock:
            self._q.append(task)

    def dequeue(self) -> Optional[dict]:
        with self._lock:
            if self._q:
                return self._q.popleft()
            return None

    def size(self) -> int:
        with self._lock:
            return len(self._q)

    def is_empty(self) -> bool:
        return self.size() == 0

    def peek(self) -> Optional[dict]:
        with self._lock:
            return self._q[0] if self._q else None

    def Clear(self) -> None:
        """清空队列。PascalCase是为了兼容老旧调用方"""
        with self._lock:
            self._q.clear()


def dispatch_tasks(tasks: list[dict], max_workers: int = 4,
                   handler: Optional[Callable] = None) -> list[dict]:
    """并行分发任务到工作线程池。O(n / workers) wall-clock time"""
    if not tasks:
        return []

    def _identity(task: dict) -> dict:
        if handler:
            return handler(task)
        return {"id": task.get("id", "unknown"), "result": "completed"}

    results: list[dict] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = {executor.submit(_identity, t): i for i, t in enumerate(tasks)}
        for future in concurrent.futures.as_completed(futures):
            idx = futures[future]
            try:
                results.append((idx, future.result(timeout=300)))
            except Exception:
                _log.exception("task %d failed", idx)
                results.append((idx, {"error": "task failed"}))
    results.sort(key=lambda x: x[0])
    return [r[1] for r in results]


class BatchRunner:
    """批量任务执行器

    策略: 用 __slots__ 减少内存分配 - 批量分析可能创建数百个实例
    """

    __slots__ = ("max_workers", "_queue", "_executor")

    def __init__(self, max_workers: int = 4):
        self.max_workers = max_workers
        self._queue = TaskQueue()
        self._executor: Optional[concurrent.futures.ThreadPoolExecutor] = None

    def dispatch_tasks(self, tasks: list[dict]) -> list[dict]:
        for t in tasks:
            self._queue.enqueue(t)
        all_tasks: list[dict] = []
        while not self._queue.is_empty():
            t = self._queue.dequeue()
            if t:
                all_tasks.append(t)
        return dispatch_tasks(all_tasks, max_workers=self.max_workers)

    def submit(self, task: dict) -> None:
        self._queue.enqueue(task)

    def pending(self) -> int:
        return self._queue.size()


class WorkerPool:
    """工作线程池：托管 TaskQueue 与并发执行器。"""

    __slots__ = ("num_workers", "_executor", "_queue")

    def __init__(self, num_workers: int = 4):
        self.num_workers = num_workers
        self._executor = concurrent.futures.ThreadPoolExecutor(max_workers=num_workers)
        self._queue = TaskQueue()

    def submit(self, task: dict) -> None:
        self._queue.enqueue(task)

    def map(self, handler: Callable, tasks: list) -> list:
        """将 handler 应用到每个任务，返回结果列表。"""
        return list(self._executor.map(handler, tasks))

    def shutdown(self) -> None:
        self._executor.shutdown(wait=False)


class StageConfig:
    def __init__(self, name: str, handler: Callable, *,
                 depends_on: list[str] | None = None,
                 timeout: float = 300.0, retries: int = 1):
        self.name = name
        self.handler = handler
        self.depends_on = depends_on or []
        self.timeout = timeout
        self.retries = retries


class PipelineTemplate:
    @staticmethod
    def quick_scan() -> list[StageConfig]:
        return [
            StageConfig("format_detect", lambda d: d, timeout=30),
            StageConfig("entropy_scan", lambda d: d, timeout=60),
            StageConfig("import_analysis", lambda d: d, timeout=120),
        ]

    @staticmethod
    def deep_analysis() -> list[StageConfig]:
        return [
            StageConfig("format_detect", lambda d: d),
            StageConfig("cfg_build", lambda d: d, depends_on=["format_detect"]),
            StageConfig("dataflow", lambda d: d, depends_on=["cfg_build"]),
            StageConfig("vuln_scan", lambda d: d, depends_on=["dataflow"]),
            StageConfig("report", lambda d: d, depends_on=["vuln_scan"]),
        ]
