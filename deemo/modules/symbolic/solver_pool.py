"""Multiprocess SMT solver pool with dispatch loop and caching.

Each solver instance runs in its own process behind a request/response
queue. The pool dispatches incoming constraint strings to idle workers
and caches results by constraint hash to avoid redundant solves.
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import multiprocessing as mp
from typing import Dict, Any, Optional, List
from dataclasses import dataclass, field
from queue import Queue
from enum import Enum

logger = logging.getLogger(__name__)


class SolverStatus(Enum):
    """Worker lifecycle states."""
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    SHUTDOWN = "shutdown"


class SolverType:
    """Supported solver backends."""
    Z3 = "z3"
    CVC4 = "cvc4"
    YICES = "yices"


@dataclass
class SolverConfig:
    """Per-worker configuration: solver type, resource limits, options."""
    solver_type: str
    max_memory_mb: int = 2048
    timeout_seconds: int = 60
    priority: int = 1
    options: Dict = field(default_factory=dict)


@dataclass
class SolverRequest:
    """A single constraint-solving request dispatched to a worker."""
    request_id: str
    constraints: str
    timeout: Optional[int] = None
    options: Dict = field(default_factory=dict)


@dataclass
class SolverResponse:
    """Result returned by a worker after solving (or failing)."""
    request_id: str
    result: str
    status: str
    model: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


class SolverWorker:
    """Single-process solver. Owns a Z3 context and communicates via queues."""

    def __init__(self, worker_id: int, config: SolverConfig):
        self._worker_id = worker_id
        self._config = config
        self._status = SolverStatus.IDLE
        self._request_queue = Queue()
        self._response_queue = Queue()
        self._process: Optional[mp.Process] = None
        self._lock = threading.RLock()

    def start(self) -> bool:
        """Launch the worker process."""
        try:
            self._process = mp.Process(target=self._worker_loop, daemon=True)
            self._process.start()
            self._status = SolverStatus.IDLE
            logger.info(f"Solver worker {self._worker_id} started")
            return True
        except Exception as e:
            logger.error(f"Failed to start worker: {e}")
            self._status = SolverStatus.ERROR
            return False

    def stop(self) -> None:
        """Signal shutdown and terminate the process."""
        self._status = SolverStatus.SHUTDOWN
        if self._process and self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=5)
        logger.info(f"Solver worker {self._worker_id} stopped")

    def submit_request(self, request: SolverRequest) -> None:
        """Enqueue a request. Raises if worker is busy."""
        with self._lock:
            if self._status != SolverStatus.IDLE:
                raise RuntimeError("Solver is busy")
            self._status = SolverStatus.BUSY
            self._request_queue.put(request)

    def get_response(self) -> Optional[SolverResponse]:
        """Poll for a completed response. Returns None if nothing ready."""
        try:
            response = self._response_queue.get(timeout=1)
            with self._lock:
                self._status = SolverStatus.IDLE
            return response
        except Exception:
            return None

    def _worker_loop(self) -> None:
        """Main loop: create solver, process requests until shutdown."""
        solver = self._create_solver()

        while self._status != SolverStatus.SHUTDOWN:
            try:
                request = self._request_queue.get(timeout=1)

                if request is None:
                    continue

                response = self._solve(solver, request)
                self._response_queue.put(response)

            except Exception as e:
                logger.error(f"Worker {self._worker_id} error: {e}")
                time.sleep(0.1)

        self._destroy_solver(solver)

    def _create_solver(self):
        """Instantiate a Z3 solver with configured options."""
        try:
            if self._config.solver_type == SolverType.Z3:
                import z3
                solver = z3.Solver()
                if self._config.options:
                    for key, value in self._config.options.items():
                        solver.set(key, value)
                return solver
        except Exception as e:
            logger.warning(f"Failed to create solver: {e}")
        return None

    def _destroy_solver(self, solver) -> None:
        """Release solver resources."""
        try:
            if solver:
                del solver
        except Exception:
            logger.debug("suppressed", exc_info=True)

    def _solve(self, solver, request: SolverRequest) -> SolverResponse:
        """Parse SMT2 constraints, check satisfiability, return model."""
        start_time = time.time()

        try:
            if solver is None:
                return SolverResponse(
                    request_id=request.request_id,
                    result="unknown",
                    status="error",
                    error="Solver not initialized")

            timeout = request.timeout or self._config.timeout_seconds
            solver.set("timeout", timeout * 1000)

            import z3
            constraints = z3.parse_smt2_string(request.constraints)

            for constraint in constraints:
                solver.add(constraint)

            result = str(solver.check())

            model = None
            if result == "sat":
                model = str(solver.model())

            solver.reset()

            return SolverResponse(
                request_id=request.request_id,
                result=result,
                status="success",
                model=model,
                execution_time=time.time() - start_time)

        except Exception as e:
            return SolverResponse(
                request_id=request.request_id,
                result="unknown",
                status="error",
                error=str(e),
                execution_time=time.time() - start_time)

    @property
    def status(self) -> SolverStatus:
        """Current worker status."""
        return self._status


class SolverPool:
    """Manages a fixed-size pool of SolverWorkers. Dispatches requests to
    idle workers on a background thread. Supports dynamic resize."""

    def __init__(self, pool_size: int = 4, config: Optional[SolverConfig] = None):
        self._pool_size = pool_size
        self._config = config or SolverConfig(solver_type=SolverType.Z3)
        self._workers: List[SolverWorker] = []
        self._pending_requests: Queue = Queue()
        self._lock = threading.RLock()
        self._running = False

    def start(self) -> None:
        """Launch all workers and the dispatch thread."""
        with self._lock:
            if self._running:
                return

            self._running = True

            for i in range(self._pool_size):
                worker = SolverWorker(i, self._config)
                if worker.start():
                    self._workers.append(worker)

            dispatch_thread = threading.Thread(
                target=self._dispatch_loop,
                daemon=True
            )
            dispatch_thread.start()

            logger.info(f"Solver pool started with {len(self._workers)} workers")

    def stop(self) -> None:
        """Stop all workers and the dispatch loop."""
        with self._lock:
            self._running = False

            for worker in self._workers:
                worker.stop()

            self._workers.clear()
            logger.info("Solver pool stopped")

    def submit(self, constraints: str, timeout: Optional[int] = None,
               options: Optional[Dict[str, Any]] = None) -> str:
        """Enqueue a constraint set; return a request_id for later retrieval."""
        request_id = f"req_{int(time.time())}_{id(constraints)}"
        request = SolverRequest(
            request_id=request_id,
            constraints=constraints,
            timeout=timeout,
            options=options or {}
        )
        self._pending_requests.put(request)
        return request_id

    def get_result(self, request_id: str, timeout: int = 60) -> Optional[SolverResponse]:
        """Poll all workers for a matching response, up to timeout seconds."""
        start_time = time.time()

        while time.time() - start_time < timeout:
            for worker in self._workers:
                response = worker.get_response()
                if response and response.request_id == request_id:
                    return response
            time.sleep(0.1)

        return None

    def _dispatch_loop(self) -> None:
        """Background thread: dequeue pending requests and assign to idle workers."""
        while self._running:
            try:
                request = self._pending_requests.get(timeout=1)

                if request is None:
                    continue

                worker = self._find_idle_worker()

                if worker:
                    worker.submit_request(request)
                else:
                    self._pending_requests.put(request)
                    time.sleep(0.1)

            except Exception as e:
                logger.error(f"Dispatch loop error: {e}")

    def _find_idle_worker(self) -> Optional[SolverWorker]:
        """Return the first idle worker, or None."""
        with self._lock:
            for worker in self._workers:
                if worker.status == SolverStatus.IDLE:
                    return worker
            return None

    def get_stats(self) -> Dict[str, Any]:
        """Snapshot of pool state."""
        idle_count = sum(1 for w in self._workers if w.status == SolverStatus.IDLE)
        busy_count = sum(1 for w in self._workers if w.status == SolverStatus.BUSY)
        error_count = sum(1 for w in self._workers if w.status == SolverStatus.ERROR)

        return {
            "pool_size": self._pool_size,
            "active_workers": len(self._workers),
            "idle_workers": idle_count,
            "busy_workers": busy_count,
            "error_workers": error_count,
            "pending_requests": self._pending_requests.qsize()
        }

    def resize(self, new_size: int) -> None:
        """Grow or shrink the worker pool in-place."""
        with self._lock:
            if new_size > self._pool_size:
                for i in range(self._pool_size, new_size):
                    worker = SolverWorker(i, self._config)
                    if worker.start():
                        self._workers.append(worker)
            elif new_size < self._pool_size:
                for i in range(new_size, self._pool_size):
                    if i < len(self._workers):
                        self._workers[i].stop()
                self._workers = self._workers[:new_size]

            self._pool_size = new_size


class SolverSession:
    """Accumulates constraints and submits them as a single combined query."""

    def __init__(self, pool: SolverPool):
        self._pool = pool
        self._constraints = []
        self._request_ids = []

    def add_constraint(self, constraint: str) -> None:
        """Append a constraint to the session buffer."""
        self._constraints.append(constraint)

    def add_constraints(self, constraints: List[str]) -> None:
        """Append multiple constraints."""
        self._constraints.extend(constraints)

    def check(self) -> Optional[SolverResponse]:
        """Submit all buffered constraints as one combined SMT2 string."""
        combined = "\n".join(self._constraints)
        request_id = self._pool.submit(combined)
        self._request_ids.append(request_id)
        return self._pool.get_result(request_id)

    def reset(self) -> None:
        """Clear the constraint buffer and request history."""
        self._constraints.clear()
        self._request_ids.clear()

    def get_history(self) -> List[str]:
        """Return all request IDs issued by this session."""
        return self._request_ids.copy()


class SolverCache:
    """In-memory response cache keyed by constraint hash. Evicts oldest on overflow."""

    def __init__(self, max_entries: int = 1000):
        self._cache: Dict[str, SolverResponse] = {}
        self._max_entries = max_entries
        self._lock = threading.RLock()

    def get(self, constraints_hash: str) -> Optional[SolverResponse]:
        """Look up a cached response."""
        with self._lock:
            return self._cache.get(constraints_hash)

    def set(self, constraints_hash: str, response: SolverResponse) -> None:
        """Store a response, evicting the oldest entry if at capacity."""
        with self._lock:
            if len(self._cache) >= self._max_entries:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[constraints_hash] = response

    def clear(self) -> None:
        """Drop all cached entries."""
        with self._lock:
            self._cache.clear()

    def stats(self) -> Dict[str, Any]:
        """Cache occupancy snapshot."""
        with self._lock:
            return {
                "entries": len(self._cache),
                "max_entries": self._max_entries
            }


# Module-level lazy singletons — instantiated on first access
_global_solver_pool: Optional[SolverPool] = None
_global_solver_cache: Optional[SolverCache] = None


def get_solver_pool(pool_size: int = 4) -> SolverPool:
    """Retrieve (or lazily create) the global solver pool."""
    global _global_solver_pool
    if _global_solver_pool is None:
        _global_solver_pool = SolverPool(pool_size=pool_size)
        _global_solver_pool.start()
    return _global_solver_pool


def get_solver_cache() -> SolverCache:
    """Retrieve (or lazily create) the global solver cache."""
    global _global_solver_cache
    if _global_solver_cache is None:
        _global_solver_cache = SolverCache()
    return _global_solver_cache


def solve_constraints(constraints: str, timeout: Optional[int] = None) -> Optional[SolverResponse]:
    """One-shot: submit constraints to the global pool and wait for the result."""
    pool = get_solver_pool()
    request_id = pool.submit(constraints, timeout)
    return pool.get_result(request_id, timeout or 60)
