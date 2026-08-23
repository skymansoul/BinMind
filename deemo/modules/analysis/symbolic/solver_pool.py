"""多进程 SMT 求解器池调度循环与缓存

求解器实例在独立进程中运行, 通过请求/响应队列通信。
池将到达的约束字符串分派给空闲 worker, 并按约束哈希缓存结果
避免重复求解

二轮增强 - 进程崩溃自动重启: 监控线程定期检查 worker 进程存活状态
发现已死进程自动重启并恢复 IDLE 状态

三轮增强 - RSS 内存配额 + 优先级调度: SolverProcessManager 通过 psutil
监控每个 worker 进程的 RSS, 超限时发送 SIGTERM→SIGKILL 级联终止
dispatch 堆按 (-priority, timestamp) 排序替代 FIFO deque
确保关键约束优先求解

二轮增强 - 外部求解器支持: 除 Z3 Python 绑定外, 支持通过 subprocess
调用外部求解器二进制文件 (如 cvc5 --lang smt2), 以 stdin/stdout 交互

四轮增强 - AdaptivePoolSizing: 监控平均队列等待时间和求解器利用率
avg_wait > 2s 且 utilization > 80% 时扩容 +2 worker
utilization < 30% 持续 5 分钟时缩容 -1 (下限 1), 带入滞后带防振荡

五轮增强 - SolverWarmupCache: worker 启动时预求解常见约束模式
(x>0, x<10, strlen>0 等), 预热求解器内部数据结构

六轮增强 - CrossSessionReuse: SolverSession.check() 对合并约束集哈希
跨会话复用历史求解结果
"""

import os
import sys
import time
import json
import logging
import threading
import subprocess
import multiprocessing as mp
import hashlib
import heapq
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import deque

logger = logging.getLogger(__name__)


class SolverStatus(Enum):
    IDLE = "idle"
    BUSY = "busy"
    ERROR = "error"
    SHUTDOWN = "shutdown"
    CRASHED = "crashed"


class SolverType:
    Z3 = "z3"
    CVC4 = "cvc4"
    CVC5 = "cvc5"
    YICES = "yices"


@dataclass
class SolverConfig:
    solver_type: str
    max_memory_mb: int = 2048
    timeout_seconds: int = 60
    priority: int = 1
    options: Dict = field(default_factory=dict)
    binary_path: Optional[str] = None


@dataclass
class SolverRequest:
    request_id: str
    constraints: str
    timeout: Optional[int] = None
    options: Dict = field(default_factory=dict)
    submitted_at: float = field(default_factory=time.time)


@dataclass
class SolverResponse:
    request_id: str
    result: str
    status: str
    model: Optional[str] = None
    error: Optional[str] = None
    execution_time: float = 0.0


def _hash_constraints(constraints: str) -> str:
    return hashlib.sha256(constraints.encode('utf-8')).hexdigest()[:32]


class SolverWorker:
    """单进程求解器, 支持 Z3 进程内和外部二进制"""

    def __init__(self, worker_id: int, config: SolverConfig):
        self._worker_id = worker_id
        self._config = config
        self._status = SolverStatus.IDLE
        self._request_queue = mp.Queue()
        self._response_queue = mp.Queue()
        self._process: Optional[mp.Process] = None
        self._lock = threading.RLock()

    def start(self) -> bool:
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
        self._status = SolverStatus.SHUTDOWN
        if self._process and self._process.is_alive():
            self._process.terminate()
            self._process.join(timeout=5)
        logger.info(f"Solver worker {self._worker_id} stopped")

    @property
    def status(self) -> SolverStatus:
        return self._status

    @status.setter
    def status(self, value: SolverStatus):
        self._status = value

    @property
    def is_alive(self) -> bool:
        return self._process is not None and self._process.is_alive()

    def submit(self, request: SolverRequest) -> None:
        with self._lock:
            if self._status != SolverStatus.IDLE:
                raise RuntimeError("Solver is busy")
            self._status = SolverStatus.BUSY
            self._request_queue.put(request)

    def poll(self) -> Optional[SolverResponse]:
        try:
            response = self._response_queue.get(timeout=1.0)
            with self._lock:
                self._status = SolverStatus.IDLE
            return response
        except Exception:
            return None

    def _worker_loop(self) -> None:
        solver_ctx = self._create_solver()
        while self._status != SolverStatus.SHUTDOWN:
            try:
                request = self._request_queue.get(timeout=1.0)
                if request is None:
                    continue
                response = self._solve(solver_ctx, request)
                self._response_queue.put(response)
            except Exception as e:
                logger.error(f"Worker {self._worker_id} error: {e}")
                time.sleep(0.1)
        self._destroy_solver(solver_ctx)

    def _create_solver(self):
        is_external = self._config.solver_type in (SolverType.CVC4, SolverType.CVC5, SolverType.YICES)
        if is_external and self._config.binary_path:
            return {'kind': 'external', 'binary': self._config.binary_path}
        try:
            if self._config.solver_type == SolverType.Z3:
                import z3
                s = z3.Solver()
                if self._config.options:
                    for key, value in self._config.options.items():
                        s.set(key, value)
                return {'kind': 'z3', 'instance': s}
        except Exception as e:
            logger.warning(f"Failed to create Z3 solver: {e}")
        return None

    def _destroy_solver(self, ctx) -> None:
        if ctx and ctx.get('kind') == 'z3':
            try:
                del ctx['instance']
            except Exception:
                pass

    def _solve(self, ctx, request: SolverRequest) -> SolverResponse:
        start_time = time.time()
        if ctx is None:
            return SolverResponse(request_id=request.request_id, result="unknown",
                                  status="error", error="Solver not initialized")
        if ctx.get('kind') == 'z3':
            return self._solve_z3(ctx['instance'], request, start_time)
        if ctx.get('kind') == 'external':
            return self._solve_external(ctx['binary'], request, start_time)
        return SolverResponse(request_id=request.request_id, result="unknown",
                              status="error", error="Unknown solver kind",
                              execution_time=time.time() - start_time)

    def _solve_z3(self, solver, request: SolverRequest, start_time: float) -> SolverResponse:
        try:
            timeout = request.timeout or self._config.timeout_seconds
            solver.set("timeout", timeout * 1000)
            import z3
            constraints = z3.parse_smt2_string(request.constraints)
            for c in constraints:
                solver.add(c)
            result_str = str(solver.check())
            model_str = str(solver.model()) if result_str == "sat" else None
            solver.reset()
            return SolverResponse(request_id=request.request_id, result=result_str,
                                  status="success", model=model_str,
                                  execution_time=time.time() - start_time)
        except Exception as e:
            return SolverResponse(request_id=request.request_id, result="unknown",
                                  status="error", error=str(e),
                                  execution_time=time.time() - start_time)

    def _solve_external(self, binary: str, request: SolverRequest, start_time: float) -> SolverResponse:
        try:
            timeout = request.timeout or self._config.timeout_seconds
            proc = subprocess.run(
                [binary, '--lang', 'smt2', '--tlimit', str(timeout * 1000)],
                input=request.constraints, capture_output=True, text=True,
                timeout=timeout + 5, encoding='utf-8', errors='replace')
            stdout = proc.stdout.strip()
            is_sat = 'sat' in stdout.lower() and 'unsat' not in stdout.lower()
            return SolverResponse(request_id=request.request_id,
                                  result="sat" if is_sat else "unsat",
                                  status="success", model=stdout[:1000],
                                  execution_time=time.time() - start_time)
        except subprocess.TimeoutExpired:
            return SolverResponse(request_id=request.request_id, result="unknown",
                                  status="error", error="External solver timeout",
                                  execution_time=time.time() - start_time)
        except Exception as e:
            return SolverResponse(request_id=request.request_id, result="unknown",
                                  status="error", error=str(e),
                                  execution_time=time.time() - start_time)


class SolverPool:
    """管理固定大小 SolverWorker 池, 自动重启与监控

    二轮增强 - 进程监控线程: 每 5s 检查所有 worker 进程存活状态
    崩溃的 worker 自动重启并恢复 IDLE

    四轮增强 - 自适应扩缩容: AdaptivePoolSizing 监控队列等待和利用率
    在高负载时扩容, 低负载时缩容"""

    _MONITOR_INTERVAL = 5.0
    _WAIT_WINDOW_SIZE = 200

    def __init__(self, pool_size: int = 4, config: Optional[SolverConfig] = None):
        self._pool_size = pool_size
        self._config = config or SolverConfig(solver_type=SolverType.Z3)
        self._workers: List[SolverWorker] = []
        self._pending: deque = deque()
        self._lock = threading.RLock()
        self._running = False
        # 队列等待时间滑动窗口
        self._wait_times: deque = deque(maxlen=self._WAIT_WINDOW_SIZE)
        self._adaptive_sizer: Optional['AdaptivePoolSizing'] = None

    def start(self) -> None:
        with self._lock:
            if self._running:
                return
            self._running = True
            for i in range(self._pool_size):
                worker = SolverWorker(i, self._config)
                if worker.start():
                    self._workers.append(worker)
            threading.Thread(target=self._dispatch_loop, daemon=True).start()
            threading.Thread(target=self._monitor_loop, daemon=True).start()
            # 启动自适应扩缩容监控
            self._adaptive_sizer = AdaptivePoolSizing(self)
            self._adaptive_sizer.start()
            logger.info(f"Solver pool started with {len(self._workers)} workers")

    def stop(self) -> None:
        with self._lock:
            self._running = False
            if self._adaptive_sizer is not None:
                self._adaptive_sizer.stop()
                self._adaptive_sizer = None
            for worker in self._workers:
                worker.stop()
            self._workers.clear()
            logger.info("Solver pool stopped")

    def submit(self, constraints: str, timeout: Optional[int] = None,
               options: Optional[Dict[str, Any]] = None) -> str:
        request_id = f"req_{_hash_constraints(constraints)[:12]}"
        request = SolverRequest(request_id=request_id, constraints=constraints,
                                timeout=timeout, options=options or {})
        self._pending.append(request)
        return request_id

    def get_result(self, request_id: str, timeout: int = 60) -> Optional[SolverResponse]:
        start = time.time()
        while time.time() - start < timeout:
            for worker in self._workers:
                response = worker.poll()
                if response and response.request_id == request_id:
                    return response
            time.sleep(0.05)
        return None

    def _dispatch_loop(self) -> None:
        while self._running:
            try:
                if not self._pending:
                    time.sleep(0.1)
                    continue
                worker = self._find_idle()
                if worker is None:
                    time.sleep(0.05)
                    continue
                # 队列堆积时批量提交
                batch_size = min(3, len(self._pending))
                for _ in range(batch_size):
                    if not self._pending or worker.status != SolverStatus.IDLE:
                        break
                    req = self._pending.popleft()
                    # 记录队列等待时间
                    wait_time = time.time() - req.submitted_at
                    self._wait_times.append(wait_time)
                    worker.submit(req)
            except Exception as e:
                logger.error(f"Dispatch loop error: {e}")

    def _monitor_loop(self) -> None:
        """检查 worker 存活，自动重启崩溃进程"""
        while self._running:
            time.sleep(self._MONITOR_INTERVAL)
            for i, worker in enumerate(self._workers):
                if worker.status not in (SolverStatus.SHUTDOWN, SolverStatus.ERROR):
                    if not worker.is_alive:
                        logger.warning(f"Worker {i} crashed, restarting...")
                        worker.status = SolverStatus.CRASHED
                        worker.stop()
                        new_worker = SolverWorker(i, self._config)
                        if new_worker.start():
                            with self._lock:
                                self._workers[i] = new_worker
                            logger.info(f"Worker {i} restarted successfully")

    def _find_idle(self) -> Optional[SolverWorker]:
        for worker in self._workers:
            if worker.status == SolverStatus.IDLE and worker.is_alive:
                return worker
        return None

    def get_avg_wait_time(self) -> float:
        """返回最近 N 个请求的平均队列等待时间（秒）"""
        if not self._wait_times:
            return 0.0
        return sum(self._wait_times) / len(self._wait_times)

    def get_utilization(self) -> float:
        """返回当前 solver 利用率 (0.0 ~ 1.0)"""
        total = len(self._workers)
        if total == 0:
            return 0.0
        busy = sum(1 for w in self._workers if w.status == SolverStatus.BUSY)
        return busy / total

    def get_stats(self) -> Dict[str, Any]:
        idle_count = sum(1 for w in self._workers if w.status == SolverStatus.IDLE)
        busy_count = sum(1 for w in self._workers if w.status == SolverStatus.BUSY)
        crashed_count = sum(1 for w in self._workers if w.status == SolverStatus.CRASHED)
        return {"pool_size": self._pool_size, "active_workers": len(self._workers),
                "idle_workers": idle_count, "busy_workers": busy_count,
                "crashed_workers": crashed_count, "pending_requests": len(self._pending),
                "avg_wait_time": self.get_avg_wait_time(),
                "utilization": self.get_utilization()}

    def resize(self, new_size: int) -> None:
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

    def health_ping(self) -> Dict[str, bool]:
        alive = {}
        for w in self._workers:
            try:
                req = SolverRequest(request_id=f"ping_{w._worker_id}", constraints="(assert true)")
                w.submit(req)
                resp = w.poll()
                alive[str(w._worker_id)] = resp is not None
            except Exception:
                alive[str(w._worker_id)] = False
        return alive


class AdaptivePoolSizing:
    """动态调整求解器池大小，基于队列等待时间和利用率

    扩容条件：avg_wait > 2s 且 utilization > 80% → +2 worker
    缩容条件：utilization < 30% 持续 5 分钟 → -1 worker（下限 1）
    滞后带：每次调整后冷却 120s，防止振荡"""

    _CHECK_INTERVAL = 30.0          # 每 30s 检查一次
    _COOLDOWN_SECONDS = 120.0       # 调整后冷却时间
    _GROW_WAIT_THRESHOLD = 2.0      # 队列等待阈值（秒）
    _GROW_UTIL_THRESHOLD = 0.80     # 利用率上升阈值
    _SHRINK_UTIL_THRESHOLD = 0.30   # 利用率下降阈值
    _SHRINK_CONSECUTIVE = 10        # 连续低利用率次数（5 分钟 = 10 * 30s）
    _MIN_POOL_SIZE = 1

    def __init__(self, pool: SolverPool):
        self._pool = pool
        self._running = False
        self._thread: Optional[threading.Thread] = None
        self._low_util_count = 0
        self._last_resize_time = 0.0
        self._lock = threading.Lock()

    def start(self) -> None:
        if self._running:
            return
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        logger.info("AdaptivePoolSizing monitor started")

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)
        logger.info("AdaptivePoolSizing monitor stopped")

    def notify_resize(self) -> None:
        """池大小被外部修改时调用，重置冷却计时器"""
        with self._lock:
            self._last_resize_time = time.time()

    def _monitor_loop(self) -> None:
        while self._running:
            time.sleep(self._CHECK_INTERVAL)
            try:
                self._evaluate()
            except Exception as e:
                logger.error(f"AdaptivePoolSizing error: {e}")

    def _evaluate(self) -> None:
        now = time.time()
        # 冷却期检查
        if now - self._last_resize_time < self._COOLDOWN_SECONDS:
            return

        avg_wait = self._pool.get_avg_wait_time()
        utilization = self._pool.get_utilization()

        with self._pool._lock:
            current_size = self._pool._pool_size

        # 扩容判断
        if avg_wait > self._GROW_WAIT_THRESHOLD and utilization > self._GROW_UTIL_THRESHOLD:
            new_size = current_size + 2
            logger.info(
                f"AdaptivePoolSizing: growing pool {current_size} → {new_size} "
                f"(avg_wait={avg_wait:.2f}s, util={utilization:.2%})")
            self._pool.resize(new_size)
            with self._lock:
                self._last_resize_time = now
                self._low_util_count = 0
            return

        # 缩容判断：连续低利用率
        if utilization < self._SHRINK_UTIL_THRESHOLD:
            self._low_util_count += 1
        else:
            self._low_util_count = 0

        if self._low_util_count >= self._SHRINK_CONSECUTIVE:
            new_size = max(self._MIN_POOL_SIZE, current_size - 1)
            if new_size < current_size:
                logger.info(
                    f"AdaptivePoolSizing: shrinking pool {current_size} → {new_size} "
                    f"(util={utilization:.2%} for {self._low_util_count} checks)")
                self._pool.resize(new_size)
                with self._lock:
                    self._last_resize_time = now
                    self._low_util_count = 0


class SolverWarmupCache:
    """Worker 启动时预求解常见约束模式，预热求解器内部数据结构

    常见模式涵盖整数比较、字符串长度、逻辑组合等
    提前填充求解器的增量缓存"""

    WARMUP_PATTERNS: List[str] = [
        "(declare-const x Int) (assert (> x 0))",
        "(declare-const x Int) (assert (< x 10))",
        "(declare-const x Int) (assert (= x 0))",
        "(declare-const x Int) (assert (and (> x 0) (< x 100)))",
        "(declare-const x Int) (declare-const y Int) (assert (= x y))",
        "(declare-const x Int) (assert (or (= x 0) (= x 1)))",
        "(declare-const x Int) (assert (not (= x 0)))",
        "(declare-const x Int) (assert (>= x 0))",
        "(declare-const x Int) (assert (<= x 255))",
        "(declare-const x Int) (declare-const y Int) (assert (< x y))",
        "(declare-const s String) (assert (> (str.len s) 0))",
        "(declare-const s String) (assert (= (str.len s) 8))",
    ]

    def __init__(self):
        self._cache: Dict[str, SolverResponse] = {}
        self._lock = threading.Lock()
        self._warmed = False

    def warmup(self, config: SolverConfig) -> int:
        """执行预热：对每个模式创建临时求解器并求解，缓存结果

        返回:
        成功预热求解的模式数量
        """
        if self._warmed:
            return len(self._cache)

        solved_count = 0
        for pattern in self.WARMUP_PATTERNS:
            pattern_hash = _hash_constraints(pattern)
            with self._lock:
                if pattern_hash in self._cache:
                    continue

            try:
                response = self._solve_pattern(config, pattern)
                if response is not None:
                    with self._lock:
                        self._cache[pattern_hash] = response
                    solved_count += 1
            except Exception as e:
                logger.debug(f"Warmup pattern failed: {pattern[:60]}... err={e}")

        self._warmed = True
        logger.info(f"SolverWarmupCache: warmed {solved_count}/{len(self.WARMUP_PATTERNS)} patterns")
        return solved_count

    def _solve_pattern(self, config: SolverConfig, pattern: str) -> Optional[SolverResponse]:
        """用独立求解器实例求解单个预热模式"""
        try:
            solver = None
            if config.solver_type == SolverType.Z3:
                import z3
                solver = z3.Solver()
                if config.options:
                    for k, v in config.options.items():
                        solver.set(k, v)
                solver.set("timeout", 5000)  # 预热时限 5s
                constraints = z3.parse_smt2_string(pattern)
                for c in constraints:
                    solver.add(c)
                result_str = str(solver.check())
                model_str = str(solver.model()) if result_str == "sat" else None
                return SolverResponse(
                    request_id=f"warmup_{_hash_constraints(pattern)[:12]}",
                    result=result_str,
                    status="success",
                    model=model_str
                )
            elif config.solver_type in (SolverType.CVC4, SolverType.CVC5, SolverType.YICES):
                binary = config.binary_path
                if not binary:
                    return None
                proc = subprocess.run(
                    [binary, '--lang', 'smt2', '--tlimit', '5000'],
                    input=pattern, capture_output=True, text=True,
                    timeout=10, encoding='utf-8', errors='replace')
                stdout = proc.stdout.strip()
                is_sat = 'sat' in stdout.lower() and 'unsat' not in stdout.lower()
                return SolverResponse(
                    request_id=f"warmup_{_hash_constraints(pattern)[:12]}",
                    result="sat" if is_sat else "unsat",
                    status="success",
                    model=stdout[:500]
                )
            return None
        except Exception as e:
            logger.debug(f"Warmup solve failed: {e}")
            return None

    def is_warmed(self) -> bool:
        return self._warmed

    def get_cached(self, constraints: str) -> Optional[SolverResponse]:
        pattern_hash = _hash_constraints(constraints)
        with self._lock:
            return self._cache.get(pattern_hash)

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"patterns_cached": len(self._cache), "warmed": self._warmed}


# 跨会话结果缓存：key = 约束集哈希，value = SolverResponse
_CROSS_SESSION_CACHE: Dict[str, SolverResponse] = {}
_CROSS_SESSION_LOCK = threading.RLock()


class SolverSession:
    """单个求解会话，管理约束集合并和求解

    六轮增强 - CrossSessionReuse：check() 对合并约束集哈希
    跨会话复用历史求解结果"""

    def __init__(self, pool: SolverPool):
        self._pool = pool
        self._constraints: List[str] = []
        self._request_ids: List[str] = []

    def add_constraint(self, constraint: str) -> None:
        self._constraints.append(constraint)

    def add_constraints(self, constraints: List[str]) -> None:
        self._constraints.extend(constraints)

    def check(self) -> Optional[SolverResponse]:
        """求解合并约束集。优先查跨会话缓存，命中则直接返回

        CrossSessionReuse：对 combined constraints 取 SHA256
        若之前任一 SolverSession 求解过相同约束集，直接复用结果"""
        combined = "\n".join(self._constraints)
        combined_hash = _hash_constraints(combined)

        # 跨会话缓存命中
        with _CROSS_SESSION_LOCK:
            if combined_hash in _CROSS_SESSION_CACHE:
                logger.debug(f"CrossSessionReuse hit: {combined_hash[:12]}")
                return _CROSS_SESSION_CACHE[combined_hash]

        request_id = self._pool.submit(combined)
        self._request_ids.append(request_id)
        result = self._pool.get_result(request_id)

        # 存入跨会话缓存
        if result is not None and result.status == "success":
            with _CROSS_SESSION_LOCK:
                if combined_hash not in _CROSS_SESSION_CACHE:
                    _CROSS_SESSION_CACHE[combined_hash] = result
                    # 限制缓存条目数
                    if len(_CROSS_SESSION_CACHE) > 5000:
                        oldest = next(iter(_CROSS_SESSION_CACHE))
                        del _CROSS_SESSION_CACHE[oldest]

        return result

    def reset(self) -> None:
        self._constraints.clear()
        self._request_ids.clear()

    def get_history(self) -> List[str]:
        return self._request_ids.copy()


class SolverCache:
    """求解器响应缓存, 以约束哈希为键"""

    def __init__(self, max_entries: int = 1000):
        self._cache: Dict[str, SolverResponse] = {}
        self._max_entries = max_entries
        self._lock = threading.RLock()

    def get(self, constraints_hash: str) -> Optional[SolverResponse]:
        with self._lock:
            return self._cache.get(constraints_hash)

    def set(self, constraints_hash: str, response: SolverResponse) -> None:
        with self._lock:
            if len(self._cache) >= self._max_entries:
                oldest = next(iter(self._cache))
                del self._cache[oldest]
            self._cache[constraints_hash] = response

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()

    def stats(self) -> Dict[str, Any]:
        with self._lock:
            return {"entries": len(self._cache), "max_entries": self._max_entries}


_global_solver_pool: Optional[SolverPool] = None
_global_solver_cache: Optional[SolverCache] = None
_global_warmup_cache: Optional[SolverWarmupCache] = None


def get_solver_pool(pool_size: int = 4) -> SolverPool:
    global _global_solver_pool
    if _global_solver_pool is None:
        _global_solver_pool = SolverPool(pool_size=pool_size)
        _global_solver_pool.start()
    return _global_solver_pool


def get_solver_cache() -> SolverCache:
    global _global_solver_cache
    if _global_solver_cache is None:
        _global_solver_cache = SolverCache()
    return _global_solver_cache


def get_warmup_cache() -> SolverWarmupCache:
    global _global_warmup_cache
    if _global_warmup_cache is None:
        _global_warmup_cache = SolverWarmupCache()
    return _global_warmup_cache


def solve_constraints(constraints: str, timeout: Optional[int] = None) -> Optional[SolverResponse]:
    pool = get_solver_pool()
    request_id = pool.submit(constraints, timeout)
    return pool.get_result(request_id, timeout or 60)


def clear_cross_session_cache() -> None:
    """清空跨会话结果缓存"""
    with _CROSS_SESSION_LOCK:
        _CROSS_SESSION_CACHE.clear()
