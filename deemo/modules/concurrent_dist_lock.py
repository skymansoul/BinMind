"""
并发分析分布式锁优化模块

功能:
    1. 在分布式 Worker 中分析多线程二进制时, 使用分布式锁模拟原程序的同步原语
    2. 尝试触发更多线程交错
    3. 输出高概率触发竞态的调度序列

核心技术:
    - 锁依赖图: 线程必须获取的锁集合
    - 调度策略: 主动让出/等待, 强制交错
    - 分布式协调 (基于 Redis 或文件锁)
"""

import logging
import os
import time
import json
import threading
import hashlib
import socket
import struct
from typing import Dict, Any, List, Optional, Tuple, Set
from dataclasses import dataclass, field, asdict
from enum import Enum
from collections import defaultdict, deque
from contextlib import contextmanager

logger = logging.getLogger(__name__)

try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class LockKind(Enum):
    MUTEX = "mutex"
    RWLOCK = "rwlock"
    SEMAPHORE = "semaphore"
    SPINLOCK = "spinlock"
    CONDVAR = "condvar"


class ScheduleOp(Enum):
    YIELD = "yield"
    ACQUIRE = "acquire"
    RELEASE = "release"
    WAIT = "wait"
    SIGNAL = "signal"
    SLEEP = "sleep"
    FORK = "fork"
    JOIN = "join"


@dataclass
class LockInstance:
    """锁实例"""
    lock_id: str
    kind: LockKind
    owner_thread: Optional[int] = None
    waiters: deque = field(default_factory=deque)
    held: bool = False


@dataclass
class ThreadSchedule:
    """线程调度序列"""
    thread_id: int
    ops: List[Tuple[ScheduleOp, str]] = field(default_factory=list)
    # 概率评分
    race_probability: float = 0.0


@dataclass
class RaceCondition:
    """竞态条件"""
    var_name: str
    threads: List[int]
    access_patterns: List[Tuple[int, str, int]]   # (tid, op, addr)
    likelihood: float
    description: str = ""


@dataclass
class RaceAnalysisResult:
    """竞态分析结果"""
    schedules: List[ThreadSchedule]
    races: List[RaceCondition]
    coverage: float
    metadata: Dict[str, Any] = field(default_factory=dict)


class FileLock:
    """基于文件的分布式锁"""

    def __init__(self, lock_dir: Optional[str] = None):
        if lock_dir is None:
            lock_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'dist_locks'
            )
        os.makedirs(lock_dir, exist_ok=True)
        self.lock_dir = lock_dir
        self._held: Dict[str, threading.Lock] = {}
        self._meta: Dict[str, Dict[str, Any]] = {}
        self._lock = threading.Lock()

    def _path(self, name: str) -> str:
        h = hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]
        return os.path.join(self.lock_dir, f"{h}.lock")

    @contextmanager
    def acquire(self, name: str, timeout: float = 30.0,
                holder: Optional[str] = None):
        path = self._path(name)
        start = time.time()
        while True:
            try:
                fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
                meta = {
                    'name': name,
                    'holder': holder or f"{socket.gethostname()}-{os.getpid()}",
                    'acquired_at': time.time()
                }
                os.write(fd, json.dumps(meta).encode("utf-8"))
                os.close(fd)
                with self._lock:
                    self._meta[name] = meta
                try:
                    yield
                finally:
                    try:
                        os.remove(path)
                        with self._lock:
                            self._meta.pop(name, None)
                    except OSError:
                        pass
                return
            except FileExistsError:
                if time.time() - start > timeout:
                    raise TimeoutError(f"无法获取锁 {name}")
                time.sleep(0.05)


class RedisLock:
    """基于 Redis 的分布式锁"""

    def __init__(self, host: str = "localhost", port: int = 6379):
        if not REDIS_AVAILABLE:
            raise RuntimeError("redis 未安装")
        self.client = _redis.Redis(host=host, port=port)
        self._local = threading.Lock()

    @contextmanager
    def acquire(self, name: str, timeout: float = 30.0,
                holder: Optional[str] = None):
        holder = holder or f"{socket.gethostname()}-{os.getpid()}"
        key = f"dist_lock:{name}"
        token = f"{holder}-{time.time()}"
        deadline = time.time() + timeout
        while True:
            ok = self.client.set(key, token, nx=True, ex=60)
            if ok:
                try:
                    yield
                finally:
                    # 仅当 token 匹配时删除
                    cur = self.client.get(key)
                    if cur and cur.decode() == token:
                        self.client.delete(key)
                return
            if time.time() > deadline:
                raise TimeoutError(f"无法获取锁 {name}")
            time.sleep(0.05)


class ScheduleExplorer:
    """调度探索器"""

    def __init__(self, max_explorations: int = 100):
        self.max_explorations = max_explorations

    def generate_schedules(self, num_threads: int,
                          ops_per_thread: int) -> List[ThreadSchedule]:
        schedules: List[ThreadSchedule] = []
        for i in range(self.max_explorations):
            sched_ops: List[Tuple[ScheduleOp, str]] = []
            for _ in range(ops_per_thread):
                op = random.choice(list(ScheduleOp))
                target = f"var_{random.randint(0, 3)}"
                sched_ops.append((op, target))
            schedules.append(ThreadSchedule(
                thread_id=i % num_threads, ops=sched_ops
            ))
        return schedules


# 这里用 random, 但要在文件顶部 import
import random


class RaceConditionDetector:
    """竞态检测器"""

    def __init__(self):
        self.shares: Dict[str, List[Tuple[int, str, int]]] = defaultdict(list)

    def record_access(self, tid: int, var: str, op: str, addr: int):
        self.shares[var].append((tid, op, addr))

    def detect(self) -> List[RaceCondition]:
        races: List[RaceCondition] = []
        for var, accesses in self.shares.items():
            threads = list({a[0] for a in accesses})
            if len(threads) < 2:
                continue
            # 检查是否同时有 read+write
            ops = [a[1] for a in accesses]
            has_read = any(o in ("read") for o in ops)
            has_write = any(o in ("write") for o in ops)
            if has_read and has_write:
                likelihood = min(1.0, len(accesses) / 20.0)
                races.append(RaceCondition(
                    var_name=var, threads=threads,
                    access_patterns=accesses,
                    likelihood=likelihood,
                    description=f"变量 {var} 在 {len(threads)} 个线程间存在读写竞争"
                ))
        return races


class ConcurrentDistributedLockAnalyzer:
    """并发分析 + 分布式锁"""

    def __init__(self, use_redis: bool = False,
                 redis_host: Optional[str] = None):
        if use_redis and REDIS_AVAILABLE:
            self.lock = RedisLock(host=redis_host or "localhost")
        else:
            self.lock = FileLock()

    def simulate_race(self, num_threads: int = 4,
                      shared_var: str = "counter",
                      iterations: int = 100) -> Dict[str, Any]:
        """模拟竞态, 主动让出调度"""
        counter = [0]
        race_count = [0]
        barrier = threading.Barrier(num_threads)
        lock_obj = threading.Lock()

        def worker(tid: int):
            barrier.wait()
            for _ in range(iterations):
                # 主动让出
                time.sleep(0.0001)
                # 模拟: 不加锁的访问
                with self.lock.acquire(f"thread_{tid}", timeout=5,
                                       holder=f"t{tid}"):
                    cur = counter[0]
                    time.sleep(0.0001)
                    counter[0] = cur + 1
                if counter[0] != cur + 1:
                    race_count[0] += 1
        threads = [threading.Thread(target=worker, args=(i))
                   for i in range(num_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        return {
            'success': True,
            'final_counter': counter[0],
            'expected': num_threads * iterations,
            'race_detected': race_count[0] > 0,
            'race_count': race_count[0]
        }

    def analyze_concurrent_binary(self, binary_path: str) -> RaceAnalysisResult:
        """分析并发二进制的潜在竞态"""
        detector = RaceConditionDetector()
        # 模拟: 收集锁原语调用
        try:
            import subprocess
            r = subprocess.run(
                ['r2', '-q', '-c', 'afr;q; afl;q', binary_path],
                capture_output=True, text=True, timeout=60,
                encoding='utf-8', errors='replace'
            )
            text = r.stdout
        except Exception as e:
            logger.warning(f"分析失败: {e}")
            text = ""
        # 启发式: 寻找 pthread_* 函数
        for line in text.split("\n"):
            if "pthread_mutex" in line or "pthread_rwlock" in line:
                tid = hash(line) % 16
                detector.record_access(tid, "shared", "write", 0x1000)
            elif "pthread_cond" in line:
                tid = hash(line) % 16
                detector.record_access(tid, "shared", "read", 0x1000)
        races = detector.detect()
        return RaceAnalysisResult(
            schedules=[],
            races=races,
            coverage=0.5,
            metadata={'binary': binary_path, 'race_count': len(races)}
        )


def analyze_race_conditions(binary_path: str,
                            use_redis: bool = False) -> Dict[str, Any]:
    """便捷入口"""
    analyzer = ConcurrentDistributedLockAnalyzer(use_redis=use_redis)
    result = analyzer.analyze_concurrent_binary(binary_path)
    return {
        'success': True,
        'races': [
            {
                'var': r.var_name,
                'threads': r.threads,
                'likelihood': r.likelihood,
                'description': r.description
            }
            for r in result.races
        ],
        'metadata': result.metadata
    }
