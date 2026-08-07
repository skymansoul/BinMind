"""Redis-backed distributed worker: dequeue, execute, publish results."""
import logging
import json
import time
import signal
import uuid
import threading
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FutTimeout

_log = logging.getLogger(__name__)

# src/ 优先导入，不可用时内联简化实现
# worker.py 可独立运行，不依赖 src/ 子包
# 外部代码可以从 worker 导入 Task/Node 等核心类型
try:
    from .src.models import Task, Node, TaskStatus, TaskType
    from .src.circuit_breaker import CircuitBreaker as _ExtCircuitBreaker
    from .src.rate_limiter import TokenBucket as _ExtTokenBucket
    from .src.utils import retry as _src_retry, backoff_delay as _src_backoff
    _SRC_AVAILABLE = True
except ImportError:
    _SRC_AVAILABLE = False

    import enum as _enum
    from dataclasses import dataclass as _dc, field as _field

    class TaskStatus(_enum.Enum):
        PENDING = "pending"
        QUEUED = "queued"
        RUNNING = "running"
        SUCCESS = "success"
        FAILURE = "failure"
        RETRYING = "retrying"
        CANCELLED = "cancelled"

    class TaskType(_enum.Enum):
        STATIC_ANALYSIS = "static_analysis"
        DYNAMIC_ANALYSIS = "dynamic_analysis"
        SYMBOLIC = "symbolic"
        DECOMPILE = "decompile"
        CUSTOM = "custom"

    @_dc
    class Task:
        id: str = ""
        type: TaskType = TaskType.CUSTOM
        payload: dict = _field(default_factory=dict)
        priority: int = 0
        status: TaskStatus = TaskStatus.PENDING
        created_at: float = _field(default_factory=time.time)
        updated_at: float = _field(default_factory=time.time)
        retries: int = 0
        max_retries: int = 3
        timeout: float = 300.0
        tags: list = _field(default_factory=list)
        parent_id: str = None

    @_dc
    class Node:
        id: str = ""
        address: str = ""
        status: str = "offline"
        last_heartbeat: float = _field(default_factory=time.time)
        capacity: int = 1
        current_load: int = 0
        labels: dict = _field(default_factory=dict)
        version: str = "0.1.0"

    class _ExtCircuitBreaker:
        def __init__(self, failure_threshold=5, recovery_timeout=60.0, name="default"):
            self._threshold = failure_threshold
            self._cooldown = recovery_timeout
            self.name = name
            self._failures = 0
            self._state = "closed"
        def before_call(self): return self._state != "open"
        def on_success(self): self._failures = 0; self._state = "closed"
        def on_failure(self):
            self._failures += 1
            if self._failures >= self._threshold: self._state = "open"

    class _ExtTokenBucket:
        def __init__(self, rate, burst=None):
            self._rate = rate
            self._burst = burst or rate
            self._tokens = float(self._burst)
            self._last = time.monotonic()
        def allow(self):
            now = time.monotonic()
            self._tokens = min(self._burst, self._tokens + (now - self._last) * self._rate)
            self._last = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return True
            return False

try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


# 指数退避 — Google SRE 第23章 "应对过载" 的背压策略 + Celery retry_backoff
# 添加 ±25% 均匀抖动，避免批量重试导致的惊群效应
def _backoff_delay(attempt: int, base: float = 2.0, cap: float = 600.0) -> float:
    """第 attempt 次重试的等待秒数，含随机抖动。"""
    import random
    raw = min(base ** attempt, cap)
    return raw * (0.75 + random.random() * 0.5)


# Lua 脚本 — ZPOPMIN 取出 score ≤ now 的到期重试任务，原子搬迁到工作队列
# 在一个往返中完成「取出 + 推入」，避免竞态窗口
_RETRY_POP_LUA = """
local items = redis.call('ZPOPMIN', KEYS[1], ARGV[1])
if not items or #items == 0 then return 0 end
local moved = 0
for i = 1, #items, 2 do
    redis.call('RPUSH', KEYS[2], items[i])
    moved = moved + 1
end
return moved
"""


# 令牌桶限流器 — 惰性填充策略
# 不在后台线程中定时补充令牌，而是在每次 acquire() 时根据时间差计算应补数量
# 优势：零后台开销；代价：长时间空闲后的首次请求可能获得 burst 个令牌
# Stripe timed rate limiter, Envoy token bucket filter
class _TokenBucket:
    """惰性填充令牌桶。rate=每秒生成数, burst=桶容量（最大突发）。"""

    __slots__ = ('_rate', '_burst', '_tokens', '_last_fill')

    def __init__(self, rate: float, burst: int):
        self._rate = rate
        self._burst = burst
        self._tokens = float(burst)
        self._last_fill = time.monotonic()

    def acquire(self) -> bool:
        now = time.monotonic()
        elapsed = now - self._last_fill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_fill = now
        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return True
        return False


class WorkerConfig:
    def __init__(self, redis_url="redis://localhost:6379/0",
                 queue="binmind:tasks", result_queue="binmind:results",
                 poll_timeout=5, max_retries=3):
        self.redis_url = redis_url
        self.queue = queue
        self.result_queue = result_queue
        self.poll_timeout = poll_timeout
        self.max_retries = max_retries
# 扩展配置，均设保守默认值以保证向后兼容
        self.dead_letter_queue = f"{queue}:dlq"
        self.retry_sorted_set = f"{queue}:retry"        # score = 下次执行时间戳
        self.heartbeat_key = "binmind:workers:heartbeat"
        self.heartbeat_interval = 15                     # TTL = interval × 3
        self.max_workers = 4
        self.job_timeout = 300
        self.breaker_threshold = 5                       # 连续失败 N 次 → 熔断
        self.breaker_cooldown = 60                       # 冷却秒数
        self.reconnect_base = 1.0
        self.reconnect_cap = 30.0
        # 优先级队列: {队列后缀: 轮询权重}, 权重大的被 BLPOP 抢占概率更高
        # 空字典退化为原始单队列模式
        self.priority_tiers: dict = {}
        # 每 handler 的令牌桶限流: {handler_name: (rate, burst)}
        self.rate_limits: dict = {}
        # 每 handler 的重试覆盖: {handler_name: max_retries}
        self.handler_retries: dict = {}


class AnalysisJob:
    def __init__(self, job_id="", binary_path="", analysis_type="", params=None):
        self.job_id = job_id or str(uuid.uuid4())[:8]
        self.binary_path = binary_path
        self.analysis_type = analysis_type
        self.params = params or {}

    def to_dict(self):
        return {"id": self.job_id, "binary": self.binary_path,
                "type": self.analysis_type, "params": self.params}

    @classmethod
    def from_dict(cls, d):
        return cls(d.get("id", ""), d.get("binary", ""),
                   d.get("type", ""), d.get("params", {}))


class JobResult:
    def __init__(self, job_id="", ok=True, findings=None, error=""):
        self.job_id = job_id
        self.ok = ok
        self.findings = findings or []
        self.error = error
        self.worker_id = ""

    def to_dict(self):
        return {"id": self.job_id, "ok": self.ok,
                "findings": self.findings, "error": self.error,
                "worker_id": self.worker_id}


# 熔断器 — Michael Nygard "Release It!" 三态断路器
# 按 handler 类型独立维护故障计数，避免一个异常 handler 拖垮整个 worker
# 半开状态允许一次探测：成功 → 关闭，失败 → 重新熔断
class _CircuitBreaker:
    """Per-handler circuit breaker with half-open probe."""

    __slots__ = ('_threshold', '_cooldown', '_failures', '_opened_at')

    def __init__(self, threshold: int = 5, cooldown: float = 60.0):
        self._threshold = threshold
        self._cooldown = cooldown
        self._failures: dict = {}
        self._opened_at: dict = {}

    def allow(self, handler_name: str) -> bool:
        opened = self._opened_at.get(handler_name)
        if opened is None:
            return True
        if time.monotonic() - opened >= self._cooldown:
            return True   # 半开
        return False

    def record_success(self, handler_name: str):
        self._failures[handler_name] = 0
        self._opened_at.pop(handler_name, None)

    def record_failure(self, handler_name: str):
        cnt = self._failures.get(handler_name, 0) + 1
        self._failures[handler_name] = cnt
        if cnt >= self._threshold:
            self._opened_at[handler_name] = time.monotonic()

    def state(self, handler_name: str) -> str:
        if handler_name not in self._opened_at:
            return "closed"
        if self.allow(handler_name):
            return "half-open"
        return "open"


class Worker:
    """Blocking queue consumer: pop job, dispatch to handler, push result."""

    def __init__(self, config=None):
        self.cfg = config or WorkerConfig()
        self._stop = threading.Event()
        self._running = False
        self.worker_id = str(uuid.uuid4())[:8]
        self._handlers = {}
        self._client = None
        self._connect()

        self._pool = ThreadPoolExecutor(max_workers=self.cfg.max_workers,
                                        thread_name_prefix=f"bmw-{self.worker_id}")
        self._inflight: dict = {}
        self._metrics = {"processed": 0, "failed": 0, "retried": 0,
                         "dlq": 0, "rate_limited": 0, "skipped_empty": 0}
        self._breaker = _CircuitBreaker(self.cfg.breaker_threshold,
                                        self.cfg.breaker_cooldown)
        self._retry_script = None
        self._heartbeat_thread = None
        # 令牌桶按 handler_name 惰性创建
        self._buckets: dict = {}
        # 优先级轮询计数器：记录当前循环号，用于决定本轮轮询哪个队列
        self._poll_counter = 0

# 连接管理：指数退避重连
    def _connect(self):
        if not REDIS_AVAILABLE:
            _log.warning("redis not available")
            return
        attempt = 0
        while not self._stop.is_set():
            try:
                self._client = _redis.Redis.from_url(self.cfg.redis_url,
                                                      socket_timeout=10,
                                                      socket_connect_timeout=5,
                                                      decode_responses=True)
                self._client.ping()
                _log.info("worker %s connected to redis", self.worker_id)
                self._retry_script = self._client.register_script(_RETRY_POP_LUA)
                return
            except Exception:
                attempt += 1
                delay = min(self.cfg.reconnect_base * (2 ** (attempt - 1)),
                            self.cfg.reconnect_cap)
                _log.warning("redis connect attempt %d failed, retry in %.1fs",
                             attempt, delay)
                time.sleep(delay)

    def _ensure_connected(self):
        if self._client is not None:
            try:
                self._client.ping()
                return
            except Exception:
                self._client = None
        self._connect()

# 心跳：后台 daemon 线程，周期性 SET with PX
    def _heartbeat_loop(self):
        ttl_ms = self.cfg.heartbeat_interval * 3 * 1000
        while not self._stop.is_set():
            if self._client:
                try:
                    self._client.set(self.cfg.heartbeat_key,
                                     json.dumps({"worker": self.worker_id,
                                                 "at": time.time()}),
                                     px=ttl_ms)
                except Exception:
                    pass
            self._stop.wait(self.cfg.heartbeat_interval)

# 限流器懒初始化
    def _get_bucket(self, handler_name: str):
        if handler_name in self._buckets:
            return self._buckets[handler_name]
        spec = self.cfg.rate_limits.get(handler_name)
        if spec is None:
            self._buckets[handler_name] = None
            return None
        rate, burst = spec
        self._buckets[handler_name] = _TokenBucket(rate, burst)
        return self._buckets[handler_name]

# 公开 API（向后兼容）
    def register_handler(self, analysis_type, func):
        self._handlers[analysis_type] = func

    def start(self):
        self._running = True
        _log.info("worker %s starting, listening on %s", self.worker_id, self.cfg.queue)
        signal.signal(signal.SIGTERM, lambda *_: self.stop())
        signal.signal(signal.SIGINT, lambda *_: self.stop())
        self._heartbeat_thread = threading.Thread(target=self._heartbeat_loop,
                                                   daemon=True,
                                                   name=f"bmw-hb-{self.worker_id}")
        self._heartbeat_thread.start()
        self._worker_loop()

    def stop(self):
        _log.info("worker %s shutting down", self.worker_id)
        self._running = False
        self._stop.set()

# 主循环
    def _worker_loop(self):
        while self._running:
            try:
                self._ensure_connected()
                self._collect_completed()
                self._poll_priority()
                self._drain_retry_set()
            except Exception:
                _log.exception("main loop error")
                time.sleep(0.5)

        # 优雅停机：等待在途任务至多 job_timeout 秒
        self._drain_inflight()
        self._pool.shutdown(wait=True)

# 优先级轮询
    def _poll_priority(self):
        """若未配置 priority_tiers，退化为原始单队列 BLPOP。
        若配置了优先级，基于加权轮询决定本轮从哪个队列拉取。
        权重比例如 {"high": 5, "medium": 3, "low": 1} 表示每 9 轮中 high 得 5 次。"""
        if self._client is None:
            time.sleep(self.cfg.poll_timeout)
            return

        tiers = self.cfg.priority_tiers
        if not tiers:
            self._poll_queue(self.cfg.queue)
            return

        # 加权选择
        self._poll_counter += 1
        total_weight = sum(tiers.values())
        if total_weight <= 0:
            self._poll_queue(self.cfg.queue)
            return

        pos = self._poll_counter % total_weight
        cumulative = 0
        chosen_suffix = None
        for suffix, w in tiers.items():
            cumulative += w
            if pos < cumulative:
                chosen_suffix = suffix
                break

        if chosen_suffix is None:
            chosen_suffix = next(iter(tiers))

        queue_name = f"{self.cfg.queue}:{chosen_suffix}"
        self._poll_queue(queue_name)

    def _poll_queue(self, queue_name: str):
        raw = self._client.blpop(queue_name, timeout=1)
        if raw is None:
            self._metrics["skipped_empty"] += 1
            return
        _, payload = raw
        try:
            job_dict = json.loads(payload)
            job = AnalysisJob.from_dict(job_dict)
        except (json.JSONDecodeError, TypeError):
            _log.warning("bad payload from %s, discarded", queue_name)
            return

        retries = job_dict.get("_retries", 0)

        # 限流门控 — 在提交线程池之前检查
        bucket = self._get_bucket(job.analysis_type)
        if bucket is not None and not bucket.acquire():
            # 限流触发 → 延迟重新入队，不消耗 retry 配额
            self._metrics["rate_limited"] += 1
            self._schedule_retry(job, retries, 1.0)
            return

        _log.info("worker %s processing %s (type=%s, retry=%d, q=%s)",
                  self.worker_id, job.job_id, job.analysis_type, retries, queue_name)

        fut = self._pool.submit(self._execute_with_timeout, job, retries)
        self._inflight[fut] = job

# 原有的 _poll 保留为内部方法，由 _poll_priority 委派
    def _poll(self):
        """单队列轮询 — 保留以支持外部代码直接调用的兼容场景。"""
        if self._client is None:
            time.sleep(self.cfg.poll_timeout)
            return
        self._poll_queue(self.cfg.queue)

# 双层超时: 外层对整体加硬超时，内层为实际执行
    def _execute_with_timeout(self, job: AnalysisJob, retries: int = 0) -> JobResult:
        fut_inner = self._pool.submit(self._execute, job, retries)
        try:
            return fut_inner.result(timeout=self.cfg.job_timeout)
        except FutTimeout:
            return JobResult(job.job_id, ok=False,
                             error=f"timeout after {self.cfg.job_timeout}s")

    def _execute(self, job: AnalysisJob, retries: int = 0) -> JobResult:
        handler = self._handlers.get(job.analysis_type)
        if handler is None:
            return JobResult(job.job_id, ok=False,
                             error=f"no handler for {job.analysis_type}")

        # 熔断器门控
        if not self._breaker.allow(job.analysis_type):
            self._schedule_retry(job, retries, self.cfg.breaker_cooldown)
            return JobResult(job.job_id, ok=False,
                             error=f"circuit open for {job.analysis_type}, requeued")

        # 每 handler 可覆盖 max_retries
        max_r = self.cfg.handler_retries.get(job.analysis_type, self.cfg.max_retries)

        try:
            findings = handler(job.binary_path, **job.params)
            self._breaker.record_success(job.analysis_type)
            return JobResult(job.job_id, ok=True, findings=findings)
        except Exception as e:
            _log.exception("job %s failed", job.job_id)
            self._breaker.record_failure(job.analysis_type)

            if retries < max_r:
                delay = _backoff_delay(retries + 1)
                self._schedule_retry(job, retries + 1, delay)
                return JobResult(job.job_id, ok=False,
                                 error=f"will retry in {delay:.1f}s")

            self._send_to_dlq(job, str(e), retries)
            return JobResult(job.job_id, ok=False, error=str(e))

# 重试调度：sorted set 按时间戳索引延迟任务
    def _schedule_retry(self, job: AnalysisJob, retry_count: int, delay: float):
        """写入 sorted set，score = 预定执行时间。
        _drain_retry_set 周期原子搬迁到期任务。
        选 sorted set 而非额外 scheduler 进程：减少运维组件，利用 Redis 原子性。"""
        payload = job.to_dict()
        payload["_retries"] = retry_count
        score = time.time() + delay
        try:
            self._client.zadd(self.cfg.retry_sorted_set, {json.dumps(payload): score})
            self._metrics["retried"] += 1
        except Exception:
            _log.exception("retry schedule failed for %s → dlq", job.job_id)
            self._send_to_dlq(job, "retry schedule failed", retry_count)

# 死信队列
    def _send_to_dlq(self, job: AnalysisJob, reason: str, retries: int):
        """永久失败任务入 DLQ，保留完整现场供运维排查和手动重放。"""
        dlq_entry = {"job": job.to_dict(), "reason": reason,
                     "retries_attempted": retries,
                     "worker_id": self.worker_id, "ts": time.time()}
        try:
            self._client.rpush(self.cfg.dead_letter_queue, json.dumps(dlq_entry))
            self._metrics["dlq"] += 1
            _log.info("job %s → dlq (reason=%s, retries=%d)", job.job_id, reason, retries)
        except Exception:
            _log.exception("critical: dlq write failed for %s", job.job_id)

    def _drain_retry_set(self):
        """单次搬迁上限 10 条，避免在主循环中阻塞过久。"""
        if self._client is None or self._retry_script is None:
            return
        try:
            moved = self._retry_script(
                keys=[self.cfg.retry_sorted_set, self.cfg.queue], args=[10]
            )
            if moved:
                _log.debug("moved %d retry jobs back to queue", moved)
        except Exception:
            pass

# 结果收集：非阻塞轮询已完成 future
    def _collect_completed(self):
        done = [f for f in self._inflight if f.done()]
        for fut in done:
            job = self._inflight.pop(fut)
            try:
                result = fut.result(timeout=0)
            except Exception as e:
                result = JobResult(job.job_id, ok=False, error=str(e))
            result.worker_id = self.worker_id
            self._publish_result(result)
            self._metrics["processed" if result.ok else "failed"] += 1

    def _publish_result(self, result: JobResult):
        if self._client is None:
            return
        try:
            self._client.rpush(self.cfg.result_queue, json.dumps(result.to_dict()))
        except Exception:
            _log.exception("failed to publish result for %s", result.job_id)

# 优雅停机：排空在途任务
    def _drain_inflight(self):
        if not self._inflight:
            return
        deadline = time.monotonic() + self.cfg.job_timeout
        remaining = list(self._inflight.items())
        for fut, job in remaining:
            timeout = max(0, deadline - time.monotonic())
            try:
                result = fut.result(timeout=timeout)
                result.worker_id = self.worker_id
                self._publish_result(result)
            except FutTimeout:
                _log.warning("inflight job %s not done by deadline → dlq", job.job_id)
                self._send_to_dlq(job, "worker shutdown timeout", 0)
            except Exception as e:
                self._send_to_dlq(job, f"worker shutdown: {e}", 0)
            self._inflight.pop(fut, None)

    def submit(self, job: AnalysisJob):
        if self._client is None:
            raise RuntimeError("not connected to redis")

        # 若配置了优先级队列，路由到对应 tier
        tiers = self.cfg.priority_tiers
        if tiers:
            priority = job.params.get("priority", "")
            if priority in tiers:
                target_q = f"{self.cfg.queue}:{priority}"
                self._client.rpush(target_q, json.dumps(job.to_dict()))
                return
        self._client.rpush(self.cfg.queue, json.dumps(job.to_dict()))

    def fetch_result(self, timeout=10):
        if self._client is None:
            return None
        raw = self._client.blpop(self.cfg.result_queue, timeout=timeout)
        if raw is None:
            return None
        _, payload = raw
        return JobResult(**json.loads(payload))

    @property
    def connected(self):
        return self._client is not None

# 运维接口
    @property
    def metrics(self):
        return dict(self._metrics)

    @property
    def inflight_count(self):
        return len(self._inflight)

    @property
    def pool_health(self):
        """线程池快照：{max_workers, inflight}。"""
        return {
            "max_workers": self.cfg.max_workers,
            "inflight": len(self._inflight),
        }

    def queue_depth(self, queue_name: str = None) -> int:
        """查询指定队列的积压量。不传参则查询默认队列。"""
        if self._client is None:
            return -1
        q = queue_name or self.cfg.queue
        return self._client.llen(q)

    def breaker_state(self, handler_name: str) -> str:
        return self._breaker.state(handler_name)

    def dlq_inspect(self, count: int = 10):
        if self._client is None:
            return []
        items = self._client.lrange(self.cfg.dead_letter_queue, -count, -1)
        return [json.loads(i) for i in items]

    def dlq_retry_one(self, index_from_tail: int = -1):
        if self._client is None:
            return False
        raw = self._client.lindex(self.cfg.dead_letter_queue, index_from_tail)
        if raw is None:
            return False
        entry = json.loads(raw)
        job_dict = entry.get("job", {})
        job_dict.pop("_retries", None)
        self._client.rpush(self.cfg.queue, json.dumps(job_dict))
        self._client.lrem(self.cfg.dead_letter_queue, 1, raw)
        _log.info("dlq job %s re-queued", job_dict.get("id", "unknown"))
        return True


# FIX: CELERY_AVAILABLE 曾被错误地别名为 REDIS_AVAILABLE。
# Celery 依赖 Redis 但 Redis != Celery。此处为非 Celery worker。
# 原始 bug 行保留供考古:
# CELERY_AVAILABLE = REDIS_AVAILABLE  # ← 语义错误: 混淆了 broker 与框架
CELERY_AVAILABLE = False  # worker_v1 使用原始 Redis，非 Celery
