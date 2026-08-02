# 2026-08-01
# distributed/ — 分布式任务调度系统的对外接口
# lazy import via __getattr__: 不引用不导入，减小冷启动开销
# 同时暴露 src/ 和 Worker 的扁平命名空间
#
# 热路径符号（Worker/Task/Node）预加载，避免 __getattr__ 首次访问延迟
# 其余按需加载，模块级别的 __getattr__ 仅在属性未命中时触发（PEP 562）

import importlib

__all__ = [
    # worker
    "Worker", "WorkerConfig", "AnalysisJob", "JobResult",
    # models
    "Task", "Node", "TaskStatus", "TaskType",
    # utils
    "retry", "backoff_delay", "setup_logging",
    # serialization
    "serialize", "deserialize",
    # priority
    "PriorityTaskQueue", "RedisPriorityQueue", "DeadLetterQueue",
    # scheduler
    "CronScheduler", "CronExpr", "parse_cron", "every",
    # batch
    "BatchCollector", "BatchPipeline",
    # circuit_breaker
    "CircuitState", "CircuitBreaker", "MultiBreaker", "SlidingWindowBreaker",
    # rate_limiter
    "TokenBucket", "DistributedTokenBucket", "ConcurrencyLimiter",
    "rate_limit", "RateLimitExceeded",
    # idempotency
    "IdempotencyGuard", "idempotency_key",
    # health
    "HealthServer", "HealthStatus",
    # pool
    "RedisPool",
    # metrics
    "Counter", "Gauge", "Histogram", "Summary", "Registry",
]

_MODULE_MAP: dict[str, str] = {
    "Worker": ".worker", "WorkerConfig": ".worker",
    "AnalysisJob": ".worker", "JobResult": ".worker",
    # src.
    "Task": ".src.models", "Node": ".src.models",
    "TaskStatus": ".src.models", "TaskType": ".src.models",
    "retry": ".src.utils", "backoff_delay": ".src.utils",
    "setup_logging": ".src.utils",
    "serialize": ".src.serialization", "deserialize": ".src.serialization",
    "PriorityTaskQueue": ".src.priority", "RedisPriorityQueue": ".src.priority",
    "DeadLetterQueue": ".src.priority",
    "CronScheduler": ".src.scheduler", "CronExpr": ".src.scheduler",
    "parse_cron": ".src.scheduler", "every": ".src.scheduler",
    "BatchCollector": ".src.batch", "BatchPipeline": ".src.batch",
    "CircuitState": ".src.circuit_breaker", "CircuitBreaker": ".src.circuit_breaker",
    "MultiBreaker": ".src.circuit_breaker", "SlidingWindowBreaker": ".src.circuit_breaker",
    "TokenBucket": ".src.rate_limiter", "DistributedTokenBucket": ".src.rate_limiter",
    "ConcurrencyLimiter": ".src.rate_limiter",
    "rate_limit": ".src.rate_limiter", "RateLimitExceeded": ".src.rate_limiter",
    "IdempotencyGuard": ".src.idempotency", "idempotency_key": ".src.idempotency",
    "HealthServer": ".src.health", "HealthStatus": ".src.health",
    "RedisPool": ".src.pool",
    "Counter": ".src.metrics", "Gauge": ".src.metrics",
    "Histogram": ".src.metrics", "Summary": ".src.metrics",
    "Registry": ".src.metrics",
}

_CACHE: dict[str, object] = {}

# 热路径预加载 — worker 和 models 在绝大多数导入路径中首先被访问
try:
    from . import worker as _worker_mod
    _CACHE[".worker"] = _worker_mod
    from .src import models as _models_mod
    _CACHE[".src.models"] = _models_mod
except ImportError:
    pass


def __getattr__(name: str):
    if name in _MODULE_MAP:
        mod_path = _MODULE_MAP[name]
        if mod_path not in _CACHE:
            _CACHE[mod_path] = importlib.import_module(
                mod_path, package=__package__
            )
        return getattr(_CACHE[mod_path], name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
