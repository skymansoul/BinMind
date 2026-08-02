# 2026-07-27
# 限流器 — 本地令牌桶 + Redis Lua 分布式令牌桶
# 惰性填充：允许时才根据时间差补令牌，零后台开销
# Redis 版用 Lua 脚本原子化 refill+consume，避免分布式竞态
#
# 扩展：并发信号量限制器 — 限制同时执行的数量而非速率

from __future__ import annotations

import time
import threading
import functools
from typing import Optional

# ---- 可选 Redis ----
try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


class RateLimitExceeded(Exception):
    """限流拒绝异常"""
    def __init__(self, message: str = "rate limit exceeded"):
        super().__init__(message)


# ===== 本地令牌桶 =====

class TokenBucket:
    """惰性填充令牌桶 — 参考 Stripe rate limiter 设计。

    rate: 每秒生成令牌数
    burst: 桶容量（最大瞬时突发）
    """

    __slots__ = ('_rate', '_burst', '_tokens', '_last_fill', '_lock')

    def __init__(self, rate: float, burst: Optional[float] = None):
        self._rate = rate
        self._burst = burst if burst is not None else rate
        self._tokens = float(self._burst)
        self._last_fill = time.monotonic()
        self._lock = threading.Lock()

    def _refill(self):
        now = time.monotonic()
        elapsed = now - self._last_fill
        self._tokens = min(self._burst, self._tokens + elapsed * self._rate)
        self._last_fill = now

    def allow(self) -> bool:
        return self.allow_n(1)

    def allow_n(self, n: int) -> bool:
        with self._lock:
            self._refill()
            if self._tokens >= n:
                self._tokens -= n
                return True
            return False

    @property
    def tokens(self) -> float:
        with self._lock:
            self._refill()
            return self._tokens

    def refill(self) -> None:
        with self._lock:
            self._refill()


# ===== 并发限制器 =====

class ConcurrencyLimiter:
    """限制同时执行的操作数。与令牌桶互补：令牌桶控速率，此控并发度。

    max_concurrent: 最大并发数。设为 10 表示最多 10 个操作同时进行。
    """

    __slots__ = ('_sem', '_active')

    def __init__(self, max_concurrent: int = 10):
        self._sem = threading.BoundedSemaphore(max_concurrent)
        self._active = 0

    def acquire(self, blocking: bool = True, timeout: float = None) -> bool:
        if timeout is not None:
            ok = self._sem.acquire(blocking=blocking, timeout=timeout)
        else:
            ok = self._sem.acquire(blocking=blocking)
        if ok:
            self._active += 1
        return ok

    def release(self):
        self._sem.release()
        self._active = max(0, self._active - 1)

    @property
    def active(self) -> int:
        return self._active

    def __enter__(self):
        self.acquire()
        return self

    def __exit__(self, *args):
        self.release()


# ===== 分布式令牌桶 (Redis Lua) =====

_LUA_REFILL_CONSUME = """
local key = KEYS[1]
local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local now = tonumber(ARGV[3])
local requested = tonumber(ARGV[4])

-- 读取当前令牌数和上次填充时间
local tokens = redis.call('HGET', key, 'tokens')
local last = redis.call('HGET', key, 'last_fill')

tokens = tonumber(tokens) or burst
last = tonumber(last) or now

-- 惰性填充
local elapsed = now - last
tokens = math.min(burst, tokens + elapsed * rate)
last = now

-- 消费
if tokens >= requested then
    tokens = tokens - requested
    redis.call('HSET', key, 'tokens', tokens, 'last_fill', last)
    -- TTL 设为 burst/rate + 60s 兜底
    redis.call('EXPIRE', key, math.ceil(burst / rate) + 60)
    return 1
end

redis.call('HSET', key, 'tokens', tokens, 'last_fill', last)
redis.call('EXPIRE', key, math.ceil(burst / rate) + 60)
return 0
"""


class DistributedTokenBucket:
    """Redis 分布式令牌桶 — Lua 原子操作。

    回退：Redis 不可用时退化为本地 TokenBucket。
    """

    __slots__ = ('_rate', '_burst', '_key', '_redis', '_fallback', '_script')

    def __init__(self, redis_client, key: str, rate: float, burst: Optional[float] = None):
        self._rate = rate
        self._burst = burst if burst is not None else rate
        self._key = key
        self._redis = redis_client
        self._fallback = TokenBucket(rate, burst)
        self._script = None
        try:
            self._script = redis_client.register_script(_LUA_REFILL_CONSUME)
        except Exception:
            pass

    def allow(self) -> bool:
        return self.allow_n(1)

    def allow_n(self, n: int) -> bool:
        if self._script is not None:
            try:
                result = self._script(
                    keys=[self._key],
                    args=[self._rate, self._burst, time.time(), n],
                )
                return bool(result)
            except Exception:
                pass
        return self._fallback.allow_n(n)

    @property
    def tokens(self) -> float:
        try:
            raw = self._redis.hget(self._key, 'tokens')
            return float(raw) if raw else float(self._burst)
        except Exception:
            pass
        return self._fallback.tokens

    def refill(self) -> None:
        self._fallback.refill()


# ===== 装饰器 =====

_RATE_LIMITERS: dict[str, TokenBucket] = {}
_RATE_LIMIT_LOCK = threading.Lock()


def rate_limit(rate: float = 10, burst: Optional[float] = None, key: str = None):
    """函数级限流装饰器。

    rate: 每秒允许调用次数
    burst: 最大突发（默认等于 rate）
    key: 共享桶的标识。不传时每个函数独立桶。

    装饰后函数可能抛出 RateLimitExceeded。
    """
    b = burst if burst is not None else rate

    def decorator(func):
        bucket_key = key or f"__rl__{func.__module__}.{func.__qualname__}"
        with _RATE_LIMIT_LOCK:
            if bucket_key not in _RATE_LIMITERS:
                _RATE_LIMITERS[bucket_key] = TokenBucket(rate, b)
        bucket = _RATE_LIMITERS[bucket_key]

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            if not bucket.allow():
                raise RateLimitExceeded(
                    f"rate limit exceeded for {func.__name__}"
                )
            return func(*args, **kwargs)
        return wrapper
    return decorator
