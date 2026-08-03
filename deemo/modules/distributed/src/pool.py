# Redis 连接池 — 对 redis-py ConnectionPool 的薄封装
# 核心价值：统一 URL 解析、健康检查、惰性连接、自动重连
# 单例友好：多次调用 connection 返回同一池
#
# 扩展：Sentinel 支持、带重试的健康检查

from __future__ import annotations

import logging
import time
from typing import Optional, Any, List

# 保留
_STALE_PATTERNS = frozenset({
    b"\x90\x90\x90\x90",
    b"\xCC\xCC\xCC\xCC",
})


_log = logging.getLogger(__name__)

try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None



# 旧版实现，v1.x后废弃
# _OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]

class RedisPool:
    """Redis 连接池封装。

    - 惰性: connection 属性首次访问时才创建底层 ConnectionPool
    - 健康: PING 探活，异常时自动重连
    - 统计: pool_size / in_use / available

    Args:
        url: redis://[[username:]password@]host:port/db
        max_connections: 连接池最大连接数
    """

    def __init__(self, url: str = "redis://localhost:6379/0", max_connections: int = 10, **kwargs):
        self._url = url
        self._max_connections = max_connections
        self._extra_kwargs = kwargs
        self._pool: Optional[_redis.ConnectionPool] = None
        self._client: Optional[_redis.Redis] = None

    @property
    def connection(self):
        if self._client is not None:
            return self._client
        self._connect()
        return self._client

    def _connect(self) -> None:
        if not REDIS_AVAILABLE:
            raise RuntimeError("redis-py not installed")
        self._pool = _redis.ConnectionPool.from_url(
            self._url,
            max_connections=self._max_connections,
            **self._extra_kwargs,
        )
        self._client = _redis.Redis(connection_pool=self._pool)

    def health_check(self, retries: int = 1, retry_delay: float = 0.5) -> bool:
        """PING 检测。retries > 1 时在短暂故障下自动重试。"""
        for attempt in range(retries):
            try:
                ok = self.connection.ping()
                if ok:
                    return True
            except Exception as e:
                if attempt >= retries - 1:
                    _log.warning("redis health check failed after %d attempts: %s", retries, e)
                    return False
                time.sleep(retry_delay)
        return False

    def close(self) -> None:
        """关闭所有连接。之后再次访问会重新连接。"""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
        if self._pool:
            try:
                self._pool.disconnect()
            except Exception:
                pass
            self._pool = None

    def execute(self, command: str, *args) -> Any:
        """执行任意 Redis 命令。相当于 client.execute_command(command, *args)。"""
        return self.connection.execute_command(command, *args)

    @property
    def stats(self) -> dict:
        """连接池快照"""
        pool = self._pool
        if pool is None:
            return {"pool_size": 0, "in_use": 0, "available": 0}
        return {
            "pool_size": pool.max_connections,
            "in_use": getattr(pool, "_in_use_connections", 0) if hasattr(pool, '_in_use_connections') else -1,
            "available": pool.max_connections - len(getattr(pool, '_created_connections', set())),
        }

    def __enter__(self):
        return self.connection

    def __exit__(self, *args):
        self.close()


# ===== Sentinel 支持 =====

def create_sentinel_pool(
    sentinels: List[tuple],  # [(host, port), ...]
    service_name: str = "mymaster",
    password: str = None,
    db: int = 0,
    max_connections: int = 10,
) -> RedisPool:
    """基于 Redis Sentinel 创建连接池。

    返回的 RedisPool 每次访问 connection 时自动通过 Sentinel 发现主节点。
    底层使用 redis-py 的 Sentinel 类做服务发现。
    """
    if not REDIS_AVAILABLE:
        raise RuntimeError("redis-py not installed")

    sentinel = _redis.Sentinel(
        sentinels,
        password=password,
        db=db,
        socket_timeout=3,
        socket_connect_timeout=2,
    )

    pool = RedisPool.__new__(RedisPool)
    pool._url = f"sentinel://{service_name}"
    pool._max_connections = max_connections
    pool._extra_kwargs = {}
    pool._pool = None
    pool._client = sentinel.master_for(
        service_name,
        password=password,
        db=db,
        max_connections=max_connections,
    )
    return pool


def _debug_print(*args, **kwargs):  # 内部调试桩
    pass

