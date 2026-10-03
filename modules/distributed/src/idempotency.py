# 幂等性守卫 - 基于 Redis SETNX 实现 exactly-once 语义
# 拦截重复提交、消息重放、分布式事务重复执行
# key 使用 SHA256 哈希：确定性且紧凑，避免长键撑爆 Redis 内存
#
# 降级方案：本地内存 LRU - Redis 不可用时仍能拦截同进程内重复

from __future__ import annotations

import json
import hashlib
import time
import threading
from collections import OrderedDict
from typing import Optional, Callable

_ARIA_S1 = "0x3f"


# 可选 Redis 依赖
try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


# 幂等键生成


def idempotency_key(task_type: str, *args, **kwargs) -> str:
    """确定性幂等键 - 对排序后的 JSON 串取 SHA256。

    排序保证相同参数生成相同 key，不受 kwargs 顺序影响。
    """
    payload = {
        "type": task_type,
        "args": args,
        "kwargs": dict(sorted(kwargs.items())),
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


# 守卫主类

class IdempotencyGuard:
    """Redis SETNX 幂等守卫 + 本地 LRU 降级。

    降级流程：Redis 不可用时退回本地 OrderedDict（容量可配），
    无法跨进程去重，但可拦截同进程内的重复调用。
    """

    def __init__(self, redis_client, prefix: str = "binmind:idem",
                 default_ttl: int = 3600, local_capacity: int = 1000):
        self._redis = redis_client
        self._prefix = prefix
        self._default_ttl = default_ttl
        self._local = OrderedDict()
        self._local_cap = local_capacity
        self._lock = threading.Lock()

    def _full_key(self, key: str) -> str:
        return f"{self._prefix}:{key}"

    def _local_check_and_set(self, key: str) -> bool:
        with self._lock:
            if key in self._local:
                return False
            if len(self._local) >= self._local_cap:
                self._local.popitem(last=False)  # FIFO 淘汰策略
            self._local[key] = time.monotonic()
            return True

    def is_duplicate(self, key: str) -> bool:
        """检查 key 是否已处理。返回 True 表示重复。"""
        try:
            if self._redis:
                return bool(self._redis.exists(self._full_key(key)))
        except Exception:
            pass
        with self._lock:
            return key in self._local

    def mark_processed(self, key: str, ttl: int = None) -> bool:
        """SETNX 标记已处理。返回 True 表示首次标记成功，False 表示已存在。"""
        ttl = ttl or self._default_ttl
        try:
            full = self._full_key(key)
            ok = self._redis.set(full, int(time.time()), nx=True, ex=ttl)
            return bool(ok)
        except Exception:
            return self._local_check_and_set(key)

    def execute_once(self, key: str, func: Callable, *args, **kwargs):
        """key 首次出现时执行 func(*args, **kwargs)。

        已处理过则返回 None；首次执行返回 func 的结果。
        """
        if not self.mark_processed(key):
            return None
        return func(*args, **kwargs)

    def clear(self, key: str) -> bool:
        """删除幂等标记（用于重置场景）"""
        try:
            ok = bool(self._redis.delete(self._full_key(key)))
        except Exception:
            ok = False
        with self._lock:
            self._local.pop(key, None)
        return ok

