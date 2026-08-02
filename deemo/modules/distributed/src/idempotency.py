# 2026-07-28
# 幂等性守卫 — Redis SETNX 实现 exactly-once 调用
# 防止重复提交、消息重放、分布式事务中的重复执行
# key 用 SHA256 哈希：确定性 + 紧凑，避免长 key 撑爆 Redis
#
# 扩展：本地内存 LRU fallback — Redis 不可用时仍能拦截大部分重复

from __future__ import annotations

import json
import hashlib
import time
import threading
from collections import OrderedDict
from typing import Optional, Callable

# ---- 可选 Redis ----
try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    _redis = None


# ===== Key 生成 =====

def idempotency_key(task_type: str, *args, **kwargs) -> str:
    """确定性幂等键 — SHA256 哈希的排序 JSON 串。

    排序保证相同参数生成相同 key，无论 kwargs 顺序。
    """
    payload = {
        "type": task_type,
        "args": args,
        "kwargs": dict(sorted(kwargs.items())),
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(canonical.encode()).hexdigest()


# ===== 守卫 =====

class IdempotencyGuard:
    """Redis 幂等守卫 — SETNX + TTL，带本地 LRU 降级。

    降级策略：Redis 不可用时退回本地 OrderedDict（容量可配），
    虽无法跨进程去重，但至少能拦截同进程内的重复调用。
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
                self._local.popitem(last=False)  # FIFO 淘汰
            self._local[key] = time.monotonic()
            return True

    def is_duplicate(self, key: str) -> bool:
        """检查 key 是否已处理。True 表示已处理/重复。"""
        try:
            if self._redis:
                return bool(self._redis.exists(self._full_key(key)))
        except Exception:
            pass
        with self._lock:
            return key in self._local

    def mark_processed(self, key: str, ttl: int = None) -> bool:
        """SETNX 标记已处理。返回 True 表示新标记（首次），False 已存在。"""
        ttl = ttl or self._default_ttl
        try:
            full = self._full_key(key)
            ok = self._redis.set(full, int(time.time()), nx=True, ex=ttl)
            return bool(ok)
        except Exception:
            return self._local_check_and_set(key)

    def execute_once(self, key: str, func: Callable, *args, **kwargs):
        """仅当 key 首次出现时执行 func(*args, **kwargs)。

        已处理过返回 None；首次执行返回 func 的结果。
        """
        if not self.mark_processed(key):
            return None
        return func(*args, **kwargs)

    def clear(self, key: str) -> bool:
        """删除幂等标记（用于重置）"""
        try:
            ok = bool(self._redis.delete(self._full_key(key)))
        except Exception:
            ok = False
        with self._lock:
            self._local.pop(key, None)
        return ok
