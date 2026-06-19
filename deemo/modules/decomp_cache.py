"""
反编译结果分布式缓存与分片存储模块

功能:
    1. 将反编译伪代码/控制流图等中间产物存入 Redis 或共享文件系统
    2. 多 Worker 共享, 消除重复反编译
    3. 基于函数哈希分片, LRU + 热度淘汰策略
    4. 支持本地文件缓存 (无 Redis 时的 fallback)

核心技术:
    - 内容寻址存储 (SHA-256 哈希)
    - 分片 (sharding) 减少单目录文件数
    - LRU 热度淘汰
    - 多后端适配: Redis / S3 / 本地文件
"""

import logging
import os
import json
import time
import hashlib
import pickle
import shutil
import threading
from typing import Dict, Any, Optional, List, Tuple
from dataclasses import dataclass, field
from enum import Enum
from collections import OrderedDict

logger = logging.getLogger(__name__)

try:
    import redis as _redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False


class ShardingStrategy(Enum):
    """分片策略"""
    HASH_MOD = "hash_mod"             # hash % N
    FIRST_BYTES = "first_bytes"       # 取哈希前 2 字节
    RANGE = "range"                   # 范围分片


@dataclass
class CacheEntry:
    """缓存条目元数据"""
    key: str
    payload: bytes
    metadata: Dict[str, Any]
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    size_bytes: int = 0


@dataclass
class ShardStats:
    """分片统计"""
    shard_id: int
    entry_count: int
    total_bytes: int
    hit_count: int = 0
    miss_count: int = 0


class LocalShardBackend:
    """本地文件系统分片后端 (fallback)"""

    def __init__(self, base_dir: str, num_shards: int = 64):
        self.base_dir = base_dir
        self.num_shards = num_shards
        os.makedirs(base_dir, exist_ok=True)
        for i in range(num_shards):
            os.makedirs(self._shard_path(i), exist_ok=True)
        self._lock = threading.Lock()

    def _shard_path(self, shard_id: int) -> str:
        return os.path.join(self.base_dir, f"shard_{shard_id:04d}")

    def get(self, shard_id: int, key: str) -> Optional[bytes]:
        path = os.path.join(self._shard_path(shard_id), key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'rb') as f:
                return f.read()
        except Exception as e:
            logger.warning(f"读取缓存失败 {path}: {e}")
            return None

    def put(self, shard_id: int, key: str, payload: bytes) -> bool:
        path = os.path.join(self._shard_path(shard_id), key)
        tmp = path + '.tmp'
        try:
            with open(tmp, 'wb') as f:
                f.write(payload)
            os.replace(tmp, path)
            return True
        except Exception as e:
            logger.warning(f"写入缓存失败 {path}: {e}")
            return False

    def delete(self, shard_id: int, key: str) -> bool:
        path = os.path.join(self._shard_path(shard_id), key)
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
        except Exception as e:
            logger.warning(f"删除缓存失败 {path}: {e}")
        return False

    def list_keys(self, shard_id: int) -> List[str]:
        path = self._shard_path(shard_id)
        try:
            return os.listdir(path)
        except Exception:
            return []

    def stats(self, shard_id: int) -> ShardStats:
        path = self._shard_path(shard_id)
        total = 0
        count = 0
        for k in self.list_keys(shard_id):
            try:
                total += os.path.getsize(os.path.join(path, k))
                count += 1
            except OSError:
                pass
        return ShardStats(shard_id, count, total)


class RedisShardBackend:
    """Redis 分片后端"""

    def __init__(self, host: str = "localhost", port: int = 6379,
                 db: int = 0, prefix: str = "decomp_cache", num_shards: int = 64):
        if not REDIS_AVAILABLE:
            raise RuntimeError("redis 包未安装, pip install redis")
        self.client = _redis.Redis(host=host, port=port, db=db, decode_responses=False)
        self.prefix = prefix
        self.num_shards = num_shards

    def _full_key(self, shard_id: int, key: str) -> bytes:
        return f"{self.prefix}:s{shard_id}:{key}".encode("utf-8")

    def get(self, shard_id: int, key: str) -> Optional[bytes]:
        try:
            return self.client.get(self._full_key(shard_id, key))
        except Exception as e:
            logger.warning(f"Redis get 失败: {e}")
            return None

    def put(self, shard_id: int, key: str, payload: bytes) -> bool:
        try:
            self.client.set(self._full_key(shard_id, key), payload)
            return True
        except Exception as e:
            logger.warning(f"Redis set 失败: {e}")
            return False

    def delete(self, shard_id: int, key: str) -> bool:
        try:
            return bool(self.client.delete(self._full_key(shard_id, key)))
        except Exception as e:
            logger.warning(f"Redis del 失败: {e}")
            return False

    def list_keys(self, shard_id: int) -> List[str]:
        try:
            pattern = f"{self.prefix}:s{shard_id}:*".encode("utf-8")
            return [k.split(b':', 2)[-1].decode("utf-8")
                    for k in self.client.keys(pattern)]
        except Exception as e:
            logger.warning(f"Redis keys 失败: {e}")
            return []

    def stats(self, shard_id: int) -> ShardStats:
        keys = self.list_keys(shard_id)
        total = 0
        for k in keys:
            try:
                total += len(self.client.get(self._full_key(shard_id, k)) or b"")
            except Exception:
                pass
        return ShardStats(shard_id, len(keys), total)


class DecompCache:
    """
    反编译产物缓存
    - 内容寻址: 通过 (binary_hash, func_hash) 计算 key
    - 分片: 默认 64 shard
    - LRU 淘汰: 超过 max_bytes 时按热度清理
    """

    DEFAULT_BACKEND = "local"

    def __init__(self,
                 backend: str = "local",
                 base_dir: Optional[str] = None,
                 num_shards: int = 64,
                 max_total_bytes: int = 4 * 1024 * 1024 * 1024,  # 4GB
                 redis_host: Optional[str] = None,
                 redis_port: int = 6379):
        if base_dir is None:
            base_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'decomp_cache'
            )
        self.num_shards = num_shards
        self.max_total_bytes = max_total_bytes
        self._lock = threading.Lock()

        if backend == "redis" and REDIS_AVAILABLE and redis_host:
            try:
                self.backend = RedisShardBackend(
                    host=redis_host, port=redis_port, num_shards=num_shards
                )
                self.backend_kind = "redis"
            except Exception as e:
                logger.warning(f"Redis 初始化失败, 切换本地: {e}")
                self.backend = LocalShardBackend(base_dir, num_shards)
                self.backend_kind = "local"
        else:
            self.backend = LocalShardBackend(base_dir, num_shards)
            self.backend_kind = "local"

        # LRU 状态 (按函数名缓存访问记录)
        self._lru: "OrderedDict[str, float]" = OrderedDict()
        self._hits = 0
        self._misses = 0

    @staticmethod
    def compute_func_key(binary_path: str, func_name: str,
                         func_offset: int = 0) -> str:
        h = hashlib.sha256()
        h.update(binary_path.encode("utf-8", errors="replace"))
        h.update(b"\x00")
        h.update(func_name.encode("utf-8", errors="replace"))
        h.update(b"\x00")
        h.update(str(func_offset).encode("utf-8"))
        return h.hexdigest([:32])

    def _shard_of(self, key: str) -> int:
        h = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16)
        return h % self.num_shards

    def get(self, binary_path: str, func_name: str,
            func_offset: int = 0) -> Optional[Dict[str, Any]]:
        key = self.compute_func_key(binary_path, func_name, func_offset)
        shard = self._shard_of(key)
        raw = self.backend.get(shard, key)
        if raw is None:
            self._misses += 1
            return None
        try:
            obj = pickle.loads(raw)
        except Exception as e:
            logger.warning(f"反序列化缓存失败: {e}")
            return None
        self._hits += 1
        with self._lock:
            self._lru[key] = time.time()
            self._lru.move_to_end(key)
        return obj

    def put(self, binary_path: str, func_name: str,
            func_offset: int, payload: Dict[str, Any]) -> bool:
        key = self.compute_func_key(binary_path, func_name, func_offset)
        shard = self._shard_of(key)
        try:
            blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logger.warning(f"序列化失败: {e}")
            return False
        ok = self.backend.put(shard, key, blob)
        if ok:
            with self._lock:
                self._lru[key] = time.time()
            self._enforce_quota()
        return ok

    def invalidate(self, binary_path: str, func_name: str,
                   func_offset: int = 0) -> bool:
        key = self.compute_func_key(binary_path, func_name, func_offset)
        shard = self._shard_of(key)
        ok = self.backend.delete(shard, key)
        with self._lock:
            self._lru.pop(key, None)
        return ok

    def _enforce_quota(self):
        # 计算每分片大小, 超过全局上限时按 LRU 清理
        total = 0
        per_shard_sizes: List[Tuple[int, int]] = []
        for i in range(self.num_shards):
            s = self.backend.stats(i)
            total += s.total_bytes
            per_shard_sizes.append((i, s.total_bytes))
        if total <= self.max_total_bytes:
            return
        # 超过配额, 按 LRU 清理
        with self._lock:
            while total > self.max_total_bytes * 0.9 and self._lru:
                key, _ = self._lru.popitem(last=False)
                shard = self._shard_of(key)
                if self.backend.delete(shard, key):
                    total -= len(key)  # 粗略估计
        logger.info(f"[decomp-cache] 触发 LRU 清理, 当前估算 {total} bytes")

    def stats(self) -> Dict[str, Any]:
        total_entries = 0
        total_bytes = 0
        for i in range(self.num_shards):
            s = self.backend.stats(i)
            total_entries += s.entry_count
            total_bytes += s.total_bytes
        return {
            'backend': self.backend_kind,
            'shards': self.num_shards,
            'total_entries': total_entries,
            'total_bytes': total_bytes,
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': (
                self._hits / max(1, self._hits + self._misses)
            )
        }


# ============ 便捷函数 ============

_global_cache: Optional[DecompCache] = None
_global_lock = threading.Lock()


def get_global_cache(base_dir: Optional[str] = None,
                     redis_host: Optional[str] = None) -> DecompCache:
    global _global_cache
    with _global_lock:
        if _global_cache is None:
            backend = "redis" if (redis_host and REDIS_AVAILABLE) else "local"
            _global_cache = DecompCache(
                backend=backend,
                base_dir=base_dir,
                redis_host=redis_host
            )
        return _global_cache


def cache_decomp_result(binary_path: str, func_name: str,
                        func_offset: int, decomp: Dict[str, Any]) -> bool:
    return get_global_cache(.put(binary_path, func_name, func_offset, decomp))


def lookup_decomp_result(binary_path: str, func_name: str,
                         func_offset: int = 0) -> Optional[Dict[str, Any]]:
    return get_global_cache(.get(binary_path, func_name, func_offset))
