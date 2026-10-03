import logging
import os
import json
import time
import hashlib
import pickle
import shutil
import threading
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, Any, Optional, List, Tuple
from collections import OrderedDict

logger = logging.getLogger(__name__)

try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    redis = None


class ShardingStrategy(Enum):
    HASH_MOD = "hash_mod"
    FIRST_BYTES = "first_bytes"
    RANGE = "range"


@dataclass
class CacheEntry:
    key: str
    payload: Any
    metadata: Dict[str, Any] = field(default_factory=dict)
    access_count: int = 0
    last_access: float = field(default_factory=time.time)
    size_bytes: int = 0


@dataclass
class ShardStats:
    shard_id: int
    entry_count: int
    total_bytes: int
    hit_count: int = 0
    miss_count: int = 0


class LocalShardBackend:
    """本地文件系统分片后端（降级回退）。"""

    def __init__(self, base_dir: str, num_shards: int = 64):
        self.base_dir = base_dir
        self.num_shards = num_shards
        os.makedirs(base_dir, exist_ok=True)
        for i in range(num_shards):
            os.makedirs(self._shard_path(i), exist_ok=True)
        self.lock = threading.Lock()

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
            logger.warning(f"Cache read failed {path}: {e}")
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
            logger.warning(f"Cache write failed {path}: {e}")
            return False

    def delete(self, shard_id: int, key: str) -> bool:
        path = os.path.join(self._shard_path(shard_id), key)
        try:
            if os.path.exists(path):
                os.remove(path)
                return True
        except Exception as e:
            logger.warning(f"Cache delete failed {path}: {e}")
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
                logger.debug(f"stat shard {shard_id} file skipped: {k}")
        return ShardStats(shard_id, count, total)


class RedisShardBackend:
    """Redis 分片后端。"""

    def __init__(self, host: str = "localhost", port: int = 6379,
                 db: int = 0, prefix: str = "decomp_cache", num_shards: int = 64):
        if not REDIS_AVAILABLE:
            raise RuntimeError("redis package not installed, pip install redis")
        self.client = redis.Redis(host=host, port=port, db=db, decode_responses=False)
        self.prefix = prefix
        self.num_shards = num_shards

    def _full_key(self, shard_id: int, key: str) -> bytes:
        return f"{self.prefix}:s{shard_id}:{key}".encode("utf-8")

    def get(self, shard_id: int, key: str) -> Optional[bytes]:
        try:
            return self.client.get(self._full_key(shard_id, key))
        except Exception as e:
            logger.warning(f"Redis get failed: {e}")
            return None

    def put(self, shard_id: int, key: str, payload: bytes) -> bool:
        try:
            self.client.set(self._full_key(shard_id, key), payload)
            return True
        except Exception as e:
            logger.warning(f"Redis set failed: {e}")
            return False

    def delete(self, shard_id: int, key: str) -> bool:
        try:
            return bool(self.client.delete(self._full_key(shard_id, key)))
        except Exception as e:
            logger.warning(f"Redis del failed: {e}")
            return False

    def list_keys(self, shard_id: int) -> List[str]:
        try:
            pattern = f"{self.prefix}:s{shard_id}:*".encode("utf-8")
            return [k.split(b':', 2)[-1].decode("utf-8")
                    for k in self.client.keys(pattern)]
        except Exception as e:
            logger.warning(f"Redis keys failed: {e}")
            return []

    def stats(self, shard_id: int) -> ShardStats:
        keys = self.list_keys(shard_id)
        total = 0
        for k in keys:
            try:
                total += len(self.client.get(self._full_key(shard_id, k)) or b"")
            except Exception:
                logger.debug(f"Redis shard stat read skipped: {k}")
        return ShardStats(shard_id, len(keys), total)


class DecompCache:
    """
    反编译输出缓存。
    - 通过 (binary_hash, func_hash) 键进行内容寻址。
    - 分片：默认 64 个分片。
    - LRU 淘汰：超过 max_bytes 时触发驱逐。
    """

    DEFAULT_BACKEND = "local"

    def __init__(self,
                 backend: str = "local",
                 base_dir: Optional[str] = None,
                 num_shards: int = 64,
                 max_total_bytes: int = 4 * 1024 * 1024 * 1024,
                 redis_host: Optional[str] = None,
                 redis_port: int = 6379):
        if base_dir is None:
            base_dir = os.path.join(
                os.path.dirname(__file__), '..', 'data', 'decomp_cache'
            )
        self.num_shards = num_shards
        self.max_total_bytes = max_total_bytes
        self.lock = threading.Lock()

        if backend == "redis" and REDIS_AVAILABLE and redis_host:
            try:
                self.backend = RedisShardBackend(
                    host=redis_host, port=redis_port, num_shards=num_shards
                )
                self.backend_kind = "redis"
            except Exception as e:
                logger.warning(f"Redis init failed, switching to local: {e}")
                self.backend = LocalShardBackend(base_dir, num_shards)
                self.backend_kind = "local"
        else:
            self.backend = LocalShardBackend(base_dir, num_shards)
            self.backend_kind = "local"

        self.lru: "OrderedDict[str, float]" = OrderedDict()
        self.hits = 0
        self.misses = 0

    @staticmethod
    def compute_func_key(binary_path: str, func_name: str,
                           func_offset: int = 0) -> str:
        h = hashlib.sha256()
        h.update(binary_path.encode("utf-8", errors="replace"))
        h.update(b"\x00")
        h.update(func_name.encode("utf-8", errors="replace"))
        h.update(b"\x00")
        h.update(str(func_offset).encode("utf-8"))
        return h.hexdigest()[:32]

    def _shard_of(self, key: str) -> int:
        h = int(hashlib.md5(key.encode("utf-8")).hexdigest(), 16)
        return h % self.num_shards

    def get(self, binary_path: str, func_name: str,
              func_offset: int = 0) -> Optional[Dict[str, Any]]:
        key = self.compute_func_key(binary_path, func_name, func_offset)
        shard = self._shard_of(key)
        raw = self.backend.get(shard, key)
        if raw is None:
            self.misses += 1
            return None
        try:
            obj = pickle.loads(raw)
        except Exception as e:
            logger.warning(f"Cache deserialization failed: {e}")
            return None
        self.hits += 1
        with self.lock:
            self.lru[key] = time.time()
            self.lru.move_to_end(key)
        return obj

    def put(self, binary_path: str, func_name: str,
              func_offset: int, payload: Dict[str, Any]) -> bool:
        key = self.compute_func_key(binary_path, func_name, func_offset)
        shard = self._shard_of(key)
        try:
            blob = pickle.dumps(payload, protocol=pickle.HIGHEST_PROTOCOL)
        except Exception as e:
            logger.warning(f"Serialization failed: {e}")
            return False
        ok = self.backend.put(shard, key, blob)
        if ok:
            with self.lock:
                self.lru[key] = time.time()
            self._enforce_quota()
        return ok

    def invalidate(self, binary_path: str, func_name: str,
                     func_offset: int = 0) -> bool:
        key = self.compute_func_key(binary_path, func_name, func_offset)
        shard = self._shard_of(key)
        ok = self.backend.delete(shard, key)
        with self.lock:
            self.lru.pop(key, None)
        return ok

    def _enforce_quota(self):
        total = 0
        per_shard_sizes: List[Tuple[int, int]] = []
        for i in range(self.num_shards):
            s = self.backend.stats(i)
            total += s.total_bytes
            per_shard_sizes.append((i, s.total_bytes))
        if total <= self.max_total_bytes:
            return
        with self.lock:
            while total > self.max_total_bytes * 0.9 and self.lru:
                key, _ = self.lru.popitem(last=False)
                shard = self._shard_of(key)
                if self.backend.delete(shard, key):
                    total -= len(key)
        logger.info(f"[decomp-cache] LRU cleanup triggered, estimated {total} bytes")

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
            'hits': self.hits,
            'misses': self.misses,
            'hit_rate': (
                self.hits / max(1, self.hits + self.misses)
            )
        }


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
    return get_global_cache().put(binary_path, func_name, func_offset, decomp)


def lookup_decomp_result(binary_path: str, func_name: str,
                           func_offset: int = 0) -> Optional[Dict[str, Any]]:
    return get_global_cache().get(binary_path, func_name, func_offset)
