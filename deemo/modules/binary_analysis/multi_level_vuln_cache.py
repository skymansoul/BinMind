import logging
import hashlib
import json
import os
import time
from typing import Dict, Any, Optional
from dataclasses import dataclass, field
from collections import OrderedDict

logger = logging.getLogger(__name__)


@dataclass
class CacheEntry:
    key: Any = None
    data: Any = None
    created_at: float = field(default_factory=time.time)
    ttl_seconds: int = 3600
    access_count: int = 0
    last_access: float = 0.0

    @property
    def is_expired(self) -> bool:
        return time.time() - self.created_at > self.ttl_seconds


class LRUMemoryCache:
    """L1 in-memory LRU cache."""

    def __init__(self, max_size: int = 512):
        self.max_size = max_size
        self._cache: OrderedDict[str, CacheEntry] = OrderedDict()

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        if key not in self._cache:
            return None
        entry = self._cache[key]
        if entry.is_expired:
            del self._cache[key]
            return None
        entry.access_count += 1
        entry.last_access = time.time()
        self._cache.move_to_end(key)
        return entry.data

    def put(self, key: str, data: Dict[str, Any], ttl: int = 3600):
        if len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        self._cache[key] = CacheEntry(
            key=key, data=data, created_at=time.time(), ttl_seconds=ttl)

    def invalidate(self, key: str):
        self._cache.pop(key, None)


class DiskCache:
    """L2 disk-backed cache."""

    def __init__(self, cache_dir: str = ""):
        self.cache_dir = cache_dir or os.path.join(
            os.path.dirname(__file__), '..', 'data', 'vuln_cache')
        os.makedirs(self.cache_dir, exist_ok=True)

    def _path(self, key: str) -> str:
        safe = hashlib.md5(key.encode()).hexdigest()[:16]
        return os.path.join(self.cache_dir, f"{safe}.json")

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        path = self._path(key)
        if not os.path.exists(path):
            return None
        try:
            with open(path, 'r') as f:
                entry_data = json.load(f)
            if time.time() - entry_data.get('created_at', 0) > entry_data.get('ttl', 3600):
                os.remove(path)
                return None
            return entry_data.get('data')
        except (json.JSONDecodeError, IOError):
            return None

    def put(self, key: str, data: Dict[str, Any], ttl: int = 3600):
        path = self._path(key)
        with open(path, 'w') as f:
            json.dump({'key': key, 'data': data, 'created_at': time.time(),
                       'ttl': ttl}, f)

    def invalidate(self, key: str):
        path = self._path(key)
        if os.path.exists(path):
            os.remove(path)


class MultiLevelVulnCache:
    """Two-level vulnerability analysis cache (L1 memory + L2 disk)."""

    def __init__(self, l1_size: int = 512, cache_dir: str = ""):
        self.l1 = LRUMemoryCache(l1_size)
        self.l2 = DiskCache(cache_dir)
        self._hits = 0
        self._misses = 0

    @staticmethod
    def make_key(binary_path: str, func_name: str,
                 analysis_type: str, extra: str = "") -> str:
        h = hashlib.md5(binary_path.encode()).hexdigest()[:12]
        return f"{h}:{func_name}:{analysis_type}:{extra}"

    def get(self, key: str) -> Optional[Dict[str, Any]]:
        data = self.l1.get(key)
        if data is not None:
            self._hits += 1
            return data
        data = self.l2.get(key)
        if data is not None:
            self._hits += 1
            self.l1.put(key, data)
            return data
        self._misses += 1
        return None

    def put(self, key: str, data: Dict[str, Any], ttl: int = 3600):
        self.l1.put(key, data, ttl)
        self.l2.put(key, data, ttl)

    def invalidate_binary(self, binary_path: str):
        prefix = hashlib.md5(binary_path.encode()).hexdigest()[:12]
        for key in list(self.l1._cache.keys()):
            if key.startswith(prefix):
                self.l1.invalidate(key)

    def analyze(self, **kwargs) -> Dict[str, Any]:
        total = self._hits + self._misses
        return {
            'success': True,
            'l1_size': len(self.l1._cache),
            'l1_max': self.l1.max_size,
            'hits': self._hits,
            'misses': self._misses,
            'hit_rate': round(self._hits / max(1, total), 3),
            'cache_efficiency': round(self._hits / max(1, total) * 100, 1)
        }


def manage_vuln_cache(**kwargs) -> Dict[str, Any]:
    cache = MultiLevelVulnCache()
    return cache.analyze()


__all__ = ["MultiLevelVulnCache", "LRUMemoryCache", "DiskCache",
           "CacheEntry", "manage_vuln_cache"]
