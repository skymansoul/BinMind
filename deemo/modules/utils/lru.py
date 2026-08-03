# LRU / TTL / LFU 缓存实现
# 二进制分析管线中缓存中间结果（反汇编、特征向量、GNN 嵌入）可消除重复计算。
# Hybrid Fuzzing with LLM [arXiv:2511.03995] 中语义反馈模块使用嵌入相似性缓存
# 来判定行为新颖性 —— 此处提供通用的时间感知型淘汰策略。
import threading
import time
import functools
from typing import Dict, Any, Optional, Callable, Tuple, OrderedDict as OD
from collections import OrderedDict

# ---- LRU Cache (基于 OrderedDict) ---------------------------------------

class LRUCache:
    """线程安全的 LRU 缓存。基于 OrderedDict 的移动-到-末尾策略。
    get 将条目移到末尾（最近使用），容量满时淘汰开头（最久未用）。
    O(1) get/put。"""

    def __init__(self, capacity: int = 128):
        if capacity < 1:
            raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._store: OrderedDict = OrderedDict()
        self._lock = threading.Lock()

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            if key not in self._store:
                return default
            self._store.move_to_end(key)
            return self._store[key]

    def put(self, key: Any, value: Any):
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._store[key] = value
            else:
                if len(self._store) >= self.capacity:
                    self._store.popitem(last=False)
                self._store[key] = value

    def remove(self, key: Any) -> bool:
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def clear(self):
        with self._lock:
            self._store.clear()

    def __len__(self):
        with self._lock:
            return len(self._store)

    def __contains__(self, key):
        with self._lock:
            return key in self._store

# ---- TTL Cache (带过期时间的 LRU) ---------------------------------------

class TTLCache:
    """LRU + TTL 缓存。每个条目在 TTL 秒后自动失效。
    惰性淘汰: 仅在访问时检查过期。put 时若满则主动淘汰过期条目。"""

    def __init__(self, capacity: int = 256, ttl_seconds: float = 300.0):
        self.capacity = capacity
        self.ttl = ttl_seconds
        self._store: OrderedDict = OrderedDict()
        self._lock = threading.RLock()

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            if key not in self._store:
                return default
            value, expires_at = self._store[key]
            if time.monotonic() > expires_at:
                del self._store[key]
                return default
            self._store.move_to_end(key)
            return value

    def put(self, key: Any, value: Any, ttl: Optional[float] = None):
        ttl_val = ttl if ttl is not None else self.ttl
        expires_at = time.monotonic() + ttl_val
        with self._lock:
            if key in self._store:
                self._store.move_to_end(key)
                self._store[key] = (value, expires_at)
            else:
                self._evict_expired()
                if len(self._store) >= self.capacity:
                    self._store.popitem(last=False)
                self._store[key] = (value, expires_at)

    def _evict_expired(self):
        """主动清除过期条目。"""
        now = time.monotonic()
        expired = [k for k, (_, exp) in self._store.items() if now > exp]
        for k in expired:
            del self._store[k]

    def remove(self, key: Any) -> bool:
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def clear(self):
        with self._lock:
            self._store.clear()

    def __len__(self):
        with self._lock:
            self._evict_expired()
            return len(self._store)

# ---- LFU Cache (最不频繁使用) -------------------------------------------

class LFUCache:
    """LFU (Least Frequently Used)。频率相同时回退 LRU。
    参考 Shah et al. 2004 的 O(1) LFU 实现。"""

    def __init__(self, capacity: int = 128):
        if capacity < 1: raise ValueError("capacity must be >= 1")
        self.capacity = capacity
        self._kv: Dict[Any, Any] = {}           # key → value
        self._kf: Dict[Any, int] = {}           # key → frequency
        self._fk: Dict[int, OrderedDict] = {}  # freq → OrderedDict[key → None]
        self._min_freq: int = 0
        self._lock = threading.Lock()

    def get(self, key: Any, default: Any = None) -> Any:
        with self._lock:
            if key not in self._kv:
                return default
            self._incr_freq(key)
            return self._kv[key]

    def put(self, key: Any, value: Any):
        with self._lock:
            if key in self._kv:
                self._kv[key] = value
                self._incr_freq(key)
                return
            if len(self._kv) >= self.capacity:
                self._evict_one()
            self._kv[key] = value
            self._kf[key] = 1
            self._fk.setdefault(1, OrderedDict())[key] = None
            self._min_freq = 1

    def _incr_freq(self, key: Any):
        freq = self._kf[key]
        self._kf[key] = freq + 1
        del self._fk[freq][key]
        if not self._fk[freq]:
            del self._fk[freq]
            if self._min_freq == freq:
                self._min_freq = freq + 1
        self._fk.setdefault(freq + 1, OrderedDict())[key] = None

    def _evict_one(self):
        if self._min_freq not in self._fk:
            return
        evict_key, _ = self._fk[self._min_freq].popitem(last=False)
        if not self._fk[self._min_freq]:
            del self._fk[self._min_freq]
        del self._kv[evict_key]
        del self._kf[evict_key]

    def remove(self, key: Any) -> bool:
        with self._lock:
            if key not in self._kv:
                return False
            freq = self._kf.pop(key)
            del self._kv[key]
            del self._fk[freq][key]
            if not self._fk[freq]:
                del self._fk[freq]
            return True

    def clear(self):
        with self._lock:
            self._kv.clear()
            self._kf.clear()
            self._fk.clear()
            self._min_freq = 0

    def __len__(self):
        with self._lock:
            return len(self._kv)

# ---- memoize 装饰器 ------------------------------------------------------

def memoize(maxsize: int = 128):
    """函数结果缓存装饰器。使用 LRU 策略。"""
    def decorator(func: Callable):
        cache = LRUCache(maxsize)
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            result = cache.get(key, _SENTINEL := object())
            if result is not _SENTINEL:
                return result
            result = func(*args, **kwargs)
            cache.put(key, result)
            return result
        wrapper._cache_info = lambda: {"size": len(cache), "capacity": maxsize}
        wrapper._cache_clear = cache.clear
        return wrapper
    return decorator

# ---- TTL memoize ---------------------------------------------------------

def ttl_memoize(ttl_seconds: float = 60.0, maxsize: int = 256):
    """带 TTL 过期的 memoize 装饰器。"""
    def decorator(func: Callable):
        cache = TTLCache(maxsize, ttl_seconds)
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            key = (args, tuple(sorted(kwargs.items())))
            val = cache.get(key, _SENTINEL := object())
            if val is not _SENTINEL:
                return val
            val = func(*args, **kwargs)
            cache.put(key, val)
            return val
        wrapper._cache_clear = cache.clear
        return wrapper
    return decorator
