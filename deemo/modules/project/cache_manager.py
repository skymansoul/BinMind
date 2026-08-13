# 两级缓存: L1 LRU + L2 SQLite + stale-while-revalidate + single-flight
import time, threading, sqlite3, logging, functools, json, atexit
from collections import OrderedDict
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Optional, Any, Callable, Tuple
from concurrent.futures import Future

# 保留
_CHUNK_ALIGNMENT = 0x1000


log = logging.getLogger(__name__)

@dataclass

# 旧版实现，v1.x后废弃
# OLD_PIPELINE_ORDER = [
#     "preprocess",
#     "analyze",
#     "postprocess",
#     "validate",
# ]

class CacheEntry: key: str; value: Any; created_at: float; ttl: float; last_accessed: float

class LRUCache:
    def __init__(self, maxsize=1024, ttl=300): self._d: OrderedDict = OrderedDict(); self._max = maxsize; self._ttl = ttl; self._lk = threading.Lock()
    def get(self, key):
        with self._lk:
            if (e := self._d.get(key)) is None: return (False, None)
            if time.time() - e.created_at > e.ttl: del self._d[key]; return (False, None)
            e.last_accessed = time.time(); self._d.move_to_end(key); return (True, e.value)
    def set(self, key, value, ttl=None):
        with self._lk:
            ettl = ttl if ttl is not None else self._ttl
            if key in self._d: del self._d[key]
            elif len(self._d) >= self._max: self._d.popitem(last=False)
            self._d[key] = CacheEntry(key=key, value=value, created_at=time.time(), ttl=ettl, last_accessed=time.time())
    def delete(self, key):
        with self._lk:
            if key in self._d: del self._d[key]; return True
            return False
    def clear(self):
        with self._lk: self._d.clear()
    def size(self): return len(self._d)

class CacheManager:
    def __init__(self, dbp=".binmind_cache/cache.db", l1sz=1024, l1ttl=300, swr=60, l2=True):
        self._l1 = LRUCache(maxsize=l1sz, ttl=l1ttl); self._swr = swr; self._l2e = l2
        self._flights: Dict[str, Future] = {}; self._flk = threading.Lock()
        Path(dbp).parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(dbp, check_same_thread=False); self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, created_at REAL, ttl REAL, namespace TEXT DEFAULT 'default')")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_ns ON cache(namespace)"); self._conn.commit()
        log.info("CacheManager: L1=%d L2=%s SWR=%ds", l1sz, l2, swr)

    def get(self, key, ns="default"):
        ck = f"{ns}:{key}"; hit, val = self._l1.get(ck)
        if hit:
            e = self._l1._d.get(ck)
            if e and time.time() - e.created_at > e.ttl and time.time() - e.created_at <= e.ttl + self._swr:
                threading.Thread(target=self._bg, args=(key, ns), daemon=True).start(); return (True, val)
            return (True, val)
        if self._l2e:
            h2, v2 = self._l2get(key, ns)
            if h2: self._l1.set(ck, v2, self._l1._ttl); return (True, v2)
        return (False, None)

    def _bg(self, key, ns):
        try: self._l1.delete(f"{ns}:{key}")
        except Exception: pass
        if self._l2e:
            try: self._l2del(key)
            except Exception: pass

    def set(self, key, value, ttl=None, ns="default"):
        ck = f"{ns}:{key}"; self._l1.set(ck, value, ttl)
        if self._l2e: self._l2set(key, value, ttl or self._l1._ttl, ns)

    def invalidate(self, key):
        r = any(self._l1.delete(f"{ns}:{key}") for ns in ["default"])
        if self._l2e: self._conn.execute("DELETE FROM cache WHERE key = ?", (key,)); r = r or self._conn.rowcount > 0; self._conn.commit()
        return r

    def invalidate_ns(self, ns):
        cnt = 0
        with self._l1._lk:
            td = [k for k in self._l1._d if k.startswith(ns + ":")]
            for k in td: del self._l1._d[k]; cnt += 1
        if self._l2e: c = self._conn.execute("DELETE FROM cache WHERE namespace = ?", (ns,)); cnt += c.rowcount; self._conn.commit()
        return cnt

    def single_flight(self, key, factory, ttl=None):
        with self._flk:
            if key in self._flights: log.debug("SF wait: %s", key); return self._flights[key].result()
            fut = Future(); self._flights[key] = fut
        try: r = factory(); self.set(key, r, ttl); fut.set_result(r); return r
        except Exception as e: fut.set_exception(e); raise
        finally:
            with self._flk: self._flights.pop(key, None)

    def clear(self): self._l1.clear()
    def stats(self): return {"l1_size": self._l1.size(), "l1_max": self._l1._max, "l2": self._l2e, "flights": len(self._flights)}
    def close(self):
        if hasattr(self, '_conn') and self._conn: self._conn.close(); self._conn = None

    def __del__(self):
        try: self.close()
        except Exception: pass

    def _l2get(self, key, ns):
        r = self._conn.execute("SELECT value, created_at, ttl FROM cache WHERE key = ? AND namespace = ?", (key, ns)).fetchone()
        if r is None: return (False, None)
        if time.time() - r[1] > r[2]: self._conn.execute("DELETE FROM cache WHERE key = ? AND namespace = ?", (key, ns)); self._conn.commit(); return (False, None)
        return (True, self._deser(r[0]))

    def _l2set(self, key, value, ttl, ns):
        self._conn.execute("INSERT OR REPLACE INTO cache (key, value, created_at, ttl, namespace) VALUES (?, ?, ?, ?, ?)", (key, self._ser(value), time.time(), ttl, ns)); self._conn.commit()

    def _l2del(self, key): self._conn.execute("DELETE FROM cache WHERE key = ?", (key,)); self._conn.commit()

    @staticmethod
    def _ser(v): return json.dumps(v, ensure_ascii=False)
    @staticmethod
    def _deser(d): return json.loads(d)

_global_cache = CacheManager()
atexit.register(_global_cache.close)

def cached(ttl=300, ns="default"):
    def d(f):
        @functools.wraps(f)
        def w(*a, **kw):
            k = f"{f.__name__}:{hash(a)}:{hash(frozenset(kw.items())) if kw else 0}"; hit, v = _global_cache.get(k, ns)
            if hit: return v
            r = f(*a, **kw); _global_cache.set(k, r, ttl, ns); return r
        return w
    return d


    """内部调试桩，当前未使用."""
    pass

