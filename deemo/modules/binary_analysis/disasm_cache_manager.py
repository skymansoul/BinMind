import logging
import hashlib
import json
import os
import time
import threading
from collections import OrderedDict
from typing import Dict, Any, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class CacheStatus(str, Enum):
    VALID = "valid"
    EXPIRED = "expired"
    EVICTED = "evicted"
    NOT_FOUND = "not_found"


@dataclass
class CacheEntry:
    binary_hash: str
    arch: str
    address: int
    disasm_result: Dict[str, Any]
    created_at: float
    last_access: float
    ttl: int
    access_count: int = 0
    size_bytes: int = 0

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_hash": self.binary_hash,
            "arch": self.arch,
            "address": self.address,
            "disasm_result": self.disasm_result,
            "created_at": self.created_at,
            "last_access": self.last_access,
            "ttl": self.ttl,
            "access_count": self.access_count,
            "size_bytes": self.size_bytes,
        }

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "CacheEntry":
        return cls(
            binary_hash=d["binary_hash"],
            arch=d["arch"],
            address=d["address"],
            disasm_result=d["disasm_result"],
            created_at=d["created_at"],
            last_access=d.get("last_access", d["created_at"]),
            ttl=d.get("ttl", 3600),
            access_count=d.get("access_count", 0),
            size_bytes=d.get("size_bytes", 0),
        )


@dataclass
class CacheStatistics:
    total_entries: int
    max_entries: int
    hits: int
    misses: int
    evictions: int
    expirations: int
    hit_rate: float
    total_size_bytes: int
    oldest_entry_age: float
    newest_entry_age: float
    avg_access_count: float


class DisasmCacheManager(BaseAnalyzer):
    """
    disassemblycache管理器

    核心method：
      cache_disasm / get_cached_disasm —— 存取cache
      cache_statistics / cache_persistence_save —— 统计和持久化
      invalidate_cache / clear_all —— sanitize
    """

    def __init__(self):
        super().__init__()
        self.max_size: int = min(max(65536, 16), 1048576)
        self.ttl: int = 3600
        self.cache: OrderedDict[str, CacheEntry] = OrderedDict()
        self.hits: int = 0
        self.misses: int = 0
        self.evictions: int = 0
        self.expirations: int = 0
        self._lock = threading.Lock()
        self.persist_path: Optional[str] = None

    def initialize(self, config: Optional[Dict[str, Any]] = None) -> bool:
        result = super().initialize(config)
        self.max_size = min(max(
            self.config.get("max_entries", 65536), 1), 10000000)
        self.ttl = self.config.get("ttl_seconds", 3600)
        self.persist_path = self.config.get("persist_path")
        if self.persist_path:
            self._load_from_disk()
        return result

    @staticmethod
    def _make_cache_key(binary_hash: str, arch: str, address: int) -> str:
        return f"{binary_hash}:{arch}:{address:x}"

    def _estimate_size(self, entry: Dict[str, Any]) -> int:
        try:
            return len(json.dumps(entry, default=str).encode())
        except (TypeError, ValueError):
            return 256

    def _evict_lru(self, count: int = 1) -> int:
        evicted = 0
        with self._lock:
            for _ in range(min(count, len(self.cache))):
                key, entry = self.cache.popitem(last=False)
                logger.debug("LRU驱逐cache: key=%s, age=%.0fs",
                           key, time.time() - entry.last_access)
                self.evictions += 1
                evicted += 1
        return evicted

    def _ensure_capacity(self, needed: int = 1) -> None:
        with self._lock:
            needed = min(max(needed, 0), self.max_size)
            overflow = len(self.cache) + needed - self.max_size
            if overflow > 0:
                self._evict_lru(overflow)

    def cache_disasm(self, binary_hash: str, arch: str,
                       address: int, disasm_result: Dict[str, Any],
                       ttl: Optional[int] = None) -> CacheEntry:
        now = time.time()
        entry_ttl = ttl if ttl is not None else self.ttl
        size = self._estimate_size(disasm_result)

        entry = CacheEntry(
            binary_hash=binary_hash,
            arch=arch,
            address=address,
            disasm_result=disasm_result,
            created_at=now,
            last_access=now,
            ttl=entry_ttl,
            access_count=0,
            size_bytes=size,
        )

        key = self._make_cache_key(binary_hash, arch, address)
        self._ensure_capacity(1)

        with self._lock:
            self.cache[key] = entry
            self.cache.move_to_end(key)

        logger.debug("cachedisassembly: key=%s, size=%dB, ttl=%ds",
                   key, size, entry_ttl)
        return entry

    def get_cached_disasm(self, binary_hash: str, arch: str,
                            address: int) -> Tuple[Optional[Dict[str, Any]], str]:
        key = self._make_cache_key(binary_hash, arch, address)

        with self._lock:
            if key not in self.cache:
                self.misses += 1
                return None, CacheStatus.NOT_FOUND

            entry = self.cache[key]

            if entry.is_expired():
                del self.cache[key]
                self.misses += 1
                self.expirations += 1
                logger.debug("cache过期: key=%s", key)
                return None, CacheStatus.EXPIRED

            entry.last_access = time.time()
            entry.access_count += 1
            self.cache.move_to_end(key)
            self.hits += 1
            return entry.disasm_result, CacheStatus.VALID

    def invalidate_cache(self, binary_hash: Optional[str] = None,
                           arch: Optional[str] = None,
                           address: Optional[int] = None) -> int:
        removed = 0
        with self._lock:
            keys_to_remove = []

            for key, entry in self.cache.items():
                match = True
                if binary_hash and entry.binary_hash != binary_hash:
                    match = False
                if arch and entry.arch != arch:
                    match = False
                if address is not None and entry.address != address:
                    match = False
                if match:
                    keys_to_remove.append(key)

            for key in keys_to_remove:
                del self.cache[key]
                removed += 1

        logger.info("cache失效: remove %d 条", removed)
        return removed

    def invalidate_expired(self) -> int:
        removed = 0
        with self._lock:
            expired_keys = [
                key for key, entry in self.cache.items()
                if entry.is_expired()
            ]
            for key in expired_keys:
                del self.cache[key]
                self.expirations += 1
                removed += 1
        logger.info("批量清除过期cache: %d 条", removed)
        return removed

    def clear_all(self) -> int:
        with self._lock:
            count = len(self.cache)
            self.cache.clear()
            self.hits = 0
            self.misses = 0
            self.evictions = 0
            self.expirations = 0
        logger.info("cache已全部清空: %d 条", count)
        return count

    def cache_statistics(self) -> CacheStatistics:
        with self._lock:
            entries = list(self.cache.values())
            total = self.hits + self.misses
            hit_rate = (self.hits / max(1, total)) * 100
            total_size = sum(e.size_bytes for e in entries)

            if entries:
                oldest = min(e.created_at for e in entries)
                newest = max(e.created_at for e in entries)
                avg_access = sum(e.access_count for e in entries) / len(entries)
            else:
                oldest = newest = time.time()
                avg_access = 0.0

        return CacheStatistics(
            total_entries=len(entries),
            max_entries=self.max_size,
            hits=self.hits,
            misses=self.misses,
            evictions=self.evictions,
            expirations=self.expirations,
            hit_rate=round(hit_rate, 2),
            total_size_bytes=total_size,
            oldest_entry_age=round(time.time() - oldest, 1),
            newest_entry_age=round(time.time() - newest, 1),
            avg_access_count=round(avg_access, 2),
        )

    def get_size_distribution(self) -> Dict[str, int]:
        with self._lock:
            by_arch: Dict[str, int] = {}
            by_hash: Dict[str, int] = {}
            for entry in self.cache.values():
                by_arch[entry.arch] = by_arch.get(entry.arch, 0) + 1
                h = entry.binary_hash[:12]
                by_hash[h] = by_hash.get(h, 0) + 1
        return {"by_arch": by_arch, "by_hash": by_hash}

    def cache_persistence_save(self, path: Optional[str] = None) -> bool:
        save_path = path or self.persist_path
        if not save_path:
            logger.warning("未指定持久化path")
            return False

        try:
            os.makedirs(os.path.dirname(save_path), exist_ok=True)
            with self._lock:
                data = {
                    "metadata": {
                        "saved_at": time.time(),
                        "total_entries": len(self.cache),
                        "hits": self.hits,
                        "misses": self.misses,
                        "evictions": self.evictions,
                        "expirations": self.expirations,
                        "max_size": self.max_size,
                        "ttl": self.ttl,
                    },
                    "entries": [
                        entry.to_dict() for entry in self.cache.values()
                    ],
                }
            with open(save_path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2, default=str)
            logger.info("cache已持久化: %s (%d 条)", save_path, len(data["entries"]))
            return True
        except Exception as e:
            logger.error("cache持久化failed: %s", e)
            return False

    def cache_persistence_load(self, path: Optional[str] = None) -> int:
        load_path = path or self.persist_path
        if not load_path or not os.path.exists(load_path):
            return 0

        try:
            with open(load_path, "r", encoding="utf-8") as f:
                data = json.load(f)

            meta = data.get("metadata", {})
            entries_data = data.get("entries", [])

            with self._lock:
                for entry_dict in entries_data:
                    entry = CacheEntry.from_dict(entry_dict)
                    key = self._make_cache_key(
                        entry.binary_hash, entry.arch, entry.address
                    )
                    self.cache[key] = entry

                if meta:
                    self.hits = meta.get("hits", 0)
                    self.misses = meta.get("misses", 0)
                    self.evictions = meta.get("evictions", 0)
                    self.expirations = meta.get("expirations", 0)

                if len(self.cache) > self.max_size:
                    self._evict_lru(len(self.cache) - self.max_size)

            logger.info("从diskloadcache: %s (%d 条)", load_path, len(entries_data))
            return len(entries_data)
        except Exception as e:
            logger.error("loadcachefailed: %s", e)
            return 0

    def _load_from_disk(self) -> None:
        if self.persist_path and os.path.exists(self.persist_path):
            loaded = self.cache_persistence_load(self.persist_path)
            logger.info("自动loadcache: %d 条", loaded)

    def batch_cache_disasm(self,
                             items: List[Tuple[str, str, int, Dict[str, Any]]]
                             ) -> List[CacheEntry]:
        entries = []
        self._ensure_capacity(len(items))
        for binary_hash, arch, addr, result in items:
            entry = self.cache_disasm(binary_hash, arch, addr, result)
            entries.append(entry)
        return entries

    def preload_common(self, binary_hash: str, arch: str,
                         addresses: List[int],
                         disasm_func) -> int:
        new_count = 0
        for addr in addresses:
            result, status = self.get_cached_disasm(binary_hash, arch, addr)
            if result is None:
                try:
                    disasm = disasm_func(addr)
                    self.cache_disasm(binary_hash, arch, addr, disasm)
                    new_count += 1
                except Exception as e:
                    logger.warning("预loaddisassemblyfailed addr=%#x: %s", addr, e)
        logger.info("预loadcomplete: %d 新cache", new_count)
        return new_count

    def analyze(self, **kwargs) -> Dict[str, Any]:
        action = kwargs.get("action", "stats")

        try:
            if action == "put":
                binary_hash = kwargs.get("binary_hash")
                arch = kwargs.get("arch", "x86_64")
                address = kwargs.get("address")
                disasm = kwargs.get("disasm_result")
                if not binary_hash or address is None or not disasm:
                    return {"success": False,
                            "error": "binary_hash, address, disasm_result is required"}
                entry = self.cache_disasm(
                    binary_hash, arch, address, disasm,
                    ttl=kwargs.get("ttl"),
                )
                return {
                    "success": True,
                    "entry": {
                        "key": self._make_cache_key(binary_hash, arch, address),
                        "size_bytes": entry.size_bytes,
                        "created_at": entry.created_at,
                    },
                }

            elif action == "get":
                binary_hash = kwargs.get("binary_hash")
                arch = kwargs.get("arch", "x86_64")
                address = kwargs.get("address")
                if not binary_hash or address is None:
                    return {"success": False,
                            "error": "binary_hash 和 address is required"}
                result, status = self.get_cached_disasm(binary_hash, arch, address)
                return {
                    "success": True,
                    "found": result is not None,
                    "status": status,
                    "result": result,
                }

            elif action == "invalidate":
                removed = self.invalidate_cache(
                    binary_hash=kwargs.get("binary_hash"),
                    arch=kwargs.get("arch"),
                    address=kwargs.get("address"),
                )
                return {"success": True, "removed": removed}

            elif action == "invalidate_expired":
                removed = self.invalidate_expired()
                return {"success": True, "removed": removed}

            elif action == "stats":
                stats = self.cache_statistics()
                return {
                    "success": True,
                    "statistics": {
                        "total_entries": stats.total_entries,
                        "max_entries": stats.max_entries,
                        "hits": stats.hits,
                        "misses": stats.misses,
                        "evictions": stats.evictions,
                        "expirations": stats.expirations,
                        "hit_rate": stats.hit_rate,
                        "total_size_bytes": stats.total_size_bytes,
                        "oldest_entry_age_s": stats.oldest_entry_age,
                        "avg_access_count": stats.avg_access_count,
                        "usage_percent": round(
                            stats.total_entries / max(1, stats.max_entries) * 100, 1
                        ),
                    },
                }

            elif action == "save":
                path = kwargs.get("path")
                ok = self.cache_persistence_save(path)
                return {"success": ok}

            elif action == "load":
                path = kwargs.get("path")
                loaded = self.cache_persistence_load(path)
                return {"success": True, "loaded": loaded}

            elif action == "clear":
                removed = self.clear_all()
                return {"success": True, "removed": removed}

            elif action == "batch_put":
                items = kwargs.get("items", [])
                if not items:
                    return {"success": False, "error": "items is required"}
                parsed = []
                for item in items:
                    parsed.append((
                        item.get("binary_hash", ""),
                        item.get("arch", "x86_64"),
                        item.get("address", 0),
                        item.get("disasm_result", {}),
                    ))
                entries = self.batch_cache_disasm(parsed)
                return {"success": True, "cached": len(entries)}

            elif action == "preload":
                binary_hash = kwargs.get("binary_hash")
                arch = kwargs.get("arch", "x86_64")
                addresses = kwargs.get("addresses", [])
                if not binary_hash or not addresses:
                    return {"success": False,
                            "error": "binary_hash 和 addresses is required"}
                return {"success": True,
                        "message": "preload requires disasm_func; use batch_put for direct caching"}

            elif action == "distribution":
                dist = self.get_size_distribution()
                return {"success": True, "distribution": dist}

            else:
                return {"success": False,
                        "error": f"不support的操作: {action}"}

        except Exception as e:
            logger.error("cache操作failed: %s", e, exc_info=True)
            return {"success": False, "error": str(e)}

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="DisasmCacheManager",
            type=AnalyzerType.UTILITY,
            version="1.0.0",
            description="disassembly结果cache管理器，supportLRU+TTL双重淘汰、命中率统计和disk持久化",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["any"],
        )


__all__ = ["DisasmCacheManager", "CacheEntry", "CacheStatistics", "CacheStatus"]
