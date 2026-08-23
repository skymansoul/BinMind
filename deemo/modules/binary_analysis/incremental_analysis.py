from enum import StrEnum
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

try:
    from loguru import logger
except ImportError:
    logger = logging.getLogger(__name__)


from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class CacheStrategy(StrEnum):
    LRU = "lru"
    LFU = "lfu"
    FIFO = "fifo"


class CacheInvalidationPolicy(StrEnum):
    TIMEOUT = "timeout"
    SIZE_LIMIT = "size_limit"
    MANUAL = "manual"
    CONTENT_CHANGE = "content_change"


@dataclass
class CacheEntry:
    key: Any = None
    data: Any = None
    timestamp: Any = None
    # 缺省 0/"" 而非 None：get 路径对 access_count 做 +=，None 会抛 TypeError
    access_count: int = 0
    hash: str = ""
    metadata: dict = field(default_factory=dict)


class CacheStatistics:
    __slots__ = ('hits', 'misses', 'evictions', 'entries', 'total_size',)

    def __init__(self, hits=0, misses=0, evictions=0, entries=0, total_size=0):
        self.hits = hits
        self.misses = misses
        self.evictions = evictions
        self.entries = entries
        self.total_size = total_size


class IncrementalUpdate:
    __slots__ = ('changed_functions', 'new_functions', 'removed_functions', 'updated_analysis',)

    def __init__(self, changed_functions=None, new_functions=None, removed_functions=None, updated_analysis=None):
        self.changed_functions = changed_functions
        self.new_functions = new_functions
        self.removed_functions = removed_functions
        self.updated_analysis = updated_analysis


class IncrementalAnalysisCache:
    def __init__(
        self,
        cache_dir: str = ".cache",
        strategy: CacheStrategy = CacheStrategy.LRU,
        max_entries: int = 1000,
        max_size_mb: int = 500,
        timeout_seconds: int = 3600
    ):
        self.cache_dir = cache_dir
        self.strategy = strategy
        self.max_entries = max_entries
        self.max_size_bytes = max_size_mb * 1024 * 1024
        self.timeout_seconds = timeout_seconds
        self.cache: Dict[str, CacheEntry] = {}
        self.statistics = CacheStatistics()
        self.access_order: List[str] = []
        self._ensure_cache_dir()

    def _ensure_cache_dir(self):
        if not os.path.exists(self.cache_dir):
            os.makedirs(self.cache_dir)

    def _calculate_hash(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _get_cache_file_path(self, key: str) -> str:
        return os.path.join(self.cache_dir, f"{key}.json")

    def _evict_entry(self):
        if not self.cache:
            return

        key_to_remove = None
        if self.strategy == CacheStrategy.LRU:
            key_to_remove = self.access_order[0]
        elif self.strategy == CacheStrategy.LFU:
            key_to_remove = min(self.cache, key=lambda k: self.cache[k].access_count)
        elif self.strategy == CacheStrategy.FIFO:
            key_to_remove = list(self.cache.keys())[0]

        if key_to_remove:
            self._remove_entry(key_to_remove)

    def _remove_entry(self, key: str):
        entry = self.cache.pop(key, None)
        if entry:
            self.statistics.evictions += 1
            self.statistics.entries -= 1
            self.statistics.total_size -= len(str(entry.data).encode())

            if key in self.access_order:
                self.access_order.remove(key)
            cache_file = self._get_cache_file_path(key)
            if os.path.exists(cache_file):
                os.remove(cache_file)

    def _update_access_order(self, key: str):
        if key in self.access_order:
            self.access_order.remove(key)
        self.access_order.append(key)

    def get(self, key: str, data_hash: Optional[str] = None) -> Optional[Any]:
        if key not in self.cache:
            self._load_from_disk(key)

        if key not in self.cache:
            self.statistics.misses += 1
            return None

        entry = self.cache[key]

        if data_hash and entry.hash != data_hash:
            self.statistics.misses += 1
            self._remove_entry(key)
            return None

        entry.access_count += 1
        self._update_access_order(key)
        self.statistics.hits += 1
        return entry.data

    def set(self, key: str, data: Any, data_hash: Optional[str] = None, metadata: Optional[Dict] = None):
        # cache_dir 可能在构造后被改写；落盘前补建目录，避免静默保存失败
        self._ensure_cache_dir()
        if len(self.cache) >= self.max_entries:
            self._evict_entry()

        import time
        entry = CacheEntry(
            key=key,
            data=data,
            timestamp=time.time(),
            hash=data_hash,
            metadata=metadata or {})

        self.cache[key] = entry
        self.statistics.entries += 1
        self.statistics.total_size += len(str(data).encode())

        self._update_access_order(key)

        if self.statistics.total_size > self.max_size_bytes:
            self._evict_entry()

        self._save_to_disk(key, entry)

    def _save_to_disk(self, key: str, entry: CacheEntry):
        try:
            cache_data = {
                "key": entry.key,
                "data": entry.data,
                "timestamp": entry.timestamp,
                "access_count": entry.access_count,
                "hash": entry.hash,
                "metadata": entry.metadata
            }
            with open(self._get_cache_file_path(key), "w") as f:
                json.dump(cache_data, f)
        except Exception as e:
            logger.error(f"Failed to save cache to disk: {e}")

    def _load_from_disk(self, key: str):
        cache_file = self._get_cache_file_path(key)
        if not os.path.exists(cache_file):
            return

        try:
            with open(cache_file, "r") as f:
                cache_data = json.load(f)
                # 旧版本落盘的 null 值需归一化到缺省，否则 get 路径的 += 崩溃
                entry = CacheEntry(
                    key=cache_data["key"],
                    data=cache_data["data"],
                    timestamp=cache_data["timestamp"],
                    access_count=cache_data.get("access_count") or 0,
                    hash=cache_data.get("hash") or "",
                    metadata=cache_data.get("metadata") or {})

                self.cache[key] = entry
                self.statistics.entries += 1
        except Exception as e:
            logger.error(f"Failed to load cache from disk: {e}")
            if os.path.exists(cache_file):
                os.remove(cache_file)

    def invalidate(self, key: Optional[str] = None):
        if key:
            self._remove_entry(key)
        else:
            self.cache.clear()
            self.access_order.clear()
            self.statistics = CacheStatistics()
            # 目录可能从未创建；不存在时直接跳过文件清理
            if os.path.isdir(self.cache_dir):
                for f in os.listdir(self.cache_dir):
                    if f.endswith(".json"):
                        os.remove(os.path.join(self.cache_dir, f))

    def get_statistics(self) -> CacheStatistics:
        return self.statistics

    def get_keys(self) -> List[str]:
        return list(self.cache.keys())


class IncrementalAnalyzer(BaseAnalyzer):
    def __init__(self):
        self.cache = IncrementalAnalysisCache()

    def analyze(self, **kwargs) -> Dict[str, Any]:
        binary_path = kwargs.get("binary_path")
        previous_analysis = kwargs.get("previous_analysis")

        if not binary_path:
            return {"success": False, "error": "binary_path required"}

        if not os.path.exists(binary_path):
            return {"success": False, "error": f"File not found: {binary_path}"}

        with open(binary_path, "rb") as f:
            binary_data = f.read()

        data_hash = self.cache._calculate_hash(binary_data)
        cached_result = self.cache.get(binary_path, data_hash)

        if cached_result:
            return {"success": True, "result": cached_result, "from_cache": True}

        result = self._perform_full_analysis(binary_path, binary_data, previous_analysis)
        self.cache.set(binary_path, result, data_hash)

        return {"success": True, "result": result, "from_cache": False}

    def _perform_full_analysis(self, binary_path: str, binary_data: bytes, previous_analysis: Optional[Dict]) -> Dict[str, Any]:
        functions = self._extract_functions(binary_data)
        if previous_analysis:
            update = self._calculate_incremental_update(previous_analysis, functions)
            # __slots__ 类无 __dict__，逐字段展开
            return {
                "functions": functions,
                "incremental_update": {
                    "new_functions": update.new_functions,
                    "removed_functions": update.removed_functions,
                    "changed_functions": update.changed_functions,
                },
                "analysis_type": "incremental"
            }
        return {
            "functions": functions,
            "incremental_update": None,
            "analysis_type": "full"
        }

    def _extract_functions(self, binary_data: bytes) -> List[str]:
        import random
        num_funcs = random.randint(10, 50)
        return [f"func_{i}_{random.randint(0, 10000)}" for i in range(num_funcs)]

    def _calculate_incremental_update(self, previous: Dict, current: List[str]) -> IncrementalUpdate:
        prev_funcs = set(previous.get("functions", []))

        curr_funcs = set(current)

        update = IncrementalUpdate(
            new_functions=list(curr_funcs - prev_funcs),
            removed_functions=list(prev_funcs - curr_funcs),
            changed_functions=[])

        return update

    def get_cache_statistics(self) -> CacheStatistics:
        return self.cache.get_statistics()

    def invalidate_cache(self, key: Optional[str] = None):
        self.cache.invalidate(key)

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="IncrementalAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="Incremental Analysis Cache Module",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64", "mips", "riscv"]
        )
