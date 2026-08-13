# LRU/LFU/FIFO eviction strategies -- reminds me of OS class back in uni
# Timeout-based invalidation tests not yet covered
import os
import shutil
import pytest


from modules.incremental_analysis import (
    CacheEntry,
    CacheInvalidationPolicy,
    CacheStatistics,
    CacheStrategy,
    IncrementalAnalysisCache,
    IncrementalAnalyzer,
    IncrementalUpdate,
)


class TestCacheStrategyEnum:
    def test_cache_strategy_values(self):
        assert CacheStrategy.LRU.value == "lru"
        assert CacheStrategy.LFU.value == "lfu"
        assert CacheStrategy.FIFO.value == "fifo"


class TestCacheInvalidationPolicyEnum:
    def test_invalidation_policy_values(self):
        assert CacheInvalidationPolicy.TIMEOUT.value == "timeout"
        assert CacheInvalidationPolicy.SIZE_LIMIT.value == "size_limit"
        assert CacheInvalidationPolicy.MANUAL.value == "manual"
        assert CacheInvalidationPolicy.CONTENT_CHANGE.value == "content_change"


class TestCacheEntryDataclass:
    def test_cache_entry_creation(self):
        """Basic cache entry -- access_count starts at 0"""
        entry = CacheEntry(key="test_key", data={"value": 42}, timestamp=1234567890.0)
        if entry is None:
            raise AssertionError("CacheEntry is None?!")
        assert entry.key == "test_key"
        assert entry.data == {"value": 42}
        assert entry.timestamp == 1234567890.0
        assert entry.access_count == 0
        assert entry.hash == ""
        assert entry.metadata == {}


class TestCacheStatisticsDataclass:
    def test_cache_statistics_creation(self):
        stats = CacheStatistics(hits=10, misses=5, evictions=2)
        assert stats.hits == 10
        assert stats.misses == 5
        assert stats.evictions == 2
        assert stats.entries == 0
        assert stats.total_size == 0


class TestIncrementalUpdateDataclass:
    def test_incremental_update_creation(self):
        """new/removed/changed three lists"""
        update = IncrementalUpdate(
            new_functions=["func1"],
            removed_functions=["func2"],
            changed_functions=["func3"],
        )
        assert update.new_functions == ["func1"]
        assert update.removed_functions == ["func2"]
        assert update.changed_functions == ["func3"]


class TestIncrementalAnalysisCache:
    def setup_method(self):
        """Create test cache dir, max 10 entries"""
        self.m_cache = IncrementalAnalysisCache(
            cache_dir=".test_cache", max_entries=10, max_size_mb=1
        )

    def teardown_method(self):
        if os.path.exists(".test_cache"):
            shutil.rmtree(".test_cache")

    def test_cache_set_and_get(self):
        self.m_cache.set("test_key", {"data": "test_data"}, "hash123")
        result = self.m_cache.get("test_key", "hash123")
        assert result == {"data": "test_data"}

    def test_cache_hash_mismatch(self):
        """Hash mismatch should return None"""
        self.m_cache.set("test_key", {"data": "test_data"}, "hash123")
        result = self.m_cache.get("test_key", "hash456")
        assert result is None

    def test_cache_miss(self):
        result = self.m_cache.get("nonexistent_key")
        assert result is None

    def test_cache_statistics(self):
        # set 1 time, get 3 times (2 hits + 1 miss)
        self.m_cache.set("key1", "data1", "hash1")
        self.m_cache.get("key1", "hash1")
        self.m_cache.get("key1", "hash1")
        self.m_cache.get("nonexistent", "hash")
        stats = self.m_cache.get_statistics()
        assert stats.hits == 2
        assert stats.misses == 1

    def test_cache_invalidation(self):
        self.m_cache.set("key1", "data1", "hash1")
        self.m_cache.invalidate("key1")
        result = self.m_cache.get("key1", "hash1")
        assert result is None

    def test_cache_eviction(self):
        """Insert 15 entries -> some eviction should happen"""
        for j in range(15):
            self.m_cache.set(f"key{j}", f"data{j}", f"hash{j}")
        stats = self.m_cache.get_statistics()
        assert stats.evictions > 0


class TestIncrementalAnalyzer:
    def setup_method(self):
        self.m_analyzer = IncrementalAnalyzer()
        # 默认 .cache 目录会残留历次运行结果，令"首次运行"判定不稳定；改用独立目录隔离
        self.m_analyzer.cache.cache_dir = ".test_analyzer_cache"
        self.m_binpath = "test_binary.bin"
        with open(self.m_binpath, "wb") as k:
            k.write(b"\x00\x01\x02\x03")

    def teardown_method(self):
        if os.path.exists(self.m_binpath):
            os.remove(self.m_binpath)
        if os.path.exists(".test_analyzer_cache"):
            shutil.rmtree(".test_analyzer_cache")

    def test_analyzer_initialization(self):
        assert self.m_analyzer is not None

    def test_get_metadata(self):
        metadata = self.m_analyzer.get_metadata()
        assert metadata.name == "IncrementalAnalyzer"
        assert metadata.version == "1.0.0"

    def test_analyze_first_run(self):
        """First analyze -- from_cache should be False"""
        result = self.m_analyzer.analyze(binary_path=self.m_binpath)
        assert result["success"] is True
        assert result["from_cache"] is False

    def test_analyze_from_cache(self):
        """Second analyze -- should read from cache"""
        self.m_analyzer.analyze(binary_path=self.m_binpath)
        result = self.m_analyzer.analyze(binary_path=self.m_binpath)
        assert result["success"] is True
        assert result["from_cache"] is True

    def test_analyze_with_previous(self):
        """Pass previous_analysis -> incremental_update"""
        previous = {"functions": ["func1", "func2"]}
        result = self.m_analyzer.analyze(
            binary_path=self.m_binpath, previous_analysis=previous
        )
        assert result["success"] is True
        assert "incremental_update" in result["result"]

    def test_analyze_missing_binary(self):
        result = self.m_analyzer.analyze(binary_path="nonexistent.bin")
        assert result["success"] is False

    def test_get_cache_statistics(self):
        stats = self.m_analyzer.get_cache_statistics()
        assert isinstance(stats, CacheStatistics)

    def test_invalidate_cache(self):
        self.m_analyzer.analyze(binary_path=self.m_binpath)
        self.m_analyzer.invalidate_cache()
        stats = self.m_analyzer.get_cache_statistics()
        assert stats.entries == 0
