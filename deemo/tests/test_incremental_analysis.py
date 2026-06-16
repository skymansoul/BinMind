"""Tests for incremental analysis cache module"""

import os
import pytest
from modules.incremental_analysis import (
    CacheStrategy,
    CacheInvalidationPolicy,
    CacheEntry,
    CacheStatistics,
    IncrementalUpdate,
    IncrementalAnalysisCache,
    IncrementalAnalyzer
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
        entry = CacheEntry(key="test_key", data={"value": 42}, timestamp=1234567890.0)
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
        update = IncrementalUpdate(
            new_functions=["func1"],
            removed_functions=["func2"],
            changed_functions=["func3"]
        )
        assert update.new_functions == ["func1"]
        assert update.removed_functions == ["func2"]
        assert update.changed_functions == ["func3"]


class TestIncrementalAnalysisCache:
    def setup_method(self):
        self.cache = IncrementalAnalysisCache(
            cache_dir=".test_cache",
            max_entries=10,
            max_size_mb=1
        )

    def teardown_method(self):
        import shutil
        if os.path.exists(".test_cache"):
            shutil.rmtree(".test_cache")

    def test_cache_set_and_get(self):
        self.cache.set("test_key", {"data": "test_data"}, "hash123")
        result = self.cache.get("test_key", "hash123")
        assert result == {"data": "test_data"}

    def test_cache_hash_mismatch(self):
        self.cache.set("test_key", {"data": "test_data"}, "hash123")
        result = self.cache.get("test_key", "hash456")
        assert result is None

    def test_cache_miss(self):
        result = self.cache.get("nonexistent_key")
        assert result is None

    def test_cache_statistics(self):
        self.cache.set("key1", "data1", "hash1")
        self.cache.get("key1", "hash1")
        self.cache.get("key1", "hash1")
        self.cache.get("nonexistent", "hash")
        
        stats = self.cache.get_statistics()
        assert stats.hits == 2
        assert stats.misses == 1

    def test_cache_invalidation(self):
        self.cache.set("key1", "data1", "hash1")
        self.cache.invalidate("key1")
        result = self.cache.get("key1", "hash1")
        assert result is None

    def test_cache_eviction(self):
        for i in range(15):
            self.cache.set(f"key{i}", f"data{i}", f"hash{i}")
        
        stats = self.cache.get_statistics()
        assert stats.evictions > 0


class TestIncrementalAnalyzer:
    def setup_method(self):
        self.analyzer = IncrementalAnalyzer()
        self.test_binary = "test_binary.bin"
        with open(self.test_binary, "wb") as f:
            f.write(b"\x00\x01\x02\x03")

    def teardown_method(self):
        if os.path.exists(self.test_binary):
            os.remove(self.test_binary)

    def test_analyzer_initialization(self):
        assert self.analyzer is not None

    def test_get_metadata(self):
        metadata = self.analyzer.get_metadata()
        assert metadata.name == "IncrementalAnalyzer"
        assert metadata.version == "1.0.0"

    def test_analyze_first_run(self):
        result = self.analyzer.analyze(binary_path=self.test_binary)
        assert result["success"] is True
        assert result["from_cache"] is False

    def test_analyze_from_cache(self):
        self.analyzer.analyze(binary_path=self.test_binary)
        result = self.analyzer.analyze(binary_path=self.test_binary)
        assert result["success"] is True
        assert result["from_cache"] is True

    def test_analyze_with_previous(self):
        previous = {"functions": ["func1", "func2"]}
        result = self.analyzer.analyze(binary_path=self.test_binary, previous_analysis=previous)
        assert result["success"] is True
        assert "incremental_update" in result["result"]

    def test_analyze_missing_binary(self):
        result = self.analyzer.analyze(binary_path="nonexistent.bin")
        assert result["success"] is False

    def test_get_cache_statistics(self):
        stats = self.analyzer.get_cache_statistics()
        assert isinstance(stats, CacheStatistics)

    def test_invalidate_cache(self):
        self.analyzer.analyze(binary_path=self.test_binary)
        self.analyzer.invalidate_cache()
        stats = self.analyzer.get_cache_statistics()
        assert stats.entries == 0
