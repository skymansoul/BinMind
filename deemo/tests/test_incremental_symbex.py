"""
Tests for incremental symbolic execution module.

Covers: IncrementalSymbEx, SolverCache, StateCheckpoint, IncrementalReport.
"""
import unittest

from modules.analysis.symbolic.incremental_symbex import (
    IncrementalSymbEx,
    IncrementalReport,
    SolverCache,
    SolverCacheEntry,
    StateCheckpoint,
    FunctionHasher,
    CacheInvalidationTag,
)


class TestSolverCacheEntry(unittest.TestCase):
    """Cache entry for solver results."""

    def test_creation(self):
        entry = SolverCacheEntry(constraint_hash="abc123", result="sat", model={"x": 42})
        self.assertEqual(entry.constraint_hash, "abc123")
        self.assertEqual(entry.result, "sat")
        self.assertEqual(entry.model["x"], 42)


class TestSolverCache(unittest.TestCase):
    """Incremental solver cache."""

    def setUp(self):
        self.cache = SolverCache(max_size=10)

    def test_put_and_get(self):
        entry = SolverCacheEntry(constraint_hash="h1", result="sat")
        self.cache.put("h1", entry)
        retrieved = self.cache.get("h1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.result, "sat")

    def test_get_miss(self):
        self.assertIsNone(self.cache.get("nonexistent"))

    def test_max_size_eviction(self):
        cache = SolverCache(max_size=3)
        for i in range(5):
            cache.put(f"h{i}", SolverCacheEntry(constraint_hash=f"h{i}", result="sat"))
        self.assertLessEqual(cache.size(), 3)

    def test_clear(self):
        self.cache.put("h1", SolverCacheEntry(constraint_hash="h1", result="sat"))
        self.cache.clear()
        self.assertEqual(self.cache.size(), 0)

    def test_stats(self):
        self.cache.put("a", SolverCacheEntry(constraint_hash="a", result="sat"))
        stats = self.cache.stats()
        self.assertIn("hits", stats)
        self.assertIn("misses", stats)


class TestStateCheckpoint(unittest.TestCase):
    """State checkpoint for save/restore."""

    def test_creation(self):
        cp = StateCheckpoint(state_id="s1", pc=0x4000, constraints=["x > 0"])
        self.assertEqual(cp.state_id, "s1")
        self.assertEqual(cp.pc, 0x4000)
        self.assertEqual(len(cp.constraints), 1)


class TestIncrementalSymbEx(unittest.TestCase):
    """Incremental symbolic execution engine."""

    def setUp(self):
        self.engine = IncrementalSymbEx()

    def test_creation(self):
        self.assertIsNotNone(self.engine)

    def test_get_report(self):
        report = self.engine.get_report()
        self.assertIsInstance(report, IncrementalReport)

    def test_analyze_empty(self):
        report = self.engine.analyze(target_func="test", max_steps=5)
        self.assertIsInstance(report, IncrementalReport)

    def test_reset(self):
        self.engine.reset()
        report = self.engine.get_report()
        self.assertIsInstance(report, IncrementalReport)


class TestIncrementalReport(unittest.TestCase):
    """Report from incremental execution."""

    def test_creation(self):
        report = IncrementalReport()
        self.assertIsNotNone(report)


class TestFunctionHasher(unittest.TestCase):
    """Function hashing for change detection."""

    def test_hash_deterministic(self):
        h1 = FunctionHasher.hash_function("func_a")
        h2 = FunctionHasher.hash_function("func_a")
        self.assertEqual(h1, h2)


class TestCacheInvalidationTag(unittest.TestCase):
    """Cache invalidation tagging."""

    def test_tag_values(self):
        self.assertIn("function_changed", CacheInvalidationTag.__members__)
        self.assertIn("constraint_updated", CacheInvalidationTag.__members__)


if __name__ == "__main__":
    unittest.main()
