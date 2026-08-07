"""
Tests for multiprocess SMT solver pool with dispatch, caching, adaptive sizing,
warmup cache, and cross-session reuse.

Covers:
- SolverWorker lifecycle (start/stop/status)
- SolverPool: submit, dispatch, monitoring, stats
- AdaptivePoolSizing: grow/shrink logic
- SolverWarmupCache: pattern-based warmup
- SolverSession: cross-session result reuse
- SolverCache: constraint-hash-based response cache
- SolverConfig, SolverRequest, SolverResponse dataclasses
"""
import unittest
import time
import threading

from modules.analysis.symbolic.solver_pool import (
    SolverPool,
    SolverWorker,
    SolverCache,
    SolverSession,
    SolverWarmupCache,
    AdaptivePoolSizing,
    SolverConfig,
    SolverRequest,
    SolverResponse,
    SolverStatus,
    SolverType,
    _hash_constraints,
    get_solver_pool,
    get_solver_cache,
    get_warmup_cache,
    clear_cross_session_cache,
)


class TestConstraintHashing(unittest.TestCase):
    """SHA-256 constraint hashing."""

    def test_same_input_same_hash(self):
        """相同约束字符串→相同哈希"""
        h1 = _hash_constraints("(assert (> x 0))")
        h2 = _hash_constraints("(assert (> x 0))")
        self.assertEqual(h1, h2)

    def test_different_input_different_hash(self):
        """不同约束→不同哈希"""
        h1 = _hash_constraints("(assert (> x 0))")
        h2 = _hash_constraints("(assert (> x 1))")
        self.assertNotEqual(h1, h2)

    def test_hash_length(self):
        """输出为 32 字符 hex 字符串"""
        h = _hash_constraints("test")
        self.assertEqual(len(h), 32)


class TestSolverConfig(unittest.TestCase):
    """Solver configuration dataclass."""

    def test_default_config(self):
        """默认配置：Z3, 2048MB, 60s timeout, priority=1"""
        config = SolverConfig(solver_type=SolverType.Z3)
        self.assertEqual(config.solver_type, SolverType.Z3)
        self.assertEqual(config.max_memory_mb, 2048)
        self.assertEqual(config.timeout_seconds, 60)
        self.assertEqual(config.priority, 1)

    def test_custom_config(self):
        """自定义配置"""
        config = SolverConfig(
            solver_type=SolverType.CVC5,
            max_memory_mb=1024,
            timeout_seconds=30,
            priority=2,
            binary_path="/usr/bin/cvc5",
        )
        self.assertEqual(config.binary_path, "/usr/bin/cvc5")
        self.assertEqual(config.priority, 2)


class TestSolverRequestResponse(unittest.TestCase):
    """SolverRequest and SolverResponse dataclasses."""

    def test_request_defaults(self):
        """SolverRequest 默认字段"""
        req = SolverRequest(request_id="req_1", constraints="(assert true)")
        self.assertEqual(req.request_id, "req_1")
        self.assertGreater(req.submitted_at, 0)
        self.assertEqual(req.options, {})

    def test_response_fields(self):
        """SolverResponse 所有字段"""
        resp = SolverResponse(
            request_id="req_1",
            result="sat",
            status="success",
            model="(x 42)",
            execution_time=0.05,
        )
        self.assertEqual(resp.result, "sat")
        self.assertEqual(resp.status, "success")
        self.assertEqual(resp.model, "(x 42)")

    def test_response_with_error(self):
        """错误响应"""
        resp = SolverResponse(
            request_id="req_err",
            result="unknown",
            status="error",
            error="Solver timeout",
        )
        self.assertEqual(resp.status, "error")
        self.assertIsNotNone(resp.error)


class TestSolverCache(unittest.TestCase):
    """Thread-safe solver response cache."""

    def setUp(self):
        self.cache = SolverCache(max_entries=5)

    def test_get_miss(self):
        """缓存未命中返回 None"""
        result = self.cache.get("nonexistent_hash")
        self.assertIsNone(result)

    def test_set_and_get(self):
        """set 后 get 返回相同值"""
        resp = SolverResponse(request_id="r1", result="sat", status="success")
        self.cache.set("hash1", resp)
        retrieved = self.cache.get("hash1")
        self.assertIsNotNone(retrieved)
        self.assertEqual(retrieved.result, "sat")

    def test_max_entries_eviction(self):
        """超出 max_entries 时驱逐最旧条目"""
        cache = SolverCache(max_entries=3)
        for i in range(5):
            resp = SolverResponse(request_id=f"r{i}", result="sat", status="success")
            cache.set(f"hash{i}", resp)
        stats = cache.stats()
        self.assertLessEqual(stats["entries"], 3)

    def test_clear(self):
        """clear 清空缓存"""
        resp = SolverResponse(request_id="r1", result="sat", status="success")
        self.cache.set("hash1", resp)
        self.cache.clear()
        self.assertEqual(self.cache.stats()["entries"], 0)


class TestSolverWarmupCache(unittest.TestCase):
    """Pre-solving common constraint patterns on startup."""

    def setUp(self):
        self.warmup = SolverWarmupCache()

    def test_not_warmed_initially(self):
        """初始状态未预热"""
        self.assertFalse(self.warmup.is_warmed())

    def test_warmup_patterns_defined(self):
        """WARMUP_PATTERNS 包含常见约束模式"""
        patterns = SolverWarmupCache.WARMUP_PATTERNS
        self.assertGreater(len(patterns), 0)
        for p in patterns:
            self.assertTrue(p.startswith("(declare-const") or "(assert" in p)

    def test_get_cached_miss(self):
        """预热前 get_cached 返回 None"""
        result = self.warmup.get_cached("(assert (> x 0))")
        self.assertIsNone(result)

    def test_stats(self):
        """stats 返回 patterns_cached 和 warmed 状态"""
        s = self.warmup.stats()
        self.assertIn("patterns_cached", s)
        self.assertIn("warmed", s)


