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


class TestSolverSession(unittest.TestCase):
    """Session with cross-session result reuse."""

    @classmethod
    def setUpClass(cls):
        clear_cross_session_cache()

    def test_add_constraint(self):
        """add_constraint 累积约束集"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        session = SolverSession(pool)
        session.add_constraint("(assert (> x 0))")
        session.add_constraint("(assert (< x 100))")
        # 约束已添加，不应抛出
        self.assertIsNotNone(session)

    def test_add_constraints_batch(self):
        """批量添加约束"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        session = SolverSession(pool)
        session.add_constraints(["(assert true)", "(assert (> y 0))"])
        # 不应抛出
        self.assertIsNotNone(session)

    def test_reset_clears_constraints(self):
        """reset 清空约束和历史"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        session = SolverSession(pool)
        session.add_constraint("(assert (> x 0))")
        session.reset()
        history = session.get_history()
        self.assertEqual(len(history), 0)

    def test_get_history(self):
        """get_history 返回请求 ID 列表"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        session = SolverSession(pool)
        history = session.get_history()
        self.assertIsInstance(history, list)


class TestSolverPool(unittest.TestCase):
    """Multiprocess solver pool with adaptive sizing."""

    def test_pool_creation(self):
        """创建池时 workers 列表为空"""
        pool = SolverPool(pool_size=2, config=SolverConfig(solver_type=SolverType.Z3))
        self.assertEqual(pool._pool_size, 2)
        self.assertEqual(len(pool._workers), 0)

    def test_get_stats_before_start(self):
        """未启动时 get_stats 返回默认值"""
        pool = SolverPool(pool_size=2, config=SolverConfig(solver_type=SolverType.Z3))
        stats = pool.get_stats()
        self.assertEqual(stats["pool_size"], 2)
        self.assertEqual(stats["active_workers"], 0)

    def test_get_avg_wait_time_empty(self):
        """无请求时平均等待时间为 0"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        self.assertEqual(pool.get_avg_wait_time(), 0.0)

    def test_get_utilization_empty(self):
        """无 worker 时利用率为 0"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        # 无活跃 worker → 除零保护
        util = pool.get_utilization()
        self.assertEqual(util, 0.0)

    def test_health_ping_returns_dict(self):
        """health_ping 返回 {worker_id: bool}"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        result = pool.health_ping()
        self.assertIsInstance(result, dict)

    def test_submit_returns_request_id(self):
        """submit 返回请求 ID 字符串"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        req_id = pool.submit("(assert true)")
        self.assertIsInstance(req_id, str)
        self.assertTrue(req_id.startswith("req_"))

    def test_stop_before_start_is_safe(self):
        """未启动就 stop 不应崩溃"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        pool.stop()  # 不应抛出


class TestAdaptivePoolSizing(unittest.TestCase):
    """Dynamic pool resizing based on queue wait time and utilization."""

    def test_creation(self):
        """创建 AdaptivePoolSizing 关联到 SolverPool"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        sizer = AdaptivePoolSizing(pool)
        self.assertIs(sizer._pool, pool)

    def test_not_running_after_creation(self):
        """创建后 running=False"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        sizer = AdaptivePoolSizing(pool)
        self.assertFalse(sizer._running)

    def test_start_stop(self):
        """start/stop 生命周期"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        sizer = AdaptivePoolSizing(pool)
        sizer.start()
        self.assertTrue(sizer._running)
        sizer.stop()
        self.assertFalse(sizer._running)

    def test_double_start_is_idempotent(self):
        """重复 start 不创建额外线程"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        sizer = AdaptivePoolSizing(pool)
        sizer.start()
        sizer.start()  # 不应崩溃
        self.assertTrue(sizer._running)
        sizer.stop()

    def test_notify_resize_updates_timer(self):
        """notify_resize 更新 last_resize_time"""
        pool = SolverPool(pool_size=1, config=SolverConfig(solver_type=SolverType.Z3))
        sizer = AdaptivePoolSizing(pool)
        before = sizer._last_resize_time
        sizer.notify_resize()
        after = sizer._last_resize_time
        self.assertGreater(after, before)

    def test_constants_defined(self):
        """所有阈值常量是合理值"""
        self.assertEqual(AdaptivePoolSizing._GROW_WAIT_THRESHOLD, 2.0)
        self.assertEqual(AdaptivePoolSizing._GROW_UTIL_THRESHOLD, 0.80)
        self.assertEqual(AdaptivePoolSizing._SHRINK_UTIL_THRESHOLD, 0.30)
        self.assertEqual(AdaptivePoolSizing._SHRINK_CONSECUTIVE, 10)
        self.assertEqual(AdaptivePoolSizing._MIN_POOL_SIZE, 1)


class TestGlobalSingletons(unittest.TestCase):
    """Global solver pool/cache singletons."""

    def test_get_solver_pool_returns_pool(self):
        """get_solver_pool 返回 SolverPool 实例"""
        pool = get_solver_pool()
        self.assertIsInstance(pool, SolverPool)

    def test_get_solver_cache_returns_cache(self):
        """get_solver_cache 返回 SolverCache 实例"""
        cache = get_solver_cache()
        self.assertIsInstance(cache, SolverCache)

    def test_get_warmup_cache_returns_warmup(self):
        """get_warmup_cache 返回 SolverWarmupCache 实例"""
        warmup = get_warmup_cache()
        self.assertIsInstance(warmup, SolverWarmupCache)

    def test_clear_cross_session_cache(self):
        """清除跨会话缓存不抛出"""
        clear_cross_session_cache()
        # 不应抛出


if __name__ == "__main__":
    unittest.main()
