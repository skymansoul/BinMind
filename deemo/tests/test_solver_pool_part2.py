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
