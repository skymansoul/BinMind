#!/usr/bin/env python3
"""
符号执行优化模块单元测试

测试内容：
1. 约束求解缓存
2. 路径剪枝策略
3. 约束简化
4. 并行求解
"""

import os
import sys
import unittest
import tempfile
import time
from unittest.mock import Mock, MagicMock, patch

# 添加项目路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConstraintSolverCache(unittest.TestCase):
    """
    约束求解缓存测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.temp_dir = tempfile.mkdtemp(prefix='solver_cache_test_')
        
    def tearDown(self):
        """
        测试后清理
        """
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_symexec_optimizer_module_import(self):
        """
        测试符号执行优化模块导入
        """
        try:
            from modules.symexec_optimizer import ConstraintSolverCache, ANGR_AVAILABLE, Z3_AVAILABLE
            self.assertTrue(True)
        except ImportError as e:
            self.skipTest(f"符号执行优化模块导入失败: {e}")

    def test_cache_policy_enum(self):
        """
        测试缓存策略枚举
        """
        from modules.symexec_optimizer import CachePolicy
        
        self.assertEqual(CachePolicy.NONE.value, 'none')
        self.assertEqual(CachePolicy.MEMORY.value, 'memory')
        self.assertEqual(CachePolicy.DISK.value, 'disk')
        self.assertEqual(CachePolicy.HYBRID.value, 'hybrid')

    def test_pruning_strategy_enum(self):
        """
        测试剪枝策略枚举
        """
        from modules.symexec_optimizer import PruningStrategy
        
        self.assertEqual(PruningStrategy.NONE.value, 'none')
        self.assertEqual(PruningStrategy.LOOP_BOUND.value, 'loop_bound')
        self.assertEqual(PruningStrategy.SIMILAR_STATE.value, 'similar_state')
        self.assertEqual(PruningStrategy.ALL.value, 'all')

    def test_cache_initialization(self):
        """
        测试缓存初始化
        """
        from modules.symexec_optimizer import ConstraintSolverCache, CachePolicy
        
        cache = ConstraintSolverCache(
            cache_policy=CachePolicy.MEMORY,
            max_size=100,
            ttl=3600
        )
        
        self.assertEqual(cache.cache_policy, CachePolicy.MEMORY)
        self.assertEqual(cache.max_size, 100)
        self.assertEqual(cache.ttl, 3600)

    def test_constraint_hashing(self):
        """
        测试约束哈希计算
        """
        from modules.symexec_optimizer import ConstraintSolverCache
        
        cache = ConstraintSolverCache()
        
        # 相同约束应产生相同哈希
        constraints1 = ['x > 0', 'y < 10']
        constraints2 = ['x > 0', 'y < 10']
        
        hash1 = cache.hash_constraints(constraints1)
        hash2 = cache.hash_constraints(constraints2)
        
        self.assertEqual(hash1, hash2)
        
        # 不同约束应产生不同哈希
        constraints3 = ['x > 5', 'y < 10']
        hash3 = cache.hash_constraints(constraints3)
        
        self.assertNotEqual(hash1, hash3)

    def test_cache_put_and_get(self):
        """
        测试缓存存取
        """
        from modules.symexec_optimizer import ConstraintSolverCache
        
        cache = ConstraintSolverCache()
        
        constraints = ['x > 0']
        hash_val = cache.hash_constraints(constraints)
        
        # 存入缓存
        cache.put(
            hash_val,
            {'satisfiable': True},
            True,
            {'x': 1},
            0.5
        )
        
        # 从缓存获取
        entry = cache.get(hash_val)
        
        self.assertIsNotNone(entry)
        self.assertTrue(entry.is_satisfiable)
        self.assertEqual(entry.hit_count, 1)

    def test_cache_miss(self):
        """
        测试缓存未命中
        """
        from modules.symexec_optimizer import ConstraintSolverCache
        
        cache = ConstraintSolverCache()
        
        # 获取不存在的缓存
        entry = cache.get('nonexistent_hash')
        
        self.assertIsNone(entry)

    def test_cache_stats(self):
        """
        测试缓存统计
        """
        from modules.symexec_optimizer import ConstraintSolverCache
        
        cache = ConstraintSolverCache()
        
        # 存入一些数据
        for i in range(5):
            hash_val = cache.hash_constraints([f'x > {i}'])
            cache.put(hash_val, {'satisfiable': True}, True)
        
        # 获取统计
        stats = cache.get_stats()
        
        self.assertIn('memory_cache_size', stats)
        self.assertIn('puts', stats)
        self.assertEqual(stats['memory_cache_size'], 5)

    def test_cache_clear(self):
        """
        测试缓存清空
        """
        from modules.symexec_optimizer import ConstraintSolverCache
        
        cache = ConstraintSolverCache()
        
        # 存入数据
        hash_val = cache.hash_constraints(['x > 0'])
        cache.put(hash_val, {'satisfiable': True}, True)
        
        # 清空
        cache.clear()
        
        # 验证已清空
        stats = cache.get_stats()
        self.assertEqual(stats['memory_cache_size'], 0)


class TestPathPruner(unittest.TestCase):
    """
    路径剪枝器测试
    """

    def test_pruner_initialization(self):
        """
        测试剪枝器初始化
        """
        from modules.symexec_optimizer import PathPruner, PruningStrategy
        
        pruner = PathPruner(
            strategy=PruningStrategy.ALL,
            loop_bound=5,
            max_paths=1000
        )
        
        self.assertEqual(pruner.strategy, PruningStrategy.ALL)
        self.assertEqual(pruner.loop_bound, 5)
        self.assertEqual(pruner.max_paths, 1000)

    def test_loop_bound_pruning(self):
        """
        测试循环边界剪枝
        """
        from modules.symexec_optimizer import PathPruner, PathInfo, PruningStrategy
        
        pruner = PathPruner(strategy=PruningStrategy.LOOP_BOUND, loop_bound=3)
        
        # 创建超过循环边界的路径
        path = PathInfo(
            path_id='test_path',
            loop_counts={0x1000: 5}  # 循环5次，超过边界3
        )
        
        should_prune, reason = pruner.should_prune(path)
        
        self.assertTrue(should_prune)
        self.assertIn('loop_bound', reason)

    def test_no_pruning_strategy(self):
        """
        测试无剪枝策略
        """
        from modules.symexec_optimizer import PathPruner, PathInfo, PruningStrategy
        
        pruner = PathPruner(strategy=PruningStrategy.NONE)
        
        path = PathInfo(path_id='test_path')
        
        should_prune, reason = pruner.should_prune(path)
        
        self.assertFalse(should_prune)

    def test_path_registration(self):
        """
        测试路径注册
        """
        from modules.symexec_optimizer import PathPruner, PathInfo
        
        pruner = PathPruner()
        
        path = PathInfo(
            path_id='test_path',
            visited_addresses={0x1000, 0x1005, 0x1010}
        )
        
        pruner.register_path(path)
        
        self.assertIn('test_path', pruner.active_paths)
        self.assertTrue(0x1000 in pruner.coverage)

    def test_pruner_stats(self):
        """
        测试剪枝器统计
        """
        from modules.symexec_optimizer import PathPruner
        
        pruner = PathPruner()
        
        stats = pruner.get_stats()
        
        self.assertIsInstance(stats.total_paths_explored, int)


class TestConstraintSimplifier(unittest.TestCase):
    """
    约束简化器测试
    """

    def test_simplifier_initialization(self):
        """
        测试简化器初始化
        """
        from modules.symexec_optimizer import ConstraintSimplifier
        
        simplifier = ConstraintSimplifier()
        
        self.assertIsInstance(simplifier.simplify_stats, dict)

    def test_duplicate_removal(self):
        """
        测试重复约束消除
        """
        from modules.symexec_optimizer import ConstraintSimplifier
        
        simplifier = ConstraintSimplifier()
        
        constraints = ['x > 0', 'x > 0', 'y < 10', 'y < 10']
        
        unique = simplifier._remove_duplicates(constraints)
        
        self.assertEqual(len(unique), 2)

    def test_simplify_empty_constraints(self):
        """
        测试空约束简化
        """
        from modules.symexec_optimizer import ConstraintSimplifier
        
        simplifier = ConstraintSimplifier()
        
        result = simplifier.simplify([])
        
        self.assertEqual(result, [])


class TestSymExecOptimizer(unittest.TestCase):
    """
    符号执行优化器测试
    """

    def test_optimizer_initialization(self):
        """
        测试优化器初始化
        """
        from modules.symexec_optimizer import SymExecOptimizer
        
        optimizer = SymExecOptimizer()
        
        self.assertIsNotNone(optimizer.cache)
        self.assertIsNotNone(optimizer.pruner)
        self.assertIsNotNone(optimizer.simplifier)

    def test_optimizer_with_custom_config(self):
        """
        测试自定义配置优化器
        """
        from modules.symexec_optimizer import SymExecOptimizer, PruningStrategy
        
        config = {
            'loop_bound': 10,
            'max_paths': 500,
            'solver_timeout': 60
        }
        
        optimizer = SymExecOptimizer(config)
        
        self.assertEqual(optimizer.pruner.loop_bound, 10)
        self.assertEqual(optimizer.pruner.max_paths, 500)

    def test_optimization_stats(self):
        """
        测试优化统计
        """
        from modules.symexec_optimizer import SymExecOptimizer
        
        optimizer = SymExecOptimizer()
        
        stats = optimizer.get_optimization_stats()
        
        self.assertIn('cache', stats)
        self.assertIn('pruning', stats)
        self.assertIn('solver', stats)


if __name__ == '__main__':
    unittest.main(verbosity=2)