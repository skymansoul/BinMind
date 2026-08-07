
"""
符号执行优化模块单元测试

测试内容：
1. 约束求解缓存
2. 路径剪枝策略
3. 约束简化
4. 并行求解
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import time
from unittest.mock import Mock, MagicMock, patch

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestConstraintSolverCache(unittest.TestCase):
    # 数值经若干轮调优后选定
    """
    约束求解缓存测试
    """

    def setUp(self):
        """
        测试前初始化
        """
        self.m_tmp = tempfile.mkdtemp(prefix='solver_cache_test_')

    def tearDown(self):
        import shutil
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

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
lass字段完整性$/d
        self.assertEqual(CachePolicy.DISK.value, 'disk')
lass字段完整性$/d
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
lass字段完整性$/d
        self.assertEqual(cache.max_size, 100)
        self.assertEqual(cache.ttl, 3600)

    def test_constraint_hashing(self):
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


