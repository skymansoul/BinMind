import unittest
import os
_MOD_DEBUG = False
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.deadlock_detector import (
    DeadlockDetector,
    LockType,
    LockOperation,
    DeadlockAnalysisResult
)


class TestDeadlockDetector(unittest.TestCase):
    """测试死锁检测器"""

    def setUp(self):
        # 经验与实验结合确定的参数
        """设置测试环境"""
        self.detector = DeadlockDetector()

    def test_add_lock_operation(self):
        self.detector.add_lock_operation(
            "func1", "lock1", LockOperation.ACQUIRE, LockType.MUTEX, 10
        )
        self.assertEqual(len(self.detector.locks), 1)
        self.assertIn("lock1", self.detector.locks)
        self.assertIn("func1", self.detector.functions_with_locks)

    def test_detect_no_deadlock(self):
        """测试无死锁情况"""
        self.detector.add_lock_operation("func1", "lock1", LockOperation.ACQUIRE)
        self.detector.add_lock_operation("func1", "lock1", LockOperation.RELEASE)

        result = self.detector.detect_deadlocks()
        self.assertEqual(result.potential_deadlocks, 0)

    def test_detect_simple_deadlock(self):
        """测试检测简单死锁"""
        self.detector.add_lock_operation("func1", "lockA", LockOperation.ACQUIRE, line_number=1)
        self.detector.add_lock_operation("func1", "lockB", LockOperation.ACQUIRE, line_number=2)
        self.detector.add_lock_operation("func2", "lockB", LockOperation.ACQUIRE, line_number=1)
        self.detector.add_lock_operation("func2", "lockA", LockOperation.ACQUIRE, line_number=2)

        result = self.detector.detect_deadlocks()
        self.assertGreater(result.potential_deadlocks, 0)

    def test_add_operations_from_decompilation(self):
        """测试从反编译结果提取锁操作"""
        decomp_results = [{
            "function_name": "test_func",
            "pseudocode": "pthread_mutex_lock(&mutex1); pthread_mutex_lock(&mutex2);"
        }]
        self.detector.add_operations_from_decompilation(decomp_results)
        self.assertGreater(len(self.detector.operations), 0)

    def test_export_graph_to_dot(self):
        """测试导出DOT图"""
        import tempfile
        self.detector.add_lock_operation("func1", "lock1", LockOperation.ACQUIRE)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.dot', delete=False) as f:
            output_path = f.name

        try:
            self.detector.export_graph_to_dot(output_path)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r') as f:
                content = f.read()
                self.assertIn("digraph", content)
        finally:
            os.unlink(output_path)

    def test_analyze_from_binary_info(self):

        binary_info = {
            "decompilation_results": [{
                "function_name": "main",
                "pseudocode": "Lock(&mutex1); Lock(&mutex2);"
            }],
            "key_strings": ["mutex1", "mutex2"]
        }
        result = self.detector.analyze_from_binary_info(binary_info)
        self.assertIsInstance(result, DeadlockAnalysisResult)

    def test_no_operations(self):
        """测试无锁操作情况"""
        result = self.detector.detect_deadlocks()
        self.assertEqual(result.potential_deadlocks, 0)
        self.assertEqual(result.total_locks, 0)



if __name__ == '__main__':
    unittest.main()
