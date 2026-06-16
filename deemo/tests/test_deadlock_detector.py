import unittest
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.deadlock_detector import (
    DeadlockDetector,
    LockType,
    LockOperation,
    DeadlockAnalysisResult,
    DeadlockDetectorAnalyzer
)


class TestDeadlockDetector(unittest.TestCase):
    """测试死锁检测器"""

    def setUp(self):
        """设置测试环境"""
        self.detector = DeadlockDetector()

    def test_add_lock_operation(self):
        """测试添加锁操作"""
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
        """测试从二进制信息分析"""
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


class TestDeadlockDetectorAnalyzer(unittest.TestCase):
    """测试死锁检测器分析器（插件集成）"""

    def setUp(self):
        """设置测试环境"""
        self.analyzer = DeadlockDetectorAnalyzer()

    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        self.assertIsNotNone(self.analyzer.detector)

    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = DeadlockDetectorAnalyzer.get_metadata()
        self.assertEqual(metadata.name, "DeadlockDetector")
        self.assertIsNotNone(metadata.description)

    def test_validate_input_valid(self):
        """测试验证有效输入"""
        # 提供 binary_info
        is_valid, error = self.analyzer.validate_input(binary_info={})
        self.assertTrue(is_valid)
        self.assertIsNone(error)
        
        # 提供 decompilation_results
        is_valid, error = self.analyzer.validate_input(decompilation_results=[])
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_validate_input_invalid(self):
        """测试验证无效输入"""
        is_valid, error = self.analyzer.validate_input()
        self.assertFalse(is_valid)
        self.assertIn("必须提供", error)

    def test_analyze_with_binary_info(self):
        """测试使用二进制信息分析"""
        binary_info = {
            "decompilation_results": [{
                "function_name": "test_func",
                "pseudocode": "Lock(&mutex1); Lock(&mutex2);"
            }],
            "key_strings": ["mutex1", "mutex2"]
        }
        
        result = self.analyzer.analyze(binary_info=binary_info)
        self.assertTrue(result["success"])
        self.assertIn("result", result)
        self.assertIn("summary", result)

    def test_analyze_with_decompilation_results(self):
        """测试使用反编译结果分析"""
        decompilation_results = [{
            "function_name": "func1",
            "pseudocode": "pthread_mutex_lock(&lockA); pthread_mutex_lock(&lockB);"
        }, {
            "function_name": "func2",
            "pseudocode": "pthread_mutex_lock(&lockB); pthread_mutex_lock(&lockA);"
        }]
        
        result = self.analyzer.analyze(decompilation_results=decompilation_results)
        self.assertTrue(result["success"])
        self.assertGreater(result["result"]["potential_deadlocks"], 0)

    def test_analyze_empty(self):
        """测试空输入分析"""
        result = self.analyzer.analyze(binary_info={})
        self.assertTrue(result["success"])
        self.assertEqual(result["result"]["potential_deadlocks"], 0)

    def test_cleanup(self):
        """测试清理方法"""
        self.analyzer.cleanup()
        self.assertIsNone(self.analyzer.detector)


if __name__ == '__main__':
    unittest.main()