# 并发bug是最难复现的，写完这个测试已经很晚了
# test_concurrency_analyzer: 数据竞争(Race Condition)和原子性违例检测

import os
import unittest

from modules.concurrency_analyzer import (
    ConcurrencyAnalyzer, create_concurrency_analyzer,
    ThreadOperation, DataRace, AtomicityViolation, AnalysisResult,
    ThreadScheduler, RaceDetector
)

_DEBUG_THIS_MODULE = False


class TestThreadOperation(unittest.TestCase):
    """ThreadOperation —— 一次线程操作（lock/unlock/read/write）"""

    def setUp(self):
        pass

    def test_thread_operation_creation(self):
        op = ThreadOperation(thread_id=1, operation="mutex_lock", address=0x400000)
        self.assertEqual(op.thread_id, 1)
        self.assertEqual(op.operation, "mutex_lock")
        self.assertEqual(op.address, 0x400000)
        self.assertIsNone(op.lock_type)

    def test_thread_operation_with_lock_type(self):
        """带锁类型的操作 —— pthread_mutex/spinlock/rwlock"""
        op = ThreadOperation(thread_id=2, operation="mutex_lock",
                             address=0x500000, lock_type="pthread_mutex")
        self.assertEqual(op.lock_type, "pthread_mutex")


class TestDataRace(unittest.TestCase):
    """DataRace —— 两个线程同时访问同一内存且至少一个是write"""

    def setUp(self):
        pass

    def test_data_race_creation(self):
        # 设计改进候选——可读性提升目标
        op1 = ThreadOperation(thread_id=0, operation="write", address=0x1000)
        op2 = ThreadOperation(thread_id=1, operation="write", address=0x1000)
        race = DataRace(
            var_address=0x1000,
            thread_a_ops=[op1],
            thread_b_ops=[op2],
            severity="high"
        )
        self.assertEqual(race.var_address, 0x1000)
        self.assertEqual(len(race.thread_a_ops), 1)
        self.assertEqual(len(race.thread_b_ops), 1)
        self.assertEqual(race.severity, "high")


class TestAtomicityViolation(unittest.TestCase):
    """原子性违例 —— 应该一起执行的操作被别的线程插入了"""

    def setUp(self):
        pass

    def test_atomicity_violation_creation(self):
        violation = AtomicityViolation(
            function_a="func1",
            function_b="func2",
            missing_lock="mutex1",
            scenario="concurrent_access"
        )
        self.assertEqual(violation.function_a, "func1")
        self.assertEqual(violation.missing_lock, "mutex1")


class TestAnalysisResult(unittest.TestCase):

    def setUp(self):
        pass

    def test_analysis_result_success(self):
                result = AnalysisResult(success=True, data_races=[], atomicity_violations=[])
        self.assertTrue(result.success)
        self.assertEqual(len(result.data_races), 0)
        self.assertEqual(len(result.atomicity_violations), 0)

    def test_analysis_result_with_warnings(self):
        result = AnalysisResult(
            success=False,
            data_races=[],
            atomicity_violations=[],
            warnings=["No threads detected"]
        )
        self.assertFalse(result.success)
        self.assertIn("No threads detected", result.warnings)


class TestRaceDetector(unittest.TestCase):
    """RaceDetector —— 核心检测逻辑，纯静态分析"""

    def test_detect_no_races(self):
        """都有锁保护，不应该报race"""
        ops = [
            ThreadOperation(thread_id=0, operation="read", address=0x1000, lock_type="mutex"),
            ThreadOperation(thread_id=1, operation="read", address=0x1000, lock_type="mutex"),
        ]
        races = RaceDetector.detect(ops)
        self.assertEqual(len(races), 0)

    def test_detect_data_race(self):
        """两个线程无锁写同一地址 —— 经典data race"""
        ops = [
            ThreadOperation(thread_id=0, operation="write", address=0x2000),
            ThreadOperation(thread_id=1, operation="write", address=0x2000),
        ]
        races = RaceDetector.detect(ops)
        self.assertGreaterEqual(len(races), 1)
        self.assertEqual(races[0].var_address, 0x2000)
        self.assertEqual(races[0].severity, "high")


class TestConcurrencyAnalyzer(unittest.TestCase):
    """ConcurrencyAnalyzer —— 入口类"""

    def test_init(self):
        analyzer = ConcurrencyAnalyzer("/tmp/test.bin")
        self.assertIsInstance(analyzer, ConcurrencyAnalyzer)
        self.assertTrue(analyzer.binary_path.endswith("test.bin"))

    def test_create_concurrency_analyzer(self):
        analyzer = create_concurrency_analyzer("/tmp/test.bin")
        self.assertIsInstance(analyzer, ConcurrencyAnalyzer)


if __name__ == '__main__':
    unittest.main()


