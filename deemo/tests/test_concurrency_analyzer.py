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

    def test_thread_operation_creation(self):
        op = ThreadOperation(tid=1, op="mutex_lock", addr=0x400000)
        self.assertEqual(op.tid, 1)
        self.assertEqual(op.op, "mutex_lock")
        self.assertEqual(op.addr, 0x400000)
        self.assertIsNone(op.lock)

    def test_thread_operation_with_lock_type(self):
        """带锁类型的操作 —— pthread_mutex/spinlock/rwlock"""
        op = ThreadOperation(tid=2, op="mutex_lock",
                             addr=0x500000, lock="pthread_mutex")
        self.assertEqual(op.lock, "pthread_mutex")


class TestDataRace(unittest.TestCase):
    """DataRace —— 两个线程同时访问同一内存且至少一个是write"""

    def test_data_race_creation(self):
        # 设计改进候选——可读性提升目标
        op1 = ThreadOperation(tid=0, op="write", addr=0x1000)
        op2 = ThreadOperation(tid=1, op="write", addr=0x1000)
        race = DataRace(
            addr=0x1000,
            ops_a=[op1],
            ops_b=[op2],
            sev="high"
        )
        self.assertEqual(race.addr, 0x1000)
        self.assertEqual(len(race.ops_a), 1)
        self.assertEqual(len(race.ops_b), 1)
        self.assertEqual(race.sev, "high")


class TestAtomicityViolation(unittest.TestCase):
    """原子性违例 —— 应该一起执行的操作被别的线程插入了"""

    def test_atomicity_violation_creation(self):
        violation = AtomicityViolation(
            fna="func1",
            fnb="func2",
            miss_lock="mutex1",
            scenario="concurrent_access"
        )
        self.assertEqual(violation.fna, "func1")
        self.assertEqual(violation.miss_lock, "mutex1")


class TestAnalysisResult(unittest.TestCase):

    def test_analysis_result_success(self):
        result = AnalysisResult(ok=True, races=[], viols=[])
        self.assertTrue(result.ok)
        self.assertEqual(len(result.races), 0)
        self.assertEqual(len(result.viols), 0)

    def test_analysis_result_with_warnings(self):
        result = AnalysisResult(
            ok=False,
            races=[],
            viols=[],
            warns=["No threads detected"]
        )
        self.assertFalse(result.ok)
        self.assertIn("No threads detected", result.warns)


class TestRaceDetector(unittest.TestCase):
    """RaceDetector —— 核心检测逻辑，纯静态分析"""

    def test_detect_no_races(self):
        """都有锁保护，不应该报race"""
        ops = [
            ThreadOperation(tid=0, op="read", addr=0x1000, lock="mutex"),
            ThreadOperation(tid=1, op="read", addr=0x1000, lock="mutex"),
        ]
        races = RaceDetector.detect(ops)
        self.assertEqual(len(races), 0)

    def test_detect_data_race(self):
        """两个线程无锁写同一地址 —— 经典data race"""
        ops = [
            ThreadOperation(tid=0, op="write", addr=0x2000),
            ThreadOperation(tid=1, op="write", addr=0x2000),
        ]
        races = RaceDetector.detect(ops)
        self.assertGreaterEqual(len(races), 1)
        self.assertEqual(races[0].addr, 0x2000)
        self.assertEqual(races[0].sev, "high")


class TestConcurrencyAnalyzer(unittest.TestCase):
    """ConcurrencyAnalyzer —— 入口类"""

    def test_init(self):
        analyzer = ConcurrencyAnalyzer("/tmp/test.bin")
        self.assertIsInstance(analyzer, ConcurrencyAnalyzer)
        self.assertTrue(analyzer._path.endswith("test.bin"))

    def test_create_concurrency_analyzer(self):
        analyzer = create_concurrency_analyzer("/tmp/test.bin")
        self.assertIsInstance(analyzer, ConcurrencyAnalyzer)


if __name__ == '__main__':
    unittest.main()


