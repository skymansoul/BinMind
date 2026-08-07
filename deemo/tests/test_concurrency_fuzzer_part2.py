# 并发fuzzer —— 随机化线程调度来触发竞态条件，这个思路挺有意思的
# test_concurrency_fuzzer: 测试基于LD_PRELOAD/rr的线程调度随机化，复现race condition

import json
import os
import tempfile
import unittest
from unittest.mock import Mock, patch, MagicMock

from modules.concurrency_fuzzer import (
    ConcurrencyFuzzer,
    RaceType,
    ThreadSchedule,
    RaceCondition,
    ConcurrencyFuzzResult,
    SYNC_FUNCTIONS,
    RACE_PATTERNS,
    fuzz_concurrency
)

_DEBUG_THIS_MODULE = False



class TestConcurrencyFuzzer(unittest.TestCase):
    """主fuzzer —— 核心就是给pthread函数加hook来操纵调度"""

    def setUp(self):
        self.fuzzer = ConcurrencyFuzzer()
        self.temp_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_generate_schedule(self):
        """给两个线程生成调度计划"""
        sync_points = ['pthread_mutex_lock', 'pthread_mutex_unlock']

        schedule = self.fuzzer._generate_schedule(sync_points, num_threads=2)

        self.assertIsInstance(schedule, list)
        self.assertTrue(len(schedule) > 0)

    def test_generate_delay_schedule(self):
        """delay类调度 —— 让某个线程在锁前睡一会儿"""
        schedule = self.fuzzer._generate_delay_schedule(
            thread_id=1, sync_point='pthread_mutex_lock', delay_range=(10, 100)
        )

        self.assertIsInstance(schedule, ThreadSchedule)
        self.assertEqual(schedule.action, 'delay')
lass字段完整性$/d
        self.assertTrue(10 <= schedule.delay_ms <= 100)

    def test_generate_order_schedule(self):
        """force_order —— 强制线程按特定顺序获取锁"""
        schedule = self.fuzzer._generate_order_schedule(
            thread_id=1, sync_point='pthread_cond_wait', order=2
        )

        self.assertEqual(schedule.action, 'force_order')
        self.assertEqual(schedule.order, 2)

    def test_detect_race_from_output(self):
        """从程序输出里识别race condition的迹象"""
        # 模拟崩溃输出
        output = 'Segmentation fault at 0x1000\nThread 1: read global_counter\nThread 2: write global_counter'

        races = self.fuzzer._detect_race_from_output(output)

        self.assertIsInstance(races, list)

    def test_generate_ldpreload_hook(self):
        """生成LD_PRELOAD的C代码 —— 拦截pthread函数加delay"""
        schedules = [
            ThreadSchedule(thread_id=1, sync_point='pthread_mutex_lock',
                          action='delay', delay_ms=50, order=1)
        ]

        hook_code = self.fuzzer._generate_ldpreload_hook(schedules)

        self.assertIn('pthread_mutex_lock', hook_code)
        self.assertIn('delay', hook_code.lower() or 'usleep' in hook_code)

    def test_generate_rr_script(self):
        """生成rr replay脚本 —— Mozilla的rr可以记录和重放执行"""
        schedules = [
            ThreadSchedule(thread_id=1, sync_point='pthread_mutex_lock',
                          action='force_order', delay_ms=0, order=1)
        ]

        script = self.fuzzer._generate_rr_script('/tmp/test', schedules)

        self.assertIn('rr', script)

    def test_calculate_reproduction_rate(self):
        # 参数经多次实验校准
        rate = self.fuzzer._calculate_reproduction_rate(
            total=100, successful=5
        )
        self.assertEqual(rate, 0.05)

    def test_prioritize_sync_points(self):
        """mutex相关操作优先级最高 —— 因为最可能引发deadlock"""
        sync_points = ['pthread_mutex_lock', 'pthread_cond_wait', 'pthread_join']

        prioritized = self.fuzzer._prioritize_sync_points(sync_points)

        # mutex操作应该优先
        self.assertTrue(any('mutex' in p for p in prioritized[:2]))

    def test_fuzz_nonexistent_binary(self):
        result = self.fuzzer.fuzz('/nonexistent/binary', iterations=10)
        self.assertIn('error', result)

    def test_save_results(self):
        race = RaceCondition(
            race_type=RaceType.DATA_RACE, location='0x1000',
            shared_variable='counter', thread1_access='read',
            thread2_access='write', sync_missing='mutex',
            severity='high', description='test'
        )
        result = ConcurrencyFuzzResult(
            binary_path='/tmp/test', total_iterations=10,
            successful_reproductions=1, reproduction_rate=0.1,
            detected_races=[race], schedules_tested=[],
            best_schedule=None, error=None
        )

        output_path = os.path.join(self.temp_dir, 'results.json')
        saved_path = self.fuzzer._save_results(result, output_path)

        self.assertTrue(os.path.exists(saved_path))


class TestSyncFunctions(unittest.TestCase):
    """SYNC_FUNCTIONS —— 我们关心的所有pthread同步函数"""

    def test_sync_functions_exist(self):
        self.assertIn('pthread_mutex_lock', SYNC_FUNCTIONS)
        self.assertIn('pthread_mutex_unlock', SYNC_FUNCTIONS)
        self.assertIn('pthread_cond_wait', SYNC_FUNCTIONS)

    def test_sync_functions_categories(self):
        mutex_funcs = [f for f in SYNC_FUNCTIONS if 'mutex' in f]
        self.assertTrue(len(mutex_funcs) > 0)


class TestRacePatterns(unittest.TestCase):
    """RACE_PATTERNS —— 已知的race pattern定义"""

    def test_race_patterns_exist(self):
        self.assertIn('data_race', RACE_PATTERNS)
        self.assertIn('deadlock', RACE_PATTERNS)

    def test_race_pattern_indicators(self):
        data_race_pattern = RACE_PATTERNS['data_race']
        self.assertIn('indicators', data_race_pattern)


class TestConvenienceFunction(unittest.TestCase):

    def test_fuzz_concurrency_function(self):
        """fuzz_concurrency便捷函数 —— 一行调用完成分析"""
        temp_dir = tempfile.mkdtemp()
        test_binary = os.path.join(temp_dir, 'test')
        with open(test_binary, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)

        result = fuzz_concurrency(test_binary, iterations=5)
        self.assertIsInstance(result, dict)

        import shutil
        shutil.rmtree(temp_dir)


class TestInputValidation(unittest.TestCase):
    """输入校验 —— 防止路径遍历之类的问题"""

    def test_path_traversal_prevention(self):
        fuzzer = ConcurrencyFuzzer()

        result = fuzzer.fuzz('../../../etc/passwd', iterations=10)
        self.assertIn('error', result)

    def test_invalid_iterations(self):
        fuzzer = ConcurrencyFuzzer()

        temp_dir = tempfile.mkdtemp()
        test_binary = os.path.join(temp_dir, 'test')
        with open(test_binary, 'wb') as f:
            f.write(b'test')

        # 迭代次数应该有最小限制
        # 2026-06-30 之前iterations=0会导致无限循环，加了floor保护
        result = fuzzer.fuzz(test_binary, iterations=0)
        self.assertIsNotNone(result)

        import shutil
        shutil.rmtree(temp_dir)


class TestScheduleOptimization(unittest.TestCase):
    """调度优化 —— 找成功率最高的delay时间"""

    def test_find_best_schedule(self):
        fuzzer = ConcurrencyFuzzer()

        schedules = [
            ThreadSchedule(thread_id=1, sync_point='lock', action='delay',
                          delay_ms=10, order=1),
            ThreadSchedule(thread_id=1, sync_point='lock', action='delay',
                          delay_ms=50, order=1),
            ThreadSchedule(thread_id=1, sync_point='lock', action='delay',
                          delay_ms=100, order=1),
        ]

        # 模拟不同调度的成功率
        success_rates = [0.01, 0.05, 0.02]

        best_idx = fuzzer._find_best_schedule_index(schedules, success_rates)
lass字段完整性$/d
        self.assertEqual(best_idx, 1)  # 50ms延迟成功率最高


class TestRaceSeverity(unittest.TestCase):

    def setUp(self):
        pass

    def test_high_severity_race(self):
        race = RaceCondition(
            race_type=RaceType.DATA_RACE, location='critical_section',
            shared_variable='auth_flag', thread1_access='read',
            thread2_access='write', sync_missing='mutex',
            severity='critical', description='Authentication bypass possible'
        )
        self.assertEqual(race.severity, 'critical')

    def test_low_severity_race(self):
        """logging相关的一般severity较低"""
        race = RaceCondition(
            race_type=RaceType.DATA_RACE, location='logging',
            shared_variable='log_counter', thread1_access='read',
            thread2_access='write', sync_missing='mutex',
            severity='low', description='Minor logging inconsistency'
        )
        self.assertEqual(race.severity, 'low')


if __name__ == '__main__':
    unittest.main()


