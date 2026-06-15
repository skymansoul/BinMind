#!/usr/bin/env python3
"""
并发模糊测试器单元测试

测试 ConcurrencyFuzzer 类的各项功能
"""
import unittest
import os
import tempfile
import json
from unittest.mock import Mock, patch, MagicMock

# 添加项目根目录到路径
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

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


class TestRaceType(unittest.TestCase):
    """测试竞争类型枚举"""
    
    def test_race_type_values(self):
        """测试枚举值"""
        self.assertEqual(RaceType.DATA_RACE.value, 'data_race')
        self.assertEqual(RaceType.DEADLOCK.value, 'deadlock')
        self.assertEqual(RaceType.LIVELOCK.value, 'livelock')
    
    def test_race_type_from_string(self):
        """测试字符串转换"""
        self.assertEqual(RaceType('data_race'), RaceType.DATA_RACE)
        self.assertEqual(RaceType('deadlock'), RaceType.DEADLOCK)


class TestThreadSchedule(unittest.TestCase):
    """测试线程调度数据类"""
    
    def test_schedule_creation(self):
        """测试创建线程调度"""
        schedule = ThreadSchedule(
            thread_id=1,
            sync_point='pthread_mutex_lock',
            action='delay',
            delay_ms=100,
            order=1
        )
        self.assertEqual(schedule.thread_id, 1)
        self.assertEqual(schedule.sync_point, 'pthread_mutex_lock')
        self.assertEqual(schedule.delay_ms, 100)
    
    def test_schedule_actions(self):
        """测试调度动作"""
        schedule = ThreadSchedule(
            thread_id=2, sync_point='pthread_cond_wait',
            action='force_order', delay_ms=0, order=2
        )
        self.assertEqual(schedule.action, 'force_order')


class TestRaceCondition(unittest.TestCase):
    """测试竞争条件数据类"""
    
    def test_race_condition_creation(self):
        """测试创建竞争条件"""
        race = RaceCondition(
            race_type=RaceType.DATA_RACE,
            location='0x1000',
            shared_variable='global_counter',
            thread1_access='read',
            thread2_access='write',
            sync_missing='mutex',
            severity='high',
            description='Unsynchronized access to global counter'
        )
        self.assertEqual(race.race_type, RaceType.DATA_RACE)
        self.assertEqual(race.shared_variable, 'global_counter')
        self.assertEqual(race.severity, 'high')


class TestConcurrencyFuzzResult(unittest.TestCase):
    """测试并发模糊测试结果数据类"""
    
    def test_result_creation(self):
        """测试创建测试结果"""
        race = RaceCondition(
            race_type=RaceType.DATA_RACE, location='0x1000',
            shared_variable='counter', thread1_access='read',
            thread2_access='write', sync_missing='mutex',
            severity='high', description='test'
        )
        schedule = ThreadSchedule(
            thread_id=1, sync_point='lock', action='delay',
            delay_ms=100, order=1
        )
        
        result = ConcurrencyFuzzResult(
            binary_path='/tmp/test',
            total_iterations=100,
            successful_reproductions=5,
            reproduction_rate=0.05,
            detected_races=[race],
            schedules_tested=[schedule],
            best_schedule=schedule,
            error=None
        )
        self.assertEqual(result.total_iterations, 100)
        self.assertEqual(result.reproduction_rate, 0.05)


class TestConcurrencyFuzzer(unittest.TestCase):
    """测试并发模糊测试器"""
    
    def setUp(self):
        """设置测试环境"""
        self.fuzzer = ConcurrencyFuzzer()
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """清理测试环境"""
        import shutil
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_generate_schedule(self):
        """测试生成调度策略"""
        sync_points = ['pthread_mutex_lock', 'pthread_mutex_unlock']
        
        schedule = self.fuzzer._generate_schedule(sync_points, num_threads=2)
        
        self.assertIsInstance(schedule, list)
        self.assertTrue(len(schedule) > 0)
    
    def test_generate_delay_schedule(self):
        """测试生成延迟调度"""
        schedule = self.fuzzer._generate_delay_schedule(
            thread_id=1, sync_point='pthread_mutex_lock', delay_range=(10, 100)
        )
        
        self.assertIsInstance(schedule, ThreadSchedule)
        self.assertEqual(schedule.action, 'delay')
        self.assertTrue(10 <= schedule.delay_ms <= 100)
    
    def test_generate_order_schedule(self):
        """测试生成顺序调度"""
        schedule = self.fuzzer._generate_order_schedule(
            thread_id=1, sync_point='pthread_cond_wait', order=2
        )
        
        self.assertEqual(schedule.action, 'force_order')
        self.assertEqual(schedule.order, 2)
    
    def test_detect_race_from_output(self):
        """测试从输出检测竞争"""
        # 模拟崩溃输出
        output = 'Segmentation fault at 0x1000\nThread 1: read global_counter\nThread 2: write global_counter'
        
        races = self.fuzzer._detect_race_from_output(output)
        
        self.assertIsInstance(races, list)
    
    def test_generate_ldpreload_hook(self):
        """测试生成LD_PRELOAD钩子"""
        schedules = [
            ThreadSchedule(thread_id=1, sync_point='pthread_mutex_lock',
                          action='delay', delay_ms=50, order=1)
        ]
        
        hook_code = self.fuzzer._generate_ldpreload_hook(schedules)
        
        self.assertIn('pthread_mutex_lock', hook_code)
        self.assertIn('delay', hook_code.lower() or 'usleep' in hook_code)
    
    def test_generate_rr_script(self):
        """测试生成rr脚本"""
        schedules = [
            ThreadSchedule(thread_id=1, sync_point='pthread_mutex_lock',
                          action='force_order', delay_ms=0, order=1)
        ]
        
        script = self.fuzzer._generate_rr_script('/tmp/test', schedules)
        
        self.assertIn('rr', script)
    
    def test_calculate_reproduction_rate(self):
        """测试计算复现率"""
        rate = self.fuzzer._calculate_reproduction_rate(
            total=100, successful=5
        )
        self.assertEqual(rate, 0.05)
    
    def test_prioritize_sync_points(self):
        """测试优先级排序同步点"""
        sync_points = ['pthread_mutex_lock', 'pthread_cond_wait', 'pthread_join']
        
        prioritized = self.fuzzer._prioritize_sync_points(sync_points)
        
        # mutex操作应该优先
        self.assertTrue(any('mutex' in p for p in prioritized[:2]))
    
    def test_fuzz_nonexistent_binary(self):
        """测试模糊不存在二进制"""
        result = self.fuzzer.fuzz('/nonexistent/binary', iterations=10)
        self.assertIn('error', result)
    
    def test_save_results(self):
        """测试保存结果"""
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
    """测试同步函数列表"""
    
    def test_sync_functions_exist(self):
        """测试同步函数列表存在"""
        self.assertIn('pthread_mutex_lock', SYNC_FUNCTIONS)
        self.assertIn('pthread_mutex_unlock', SYNC_FUNCTIONS)
        self.assertIn('pthread_cond_wait', SYNC_FUNCTIONS)
    
    def test_sync_functions_categories(self):
        """测试同步函数分类"""
        mutex_funcs = [f for f in SYNC_FUNCTIONS if 'mutex' in f]
        self.assertTrue(len(mutex_funcs) > 0)


class TestRacePatterns(unittest.TestCase):
    """测试竞争模式"""
    
    def test_race_patterns_exist(self):
        """测试竞争模式存在"""
        self.assertIn('data_race', RACE_PATTERNS)
        self.assertIn('deadlock', RACE_PATTERNS)
    
    def test_race_pattern_indicators(self):
        """测试竞争模式指示器"""
        data_race_pattern = RACE_PATTERNS['data_race']
        self.assertIn('indicators', data_race_pattern)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""
    
    def test_fuzz_concurrency_function(self):
        """测试fuzz_concurrency便捷函数"""
        temp_dir = tempfile.mkdtemp()
        test_binary = os.path.join(temp_dir, 'test')
        with open(test_binary, 'wb') as f:
            f.write(b'\x7fELF' + b'\x00' * 100)
        
        result = fuzz_concurrency(test_binary, iterations=5)
        self.assertIsInstance(result, dict)
        
        import shutil
        shutil.rmtree(temp_dir)


class TestInputValidation(unittest.TestCase):
    """测试输入校验"""
    
    def test_path_traversal_prevention(self):
        """测试路径遍历防护"""
        fuzzer = ConcurrencyFuzzer()
        
        result = fuzzer.fuzz('../../../etc/passwd', iterations=10)
        self.assertIn('error', result)
    
    def test_invalid_iterations(self):
        """测试无效迭代次数"""
        fuzzer = ConcurrencyFuzzer()
        
        temp_dir = tempfile.mkdtemp()
        test_binary = os.path.join(temp_dir, 'test')
        with open(test_binary, 'wb') as f:
            f.write(b'test')
        
        # 迭代次数应该有最小限制
        result = fuzzer.fuzz(test_binary, iterations=0)
        self.assertIsNotNone(result)
        
        import shutil
        shutil.rmtree(temp_dir)


class TestScheduleOptimization(unittest.TestCase):
    """测试调度优化"""
    
    def test_find_best_schedule(self):
        """测试寻找最佳调度"""
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
        self.assertEqual(best_idx, 1)  # 50ms延迟成功率最高


class TestRaceSeverity(unittest.TestCase):
    """测试竞争严重程度"""
    
    def test_high_severity_race(self):
        """测试高严重程度竞争"""
        race = RaceCondition(
            race_type=RaceType.DATA_RACE, location='critical_section',
            shared_variable='auth_flag', thread1_access='read',
            thread2_access='write', sync_missing='mutex',
            severity='critical', description='Authentication bypass possible'
        )
        self.assertEqual(race.severity, 'critical')
    
    def test_low_severity_race(self):
        """测试低严重程度竞争"""
        race = RaceCondition(
            race_type=RaceType.DATA_RACE, location='logging',
            shared_variable='log_counter', thread1_access='read',
            thread2_access='write', sync_missing='mutex',
            severity='low', description='Minor logging inconsistency'
        )
        self.assertEqual(race.severity, 'low')


if __name__ == '__main__':
    unittest.main()