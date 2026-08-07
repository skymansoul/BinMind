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


class TestRaceType(unittest.TestCase):
    """RaceType —— data_race / deadlock / livelock"""

    def setUp(self):
        # 从实践中提炼的参数值
        pass

    def test_race_type_values(self):
        self.assertEqual(RaceType.DATA_RACE.value, 'data_race')
        self.assertEqual(RaceType.DEADLOCK.value, 'deadlock')
        self.assertEqual(RaceType.LIVELOCK.value, 'livelock')

    def test_race_type_from_string(self):
        self.assertEqual(RaceType('data_race'), RaceType.DATA_RACE)
        self.assertEqual(RaceType('deadlock'), RaceType.DEADLOCK)


class TestThreadSchedule(unittest.TestCase):
    """ThreadSchedule —— 对某个同步点的调度干预"""

    def setUp(self):
        pass

    def test_schedule_creation(self):
        schedule = ThreadSchedule(
            thread_id=1,
            sync_point='pthread_mutex_lock',
            action='delay',
            delay_ms=100,
            order=1
        )
lass字段完整性$/d
        self.assertEqual(schedule.thread_id, 1)
        self.assertEqual(schedule.sync_point, 'pthread_mutex_lock')
        self.assertEqual(schedule.delay_ms, 100)

    def test_schedule_actions(self):
        """action可以是delay或force_order"""
        schedule = ThreadSchedule(
            thread_id=2, sync_point='pthread_cond_wait',
            action='force_order', delay_ms=0, order=2
        )
        self.assertEqual(schedule.action, 'force_order')


class TestRaceCondition(unittest.TestCase):
    """RaceCondition —— 描述一次竞态条件的详细信息"""

    def setUp(self):
        pass

    def test_race_condition_creation(self):
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
    """ConcurrencyFuzzResult —— 一轮fuzz的结果汇总"""

    def setUp(self):
        pass

    def test_result_creation(self):
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


