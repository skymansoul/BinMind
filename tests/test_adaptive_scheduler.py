"""
adaptive_scheduler 模块测试 —— MAB 驱动的自适应方法调度。

实际 API:
  - AdaptiveScheduler 类: select_methods(features), update(method, reward), stats, epsilon
  - AnalysisMethod 枚举: STATIC_RULES, SYMBOLIC, FUZZING, LLM_DECOMP, LLM_CRASH, ROP_CHAIN, FORMAT_STRING
  - compute_reward(vulns_found, exploit_success, false_positives, elapsed_sec) -> float
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.adaptive_scheduler import (
    AdaptiveScheduler,
    AnalysisMethod,
    compute_reward,
)


class TestAnalysisMethod(unittest.TestCase):

    def test_enum_values(self):
        methods = [m.value for m in AnalysisMethod]
        self.assertIn('static_rules', methods)
        self.assertIn('symbolic', methods)
        self.assertIn('fuzzing', methods)
        self.assertIn('llm_decomp', methods)
        self.assertIn('llm_crash', methods)

    def test_enum_count(self):
        methods = list(AnalysisMethod)
        self.assertGreaterEqual(len(methods), 5)


class TestAdaptiveScheduler(unittest.TestCase):

    def setUp(self):
        self.scheduler = AdaptiveScheduler()

    def test_init(self):
        self.assertIsNotNone(self.scheduler)

    def test_epsilon_default(self):
        self.assertIsInstance(self.scheduler.epsilon, float)

    def test_select_methods_returns_list(self):
        features = {'nx': True, 'pie': False, 'canary': False}
        result = self.scheduler.select_methods(features)
        self.assertIsInstance(result, list)

    def test_select_empty_features(self):
        result = self.scheduler.select_methods({})
        self.assertIsInstance(result, list)
        self.assertGreater(len(result), 0)

    def test_select_with_full_protections(self):
        features = {'nx': True, 'pie': True, 'canary': True, 'relro': 'full'}
        result = self.scheduler.select_methods(features)
        self.assertIsInstance(result, list)

    def test_select_without_protections(self):
        features = {'nx': False, 'pie': False, 'canary': False, 'relro': 'none'}
        result = self.scheduler.select_methods(features)
        self.assertIsInstance(result, list)

    def test_update_method(self):
        """update 方法接受 AnalysisMethod 和 float。"""
        self.scheduler.update(AnalysisMethod.STATIC_RULES, 0.8)
        self.scheduler.update(AnalysisMethod.SYMBOLIC, 0.3)

    def test_stats(self):
        """stats 方法返回可读的统计信息。"""
        self.scheduler.update(AnalysisMethod.STATIC_RULES, 0.9)
        stats = self.scheduler.stats()
        self.assertIsInstance(stats, dict)

    def test_consistency_same_input(self):
        features = {'nx': True, 'pie': False, 'canary': False}
        for _ in range(3):
            result = self.scheduler.select_methods(features)
            self.assertIsInstance(result, list)


class TestComputeReward(unittest.TestCase):

    def test_successful_exploit(self):
        reward = compute_reward(
            vulns_found=2, exploit_success=True,
            false_positives=0, elapsed_sec=60.0,
        )
        self.assertGreater(reward, 0)

    def test_no_vulns(self):
        reward = compute_reward(
            vulns_found=0, exploit_success=False,
            false_positives=0, elapsed_sec=60.0,
        )
        self.assertIsInstance(reward, float)

    def test_many_false_positives_penalty(self):
        reward_good = compute_reward(2, True, 0, 60.0)
        reward_bad = compute_reward(2, True, 5, 60.0)
        self.assertGreaterEqual(reward_good, reward_bad)

    def test_faster_is_better(self):
        reward_fast = compute_reward(3, True, 0, 10.0)
        reward_slow = compute_reward(3, True, 0, 300.0)
        self.assertGreaterEqual(reward_fast, reward_slow)


if __name__ == '__main__':
    unittest.main()
