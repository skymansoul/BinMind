import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.pmc_side_channel import (
    PMCSideChannelEvaluator,
    ExploitabilityScore,
    PMCCounterType,
    evaluate_side_channel,
    measure_cache_timing
)


class TestPMCSideChannel(unittest.TestCase):
    """PMC侧信道评估模块测试"""
    
    def test_init_evaluator(self):
        """测试评估器初始化"""
        evaluator = PMCSideChannelEvaluator()
        self.assertIsNotNone(evaluator)
    
    def test_estimate_cache_access_time(self):
        """测试估算缓存访问时间"""
        evaluator = PMCSideChannelEvaluator()
        
        hit_time = evaluator._estimate_cache_access_time(0x1000, True)
        self.assertGreater(hit_time, 0)
        self.assertLess(hit_time, 10)
        
        miss_time = evaluator._estimate_cache_access_time(0x1000, False)
        self.assertGreater(miss_time, 50)
        self.assertLess(miss_time, 300)
    
    def test_calculate_std(self):
        """测试计算标准差"""
        evaluator = PMCSideChannelEvaluator()
        
        values = [1, 2, 3, 4, 5]
        std = evaluator._calculate_std(values)
        self.assertGreater(std, 0)
        
        # 相同值的标准差应为0
        same_values = [5, 5, 5, 5]
        std = evaluator._calculate_std(same_values)
        self.assertEqual(std, 0)
    
    def test_calculate_signal_strength(self):
        """测试计算信号强度"""
        evaluator = PMCSideChannelEvaluator()
        result = type('obj', (), {'statistics': {'difference_ps': 100000}})
        
        strength = evaluator._calculate_signal_strength(result)
        self.assertGreater(strength, 0)
        self.assertLessEqual(strength, 1.0)
    
    def test_determine_exploitability(self):
        """测试确定可利用性"""
        evaluator = PMCSideChannelEvaluator()
        
        result1 = type('obj', (), {'signal_detected': False})
        self.assertEqual(evaluator._determine_exploitability(result1), ExploitabilityScore.NONE)
        
        result2 = type('obj', (), {'signal_detected': True, 'signal_strength': 0.6})
        self.assertEqual(evaluator._determine_exploitability(result2), ExploitabilityScore.HIGH)
        
        result3 = type('obj', (), {'signal_detected': True, 'signal_strength': 0.3})
        self.assertEqual(evaluator._determine_exploitability(result3), ExploitabilityScore.MEDIUM)
        
        result4 = type('obj', (), {'signal_detected': True, 'signal_strength': 0.1})
        self.assertEqual(evaluator._determine_exploitability(result4), ExploitabilityScore.LOW)
    
    def test_measure_cache_timing(self):
        """测试测量缓存时序"""
        evaluator = PMCSideChannelEvaluator()
        result = evaluator.measure_cache_timing([0x1000, 0x2000], iterations=10)
        
        self.assertIsNotNone(result)
        self.assertTrue(len(result.measurements) > 0)
    
    def test_generate_report(self):
        """测试生成报告"""
        evaluator = PMCSideChannelEvaluator()
        result = type('obj', (), {
            'signal_detected': True,
            'signal_strength': 0.7,
            'exploitability': ExploitabilityScore.HIGH,
            'statistics': {'avg_hit_time_ps': 1000, 'avg_miss_time_ps': 100000},
            'notes': ['test note']
        })
        
        report = evaluator.generate_report(result)
        self.assertIsNotNone(report)
        self.assertIn("侧信道", report)


if __name__ == '__main__':
    unittest.main()
