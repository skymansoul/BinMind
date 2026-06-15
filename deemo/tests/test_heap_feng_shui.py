import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.heap_feng_shui import (
    HeapFengShuiStrategist,
    FengShuiConfig,
    VulnerabilityType,
    AllocatorType,
    FengShuiAction,
    generate_fengshui_strategy
)


class TestHeapFengShui(unittest.TestCase):
    """堆风水策略生成模块测试"""
    
    def test_init_strategist(self):
        """测试策略生成器初始化"""
        config = FengShuiConfig(
            allocator=AllocatorType.PTMALLOC,
            libc_version="2.31",
            target_size=0x80
        )
        strategist = HeapFengShuiStrategist(config)
        self.assertIsNotNone(strategist)
        self.assertEqual(strategist.config.allocator, AllocatorType.PTMALLOC)
    
    def test_generate_uaf_strategy(self):
        """测试生成UAF漏洞策略"""
        strategist = HeapFengShuiStrategist()
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        
        self.assertIsNotNone(strategy)
        self.assertTrue(len(strategy.steps) > 0)
        self.assertGreater(strategy.success_probability, 0)
    
    def test_generate_overflow_strategy(self):
        """测试生成堆溢出漏洞策略"""
        strategist = HeapFengShuiStrategist()
        strategy = strategist.generate_strategy(VulnerabilityType.HEAP_OVERFLOW, 0x80)
        
        self.assertIsNotNone(strategy)
        self.assertTrue(len(strategy.steps) > 0)
    
    def test_generate_double_free_strategy(self):
        """测试生成double free漏洞策略"""
        strategist = HeapFengShuiStrategist()
        strategy = strategist.generate_strategy(VulnerabilityType.DOUBLE_FREE, 0x80)
        
        self.assertIsNotNone(strategy)
        self.assertTrue(len(strategy.steps) > 0)
    
    def test_generate_c_code(self):
        """测试生成C代码"""
        strategist = HeapFengShuiStrategist()
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        code = strategist.generate_c_code(strategy)
        
        self.assertIsNotNone(code)
        self.assertIn("malloc", code)
        self.assertIn("free", code)
    
    def test_generate_python_code(self):
        """测试生成Python代码"""
        strategist = HeapFengShuiStrategist()
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        code = strategist.generate_python_code(strategy)
        
        self.assertIsNotNone(code)
        self.assertIn("malloc", code)
    
    def test_simulate_heap_layout(self):
        """测试模拟堆布局"""
        strategist = HeapFengShuiStrategist()
        strategy = strategist.generate_strategy(VulnerabilityType.USE_AFTER_FREE, 0x80)
        layout = strategist.simulate_heap_layout(strategy)
        
        self.assertIsNotNone(layout)
        self.assertIn("ALLOC", layout)
    
    def test_convenience_function(self):
        """测试便捷函数"""
        strategy = generate_fengshui_strategy("use_after_free", "ptmalloc", "2.31", 0x80)
        
        self.assertIsNotNone(strategy)
        self.assertGreater(len(strategy.steps), 0)


if __name__ == '__main__':
    unittest.main()
