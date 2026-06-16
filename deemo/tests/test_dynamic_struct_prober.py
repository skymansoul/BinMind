"""
动态结构体探测模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDynamicStructProber(unittest.TestCase):
    """测试动态结构体探测器"""
    
    def test_prober_initialization(self):
        """测试探测器初始化"""
        from modules.dynamic_struct_prober import DynamicStructProber
        
        prober = DynamicStructProber('/path/to/binary')
        self.assertIsNotNone(prober)
    
    def test_probe_struct_layout(self):
        """测试结构体布局探测"""
        from modules.dynamic_struct_prober import DynamicStructProber
        
        prober = DynamicStructProber('/path/to/binary')
        result = prober.probe_struct_layout(max_struct_size=64)
        
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
