"""
反编译增强模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDecompilerEnhancer(unittest.TestCase):
    """测试反编译增强器"""
    
    def test_enhancer_initialization(self):
        """测试增强器初始化"""
        from modules.decompiler_enhancements import DecompilerEnhancer
        
        enhancer = DecompilerEnhancer()
        self.assertIsNotNone(enhancer)
    
    def test_enhance(self):
        """测试伪代码增强"""
        from modules.decompiler_enhancements import DecompilerEnhancer
        
        enhancer = DecompilerEnhancer()
        result = enhancer.enhance('int add(int a, int b) { return a + b; }')
        
        self.assertTrue(result.analysis_success)


if __name__ == '__main__':
    unittest.main()
