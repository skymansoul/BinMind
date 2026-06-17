"""
反编译增强模块测试
"""

import unittest
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDecompilerEnhancer(unittest.TestCase):
    """测试反编译增强器"""
    
    def test_enhancer_initialization(self):
        """测试增强器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'decompiler_enhancements.py')
        spec = importlib.util.spec_from_file_location('decompiler_enhancements', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        enhancer = module.DecompilerEnhancer()
        self.assertIsNotNone(enhancer)
    
    def test_enhance(self):
        """测试伪代码增强"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'decompiler_enhancements.py')
        spec = importlib.util.spec_from_file_location('decompiler_enhancements', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        enhancer = module.DecompilerEnhancer()
        result = enhancer.enhance('int add(int a, int b) { return a + b; }')
        
        self.assertTrue(result.analysis_success)


if __name__ == '__main__':
    unittest.main()
