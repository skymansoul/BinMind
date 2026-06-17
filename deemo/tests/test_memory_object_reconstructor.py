"""
内存对象重构模块测试
"""

import unittest
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestMemoryObjectReconstructor(unittest.TestCase):
    """测试内存对象重构器"""
    
    def test_reconstructor_initialization(self):
        """测试重构器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'memory_object_reconstructor.py')
        spec = importlib.util.spec_from_file_location('memory_object_reconstructor', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        reconstructor = module.MemoryObjectReconstructor()
        self.assertIsNotNone(reconstructor)
    
    def test_reconstruct(self):
        """测试内存对象重构"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'memory_object_reconstructor.py')
        spec = importlib.util.spec_from_file_location('memory_object_reconstructor', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        reconstructor = module.MemoryObjectReconstructor()
        result = reconstructor.reconstruct(memory_data=bytes([0x00] * 256))
        
        self.assertTrue(result.analysis_success)


if __name__ == '__main__':
    unittest.main()
