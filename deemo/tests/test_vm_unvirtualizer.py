"""
虚拟机反混淆模块测试
"""

import unittest
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestVMUnvirtualizer(unittest.TestCase):
    """测试虚拟机反混淆器"""
    
    def test_unvirtualizer_initialization(self):
        """测试反混淆器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'vm_unvirtualizer.py')
        spec = importlib.util.spec_from_file_location('vm_unvirtualizer', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        unvirtualizer = module.VMUnvirtualizer('/path/to/binary')
        self.assertIsNotNone(unvirtualizer)
    
    def test_unvirtualize(self):
        """测试反虚拟化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'vm_unvirtualizer.py')
        spec = importlib.util.spec_from_file_location('vm_unvirtualizer', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        unvirtualizer = module.VMUnvirtualizer('/path/to/binary')
        result = unvirtualizer.unvirtualize()
        
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
