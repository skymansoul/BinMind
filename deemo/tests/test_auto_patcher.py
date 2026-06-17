"""
自动补丁模块测试
"""

import unittest
import sys
import os
import tempfile
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestAutoPatcher(unittest.TestCase):
    """测试自动补丁器"""
    
    def test_patcher_initialization(self):
        """测试补丁器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'auto_patcher.py')
        spec = importlib.util.spec_from_file_location('auto_patcher', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(bytes([0x00] * 256))
            temp_path = f.name
        
        try:
            patcher = module.AutoPatcher(temp_path)
            self.assertIsNotNone(patcher)
        finally:
            os.unlink(temp_path)
    
    def test_analyze_and_patch(self):
        """测试分析与补丁"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'auto_patcher.py')
        spec = importlib.util.spec_from_file_location('auto_patcher', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.bin', delete=False) as f:
            f.write(bytes([0x00] * 256))
            temp_path = f.name
        
        try:
            patcher = module.AutoPatcher(temp_path)
            result = patcher.analyze_and_patch()
            
            self.assertTrue(result.analysis_success)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()
