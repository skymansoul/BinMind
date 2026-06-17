"""
插件化二进制文件格式解析器测试
"""

import unittest
import sys
import os
import importlib.util
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestBinaryFormatLoader(unittest.TestCase):
    """测试二进制格式加载器"""
    
    def test_loader_initialization(self):
        """测试加载器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'binary_format_loader.py')
        spec = importlib.util.spec_from_file_location('binary_format_loader', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        loader = module.BinaryFormatLoader()
        self.assertIsNotNone(loader)
    
    def test_detect_format_pe(self):
        """测试PE格式检测"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'binary_format_loader.py')
        spec = importlib.util.spec_from_file_location('binary_format_loader', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        loader = module.BinaryFormatLoader()
        
        with tempfile.NamedTemporaryFile(mode='wb', suffix='.exe', delete=False) as f:
            f.write(b'MZ\x90\x00' + bytes([0x00] * 100))
            temp_path = f.name
        
        try:
            result = loader.detect_format(temp_path)
            self.assertEqual(result, module.BinaryFormat.PE)
        finally:
            os.unlink(temp_path)


if __name__ == '__main__':
    unittest.main()