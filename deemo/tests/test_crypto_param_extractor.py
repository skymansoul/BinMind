"""
密码学参数提取模块测试
"""

import unittest
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestCryptoParamExtractor(unittest.TestCase):
    """测试密码学参数提取器"""
    
    def test_extractor_initialization(self):
        """测试提取器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'crypto_param_extractor.py')
        spec = importlib.util.spec_from_file_location('crypto_param_extractor', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        extractor = module.CryptoParamExtractor('/path/to/binary')
        self.assertIsNotNone(extractor)
    
    def test_extract_parameters(self):
        """测试参数提取"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'crypto_param_extractor.py')
        spec = importlib.util.spec_from_file_location('crypto_param_extractor', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        extractor = module.CryptoParamExtractor('/path/to/binary')
        result = extractor.extract_parameters('AES_encrypt(key, data);')
        
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
