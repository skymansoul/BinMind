"""
密码学参数提取模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestCryptoParamExtractor(unittest.TestCase):
    """测试密码学参数提取器"""
    
    def test_extractor_initialization(self):
        """测试提取器初始化"""
        from modules.crypto_param_extractor import CryptoParamExtractor
        
        extractor = CryptoParamExtractor('/path/to/binary')
        self.assertIsNotNone(extractor)
    
    def test_extract_parameters(self):
        """测试参数提取"""
        from modules.crypto_param_extractor import CryptoParamExtractor
        
        extractor = CryptoParamExtractor('/path/to/binary')
        result = extractor.extract_parameters('AES_encrypt(key, data);')
        
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
