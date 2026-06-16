"""
字符串反混淆模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestStringUnobfuscator(unittest.TestCase):
    """测试字符串反混淆器"""
    
    def test_unobfuscator_initialization(self):
        """测试反混淆器初始化"""
        from modules.string_unobfuscator import StringUnobfuscator
        
        unobfuscator = StringUnobfuscator('/path/to/binary')
        self.assertIsNotNone(unobfuscator)
    
    def test_unobfuscate(self):
        """测试字符串反混淆"""
        from modules.string_unobfuscator import StringUnobfuscator
        
        unobfuscator = StringUnobfuscator('/path/to/binary')
        result = unobfuscator.unobfuscate(data_section=b'hello\x00')
        
        self.assertIsNotNone(result)


if __name__ == '__main__':
    unittest.main()
