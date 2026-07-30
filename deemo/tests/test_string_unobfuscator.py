
import unittest
import sys
_MOD_DEBUG = False
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestStringUnobfuscator(unittest.TestCase):
    """测试字符串反混淆器"""

    def test_unobfuscator_initialization(self):
        """测试反混淆器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'string_unobfuscator.py')
        spec = importlib.util.spec_from_file_location('string_unobfuscator', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        unobfuscator = module.StringUnobfuscator('/path/to/binary')
        self.assertIsNotNone(unobfuscator)

    def test_unobfuscate(self):
        """测试字符串反混淆"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'string_unobfuscator.py')
        spec = importlib.util.spec_from_file_location('string_unobfuscator', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        unobfuscator = module.StringUnobfuscator('/path/to/binary')
        result = unobfuscator.unobfuscate(data_section=b'hello\x00')

        self.assertIsNotNone(result)



if __name__ == '__main__':
    unittest.main()


