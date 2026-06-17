"""
YARA规则自动生成模块测试
"""

import unittest
import sys
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestYaraAutoGenerator(unittest.TestCase):
    """测试YARA规则自动生成器"""
    
    def test_generator_initialization(self):
        """测试生成器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'yara_auto_gen.py')
        spec = importlib.util.spec_from_file_location('yara_auto_gen', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        generator = module.YaraAutoGenerator()
        self.assertIsNotNone(generator)
    
    def test_generate_rules(self):
        """测试规则生成"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'yara_auto_gen.py')
        spec = importlib.util.spec_from_file_location('yara_auto_gen', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        
        generator = module.YaraAutoGenerator()
        result = generator.generate_rules(sample_data=b'MZ\x90\x00' + bytes([0x00] * 100))
        
        self.assertTrue(result.analysis_success)


if __name__ == '__main__':
    unittest.main()
