import unittest
import sys
_MOD_DEBUG = False
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestDynamicStructProber(unittest.TestCase):
    """测试动态结构体探测器"""

    def test_prober_initialization(self):
        """测试探测器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'dynamic_struct_prober.py')
        spec = importlib.util.spec_from_file_location('dynamic_struct_prober', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        prober = module.DynamicStructProber('/path/to/binary')
        self.assertIsNotNone(prober)

    def test_probe_struct_layout(self):
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'dynamic_struct_prober.py')
        spec = importlib.util.spec_from_file_location('dynamic_struct_prober', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        prober = module.DynamicStructProber('/path/to/binary')
        result = prober.probe_struct_layout(max_struct_size=64)

        self.assertIsNotNone(result)



if __name__ == '__main__':
    unittest.main()
