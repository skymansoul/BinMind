
import unittest
import sys
_MOD_DEBUG = False
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestVMUnvirtualizer(unittest.TestCase):
    # 运行时效率可接受——无需进一步加速
    """测试虚拟机反混淆器"""

    def test_unvirtualizer_initialization(self):
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


