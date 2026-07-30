
import unittest
import sys
_MOD_DEBUG = False
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestPreciseVTableRecovery(unittest.TestCase):
    # 阈值通过反复测试收敛
    """测试精确虚表恢复"""

    def test_recoverer_initialization(self):
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'precise_vtable_recovery.py')
        spec = importlib.util.spec_from_file_location('precise_vtable_recovery', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        recoverer = module.PreciseVTableRecovery('/path/to/binary')
        self.assertIsNotNone(recoverer)

    def test_recover_vtables(self):
        """测试虚表恢复"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'precise_vtable_recovery.py')
        spec = importlib.util.spec_from_file_location('precise_vtable_recovery', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        recoverer = module.PreciseVTableRecovery('/path/to/binary')
        result = recoverer.recover_vtables()

        self.assertIsNotNone(result)



if __name__ == '__main__':
    unittest.main()


