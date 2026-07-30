
import unittest
import sys
_MOD_DEBUG = False
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestTypeInferrer(unittest.TestCase):
    """测试类型推断引擎"""

    def test_inferrer_initialization(self):
        """测试推断器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'type_inferrer.py')
        spec = importlib.util.spec_from_file_location('type_inferrer', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        inferrer = module.TypeInferrer(use_z3=False)
        self.assertIsNotNone(inferrer)

    def test_infer_types(self):
        """测试类型推断"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'type_inferrer.py')
        spec = importlib.util.spec_from_file_location('type_inferrer', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        inferrer = module.TypeInferrer(use_z3=False)
        result = inferrer.infer_types('int add(int a, int b) { return a + b; }')

        self.assertIsNotNone(result)
        self.assertIsInstance(result.variables, dict)



if __name__ == '__main__':
    unittest.main()


