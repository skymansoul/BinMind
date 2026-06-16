"""
类型推断引擎模块测试
"""

import unittest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestTypeInferrer(unittest.TestCase):
    """测试类型推断引擎"""
    
    def test_inferrer_initialization(self):
        """测试推断器初始化"""
        from modules.type_inferrer import TypeInferrer
        
        inferrer = TypeInferrer(use_z3=False)
        self.assertIsNotNone(inferrer)
    
    def test_infer_types(self):
        """测试类型推断"""
        from modules.type_inferrer import TypeInferrer
        
        inferrer = TypeInferrer(use_z3=False)
        result = inferrer.infer_types('int add(int a, int b) { return a + b; }')
        
        self.assertIsNotNone(result)
        self.assertIsInstance(result.variables, dict)


if __name__ == '__main__':
    unittest.main()
