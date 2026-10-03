
import unittest
import sys
_MOD_DEBUG = False
import os
import importlib.util

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))


class TestTrendTracker(unittest.TestCase):
    """测试趋势追踪器"""

    def test_tracker_initialization(self):
        """测试追踪器初始化"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'trend_tracker.py')
        spec = importlib.util.spec_from_file_location('trend_tracker', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        tracker = module.TrendTracker()
        self.assertIsNotNone(tracker)

    def test_store_analysis_result(self):
        """测试存储分析结果"""
        module_path = os.path.join(os.path.dirname(__file__), '..', 'modules', 'trend_tracker.py')
        spec = importlib.util.spec_from_file_location('trend_tracker', module_path)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        tracker = module.TrendTracker()
        result = tracker.store_analysis_result(
            binary_path='/path/to/binary',
            binary_hash='test_hash_123',
            results={'vulnerabilities': []}
        )

        self.assertIsNotNone(result)
        self.assertTrue(len(result) > 0)



if __name__ == '__main__':
    unittest.main()


