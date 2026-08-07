"""
动态污点分析测试 — Part 3: QBDI / 工厂函数 / 运行入口.

测试 QBDITaintTracker、create_dynamic_taint_tracker、run_dynamic_taint_analysis.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_dynamic_taint_helpers import create_mock_qbdi


class TestQBDITaintTracker(unittest.TestCase):
    """测试 QBDITaintTracker 类"""

    def setUp(self):
        for mod in ['modules.dynamic_taint', 'pyqbdi']:
            if mod in sys.modules:
                del sys.modules[mod]

    def test_initialize_qbdi_tracker(self):
        mock_qbdi = create_mock_qbdi()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'pyqbdi': mock_qbdi}):
            from modules.analysis.dynamic.dynamic_taint import QBDITaintTracker
            tracker = QBDITaintTracker('/fake/binary')
            self.assertEqual(tracker.binary_path, '/fake/binary')
            self.assertIsNotNone(tracker.taint_sources)
            self.assertIsNotNone(tracker.taint_sinks)
            self.assertIsNone(tracker.vm)
            self.assertIsNone(tracker.state)

    def test_default_taint_sources(self):
        mock_qbdi = create_mock_qbdi()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'pyqbdi': mock_qbdi}):
            from modules.analysis.dynamic.dynamic_taint import QBDITaintTracker
            tracker = QBDITaintTracker('/fake/binary')
            source_names = [s.name for s in tracker.taint_sources]
            self.assertIn('read', source_names)
            self.assertIn('recv', source_names)
            self.assertIn('gets', source_names)


class TestCreateDynamicTaintTracker(unittest.TestCase):
    """测试 create_dynamic_taint_tracker 函数"""

    def setUp(self):
        for mod in ['modules.dynamic_taint', 'frida', 'pyqbdi']:
            if mod in sys.modules:
                del sys.modules[mod]

    def test_create_frida_tracker(self):
        mock_frida = MagicMock()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida, 'pyqbdi': None}):
            from modules.analysis.dynamic.dynamic_taint import (
                create_dynamic_taint_tracker, FridaTaintTracker
            )
            tracker = create_dynamic_taint_tracker('/fake/binary', 'frida')
            self.assertIsInstance(tracker, FridaTaintTracker)

    def test_create_qbdi_tracker(self):
        mock_qbdi = MagicMock()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': None, 'pyqbdi': mock_qbdi}):
            from modules.analysis.dynamic.dynamic_taint import (
                create_dynamic_taint_tracker, QBDITaintTracker
            )
            tracker = create_dynamic_taint_tracker('/fake/binary', 'qbdi')
            self.assertIsInstance(tracker, QBDITaintTracker)

    def test_create_tracker_none_available(self):
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': None, 'pyqbdi': None}):
            from modules.analysis.dynamic.dynamic_taint import create_dynamic_taint_tracker
            tracker = create_dynamic_taint_tracker('/fake/binary', 'frida')
            self.assertIsNone(tracker)


class TestRunDynamicTaintAnalysis(unittest.TestCase):
    """测试 run_dynamic_taint_analysis 函数"""

    def setUp(self):
        for mod in ['modules.dynamic_taint', 'frida', 'pyqbdi']:
            if mod in sys.modules:
                del sys.modules[mod]

    def test_run_analysis_no_tracker_available(self):
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': None, 'pyqbdi': None}):
            from modules.analysis.dynamic.dynamic_taint import run_dynamic_taint_analysis
            result = run_dynamic_taint_analysis('/fake/binary', 'frida')
            self.assertFalse(result['success'])
            self.assertIn('error', result)
            self.assertEqual(result['engine'], 'frida')
            self.assertEqual(result['taint_marks'], [])
            self.assertEqual(result['taint_flows'], [])
            self.assertEqual(result['vulnerabilities'], [])


if __name__ == '__main__':
    unittest.main()
