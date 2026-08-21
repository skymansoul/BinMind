"""
动态污点分析测试 — Part 2: FridaTaintTracker.

测试 Frida 后端的污点追踪器初始化、脚手架生成、自定义源/汇、兼容格式.
"""
import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.test_dynamic_taint_helpers import create_mock_frida, create_mock_qbdi


class TestFridaTaintTracker(unittest.TestCase):
    """测试 FridaTaintTracker 类"""

    def setUp(self):
        for mod in ['modules.dynamic_taint', 'frida']:
            if mod in sys.modules:
                del sys.modules[mod]

    def test_initialize_frida_tracker(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker
            tracker = FridaTaintTracker('/fake/binary')
            self.assertEqual(tracker.binary_path, '/fake/binary')
            self.assertIsNotNone(tracker.taint_sources)
            self.assertIsNotNone(tracker.taint_sinks)
            self.assertIsNone(tracker.session)
            self.assertIsNone(tracker.script)

    def test_default_taint_sources_configured(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker
            tracker = FridaTaintTracker('/fake/binary')
            self.assertGreater(len(tracker.taint_sources), 0)
            source_names = [s.name for s in tracker.taint_sources]
            self.assertIn('read', source_names)
            self.assertIn('recv', source_names)
            self.assertIn('scanf', source_names)
            self.assertIn('getenv', source_names)

    def test_default_taint_sinks_configured(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker
            tracker = FridaTaintTracker('/fake/binary')
            self.assertGreater(len(tracker.taint_sinks), 0)
            sink_names = [s.name for s in tracker.taint_sinks]
            self.assertIn('system', sink_names)
            self.assertIn('execve', sink_names)
            self.assertIn('printf', sink_names)
            self.assertIn('strcpy', sink_names)
            self.assertIn('memcpy', sink_names)

    def test_generate_frida_script(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker
            tracker = FridaTaintTracker('/fake/binary')
            script = tracker.generate_frida_script()
            self.assertIsInstance(script, str)
            self.assertGreater(len(script), 0)
            self.assertIn('Interceptor.attach', script)
            self.assertIn('taintSources', script)
            self.assertIn('taintSinks', script)
            self.assertIn('taintFlows', script)
            self.assertIn('read', script)
            self.assertIn('system', script)

    def test_add_custom_taint_source(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import (
                FridaTaintTracker, DynamicTaintSource
            )
            tracker = FridaTaintTracker('/fake/binary')
            original_count = len(tracker.taint_sources)
            custom_source = DynamicTaintSource(
                name='custom_input', address=0x500000,
                type='custom', description='自定义输入源'
            )
            tracker.add_custom_taint_source(custom_source)
            self.assertEqual(len(tracker.taint_sources), original_count + 1)
            self.assertIn('custom_input', [s.name for s in tracker.taint_sources])

    def test_add_custom_taint_sink(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import (
                FridaTaintTracker, DynamicTaintSink
            )
            tracker = FridaTaintTracker('/fake/binary')
            original_count = len(tracker.taint_sinks)
            custom_sink = DynamicTaintSink(
                name='custom_dangerous', address=0x600000,
                type='custom', argument_positions=[0, 1],
                description='自定义危险函数'
            )
            tracker.add_custom_taint_sink(custom_sink)
            self.assertEqual(len(tracker.taint_sinks), original_count + 1)
            self.assertIn('custom_dangerous', [s.name for s in tracker.taint_sinks])

    def test_is_available_when_frida_not_installed(self):
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': None}):
            from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker
            tracker = FridaTaintTracker('/fake/binary')
            self.assertFalse(tracker.is_available())

    def test_is_available_when_binary_not_exists(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=False), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker
            tracker = FridaTaintTracker('/fake/binary')
            self.assertFalse(tracker.is_available())

    def test_to_compatible_format(self):
        mock_frida, _, _, _ = create_mock_frida()
        with patch('os.path.exists', return_value=True), \
             patch('os.path.isfile', return_value=True), \
             patch.dict('sys.modules', {'frida': mock_frida}):
            from modules.analysis.dynamic.dynamic_taint import (
                FridaTaintTracker, DynamicTaintSource, DynamicTaintSink,
                DynamicTaintFlow, DynamicVulnerability
            )
            tracker = FridaTaintTracker('/fake/binary')
            source = DynamicTaintSource(
                name='read', address=0x400000, type='input', description='标准输入'
            )
            sink = DynamicTaintSink(
                name='system', address=0x400200, type='system',
                argument_positions=[0], description='命令执行'
            )
            flow = DynamicTaintFlow(
                source=source, sink=sink, path=[0x400000, 0x400200],
                tainted_variables=['0x7fff0000'], confidence=0.9
            )
            tracker.taint_flows.append(flow)
            vuln = DynamicVulnerability(
                type='command_injection', function_name='system',
                address=0x400200, description='污点传播漏洞',
                severity='Critical', evidence=['test evidence'],
                tainted_variables=['0x7fff0000'], taint_flow=flow
            )
            tracker.vulnerabilities.append(vuln)
            compatible = tracker.to_compatible_format()
            self.assertIn('taint_flows', compatible)
            self.assertIn('vulnerabilities', compatible)
            self.assertIn('analysis_method', compatible)
            self.assertEqual(compatible['analysis_method'], 'FridaTaintTracker')
            self.assertEqual(len(compatible['taint_flows']), 1)
            self.assertEqual(len(compatible['vulnerabilities']), 1)
            flow_data = compatible['taint_flows'][0]
            self.assertIn('source', flow_data)
            self.assertIn('sink', flow_data)
            self.assertIn('path', flow_data)
            vuln_data = compatible['vulnerabilities'][0]
            self.assertIn('type', vuln_data)
            self.assertIn('severity', vuln_data)
            self.assertIn('address', vuln_data)


"""
动态污点分析测试 — Part 3: QBDI / 工厂函数 / 运行入口.

测试 QBDITaintTracker、create_dynamic_taint_tracker、run_dynamic_taint_analysis.
"""
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
