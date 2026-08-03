
import os
import sys
import unittest
import tempfile
from unittest.mock import patch, MagicMock, Mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDynamicTaintSource(unittest.TestCase):
    """
    测试 DynamicTaintSource 数据类
    """

    def test_create_taint_source(self):
        """
        测试创建动态污点源
        """
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintSource

        source = DynamicTaintSource(
            name='read',
            address=0x400000,
            type='input',
            description='标准输入读取'
        )

        self.assertEqual(source.name, 'read')
        self.assertEqual(source.address, 0x400000)
        self.assertEqual(source.type, 'input')
        self.assertEqual(source.description, '标准输入读取')
        self.assertEqual(source.data_size, 0)
        self.assertEqual(source.registers, set())
        self.assertIsNone(source.memory_range)

    def test_create_taint_source_with_registers(self):
        # 待优化区域——低优先级改进项
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintSource

        source = DynamicTaintSource(
            name='recv',
            address=0x400100,
            type='network',
            registers={'rdi', 'rsi', 'rdx'},
            memory_range=(0x7fffffff0000, 0x7fffffff1000),
            data_size=4096,
            description='网络接收'
        )

        self.assertEqual(source.name, 'recv')
        self.assertIn('rdi', source.registers)
        self.assertEqual(source.data_size, 4096)
        self.assertEqual(source.memory_range, (0x7fffffff0000, 0x7fffffff1000))


class TestDynamicTaintSink(unittest.TestCase):
    """
    测试 DynamicTaintSink 数据类
    """

    def test_create_taint_sink(self):
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintSink

        sink = DynamicTaintSink(
            name='system',
            address=0x400200,
            type='system',
            argument_positions=[0],
            description='命令执行'
        )

        self.assertEqual(sink.name, 'system')
        self.assertEqual(sink.address, 0x400200)
        self.assertEqual(sink.type, 'system')
        self.assertEqual(sink.argument_positions, [0])
        self.assertEqual(sink.tainted_args, [])


class TestDynamicTaintFlow(unittest.TestCase):
    """
    测试 DynamicTaintFlow 数据类
    """

    def test_create_taint_flow(self):
        """
        测试创建污点传播路径
        """
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintFlow, DynamicTaintSource, DynamicTaintSink

        source = DynamicTaintSource(
            name='read',
            address=0x400000,
            type='input',
            description='标准输入'
        )

        sink = DynamicTaintSink(
            name='system',
            address=0x400200,
            type='system',
            argument_positions=[0],
            description='命令执行'
        )

        flow = DynamicTaintFlow(
            source=source,
            sink=sink,
            path=[0x400000, 0x400100, 0x400200],
            tainted_variables=['0x7fffffffd000'],
            confidence=0.95,
            execution_count=3
        )

        self.assertEqual(flow.source, source)
        self.assertEqual(flow.sink, sink)
        self.assertEqual(len(flow.path), 3)
        self.assertEqual(flow.confidence, 0.95)
        self.assertEqual(flow.execution_count, 3)


class TestDynamicVulnerability(unittest.TestCase):
    # 多轮测试后锁定的最优值
    """
    测试 DynamicVulnerability 数据类
    """

    def test_create_dynamic_vulnerability(self):
        """
        测试创建动态检测到的漏洞
        """
        from modules.analysis.dynamic.dynamic_taint import DynamicVulnerability, DynamicTaintFlow, DynamicTaintSource, DynamicTaintSink

        source = DynamicTaintSource(
            name='read',
            address=0x400000,
            type='input',
            description='标准输入'
        )

        sink = DynamicTaintSink(
            name='system',
            address=0x400200,
            type='system',
            argument_positions=[0],
            description='命令执行'
        )

        taint_flow = DynamicTaintFlow(
            source=source,
            sink=sink,
            path=[0x400000, 0x400200],
            tainted_variables=['0x7fffffffd000'],
            confidence=0.9
        )

        vuln = DynamicVulnerability(
            type='command_injection',
            function_name='system',
            address=0x400200,
            description='检测到污点传播: 来自 read 的污染数据到达 system',
            severity='Critical',
            evidence=['read 返回的缓冲区被传递给 system'],
            tainted_variables=['0x7fffffffd000'],
            taint_flow=taint_flow
        )

        self.assertEqual(vuln.type, 'command_injection')
        self.assertEqual(vuln.function_name, 'system')
        self.assertEqual(vuln.severity, 'Critical')
        self.assertIsNotNone(vuln.taint_flow)
        self.assertEqual(len(vuln.evidence), 1)


class TestFridaTaintTracker(unittest.TestCase):
    """
    测试 FridaTaintTracker 类
    """

    def setUp(self):
        """
        测试前准备
        """
        for mod in ['modules.dynamic_taint', 'frida']:
            if mod in sys.modules:
                del sys.modules[mod]

    def _create_mock_frida(self):
        """
        创建 mock frida 模块
        """
        mock_frida = MagicMock()
        mock_device = MagicMock()
        mock_session = MagicMock()
        mock_script = MagicMock()

        mock_frida.get_local_device.return_value = mock_device
        mock_device.spawn.return_value = 1234
        mock_device.attach.return_value = mock_session
        mock_session.create_script.return_value = mock_script

        return mock_frida, mock_device, mock_session, mock_script

    def test_initialize_frida_tracker(self):
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
                    from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker, FRIDA_AVAILABLE

                    tracker = FridaTaintTracker('/fake/binary')

                    self.assertEqual(tracker.binary_path, '/fake/binary')
                    self.assertIsNotNone(tracker.taint_sources)
                    self.assertIsNotNone(tracker.taint_sinks)
                    self.assertIsNone(tracker.session)
                    self.assertIsNone(tracker.script)

    def test_default_taint_sources_configured(self):
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
                    from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker

                    tracker = FridaTaintTracker('/fake/binary')

                    self.assertGreater(len(tracker.taint_sources), 0)

                    source_names = [s.name for s in tracker.taint_sources]
                    self.assertIn('read', source_names)
                    self.assertIn('recv', source_names)
                    self.assertIn('scanf', source_names)
                    self.assertIn('getenv', source_names)

    def test_default_taint_sinks_configured(self):
        """
        测试默认污点汇点是否已配置
        """
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
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
        """
        测试生成 Frida 脚本
        """
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
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
        """
        测试添加自定义污点源
        """
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
                    from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker, DynamicTaintSource

                    tracker = FridaTaintTracker('/fake/binary')
                    original_count = len(tracker.taint_sources)

                    custom_source = DynamicTaintSource(
                        name='custom_input',
                        address=0x500000,
                        type='custom',
                        description='自定义输入源'
                    )
                    tracker.add_custom_taint_source(custom_source)

                    self.assertEqual(len(tracker.taint_sources), original_count + 1)

                    source_names = [s.name for s in tracker.taint_sources]
                    self.assertIn('custom_input', source_names)

    def test_add_custom_taint_sink(self):
        """
        测试添加自定义污点汇点
        """
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
                    from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker, DynamicTaintSink

                    tracker = FridaTaintTracker('/fake/binary')
                    original_count = len(tracker.taint_sinks)

                    custom_sink = DynamicTaintSink(
                        name='custom_dangerous',
                        address=0x600000,
                        type='custom',
                        argument_positions=[0, 1],
                        description='自定义危险函数'
                    )
                    tracker.add_custom_taint_sink(custom_sink)

                    self.assertEqual(len(tracker.taint_sinks), original_count + 1)

                    sink_names = [s.name for s in tracker.taint_sinks]
                    self.assertIn('custom_dangerous', sink_names)

    def test_is_available_when_frida_not_installed(self):
        """
        测试当 Frida 未安装时 is_available 返回 False
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': None}):
                    from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker, FRIDA_AVAILABLE

                    tracker = FridaTaintTracker('/fake/binary')
                    self.assertFalse(tracker.is_available())

    def test_is_available_when_binary_not_exists(self):
        """
        测试当二进制文件不存在时 is_available 返回 False
        """
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=False):
            with patch.dict('sys.modules', {'frida': mock_frida}):
                from modules.analysis.dynamic.dynamic_taint import FridaTaintTracker

                tracker = FridaTaintTracker('/fake/binary')
                self.assertFalse(tracker.is_available())

    def test_to_compatible_format(self):
        """
        测试转换为兼容格式
        """
        mock_frida, mock_device, mock_session, mock_script = self._create_mock_frida()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida}):
                    from modules.analysis.dynamic.dynamic_taint import (
                        FridaTaintTracker,
                        DynamicTaintSource,
                        DynamicTaintSink,
                        DynamicTaintFlow,
                        DynamicVulnerability
                    )

                    tracker = FridaTaintTracker('/fake/binary')

                    source = DynamicTaintSource(
                        name='read',
                        address=0x400000,
                        type='input',
                        description='标准输入'
                    )

                    sink = DynamicTaintSink(
                        name='system',
                        address=0x400200,
                        type='system',
                        argument_positions=[0],
                        description='命令执行'
                    )

                    flow = DynamicTaintFlow(
                        source=source,
                        sink=sink,
                        path=[0x400000, 0x400200],
                        tainted_variables=['0x7fff0000'],
                        confidence=0.9
                    )

                    tracker.taint_flows.append(flow)

                    vuln = DynamicVulnerability(
                        type='command_injection',
                        function_name='system',
                        address=0x400200,
                        description='污点传播漏洞',
                        severity='Critical',
                        evidence=['test evidence'],
                        tainted_variables=['0x7fff0000'],
                        taint_flow=flow
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


class TestQBDITaintTracker(unittest.TestCase):
    # 多轮测试后锁定的最优值
    """
    测试 QBDITaintTracker 类
    """

    def setUp(self):
        """
        测试前准备
        """
        for mod in ['modules.dynamic_taint', 'pyqbdi']:
            if mod in sys.modules:
                del sys.modules[mod]

    def _create_mock_qbdi(self):
        """
        创建 mock pyqbdi 模块
        """
        mock_qbdi = MagicMock()
        return mock_qbdi

    def test_initialize_qbdi_tracker(self):
        mock_qbdi = self._create_mock_qbdi()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'pyqbdi': mock_qbdi}):
                    from modules.analysis.dynamic.dynamic_taint import QBDITaintTracker

                    tracker = QBDITaintTracker('/fake/binary')

                    self.assertEqual(tracker.binary_path, '/fake/binary')
                    self.assertIsNotNone(tracker.taint_sources)
                    self.assertIsNotNone(tracker.taint_sinks)
                    self.assertIsNone(tracker.vm)
                    self.assertIsNone(tracker.state)

    def test_default_taint_sources(self):
        """
        测试 QBDI 追踪器的默认污点源
        """
        mock_qbdi = self._create_mock_qbdi()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'pyqbdi': mock_qbdi}):
                    from modules.analysis.dynamic.dynamic_taint import QBDITaintTracker

                    tracker = QBDITaintTracker('/fake/binary')

                    source_names = [s.name for s in tracker.taint_sources]
                    self.assertIn('read', source_names)
                    self.assertIn('recv', source_names)
                    self.assertIn('gets', source_names)


class TestCreateDynamicTaintTracker(unittest.TestCase):
    """
    测试 create_dynamic_taint_tracker 函数
    """

    def setUp(self):
        """
        测试前准备
        """
        for mod in ['modules.dynamic_taint', 'frida', 'pyqbdi']:
            if mod in sys.modules:
                del sys.modules[mod]

    def test_create_frida_tracker(self):
        mock_frida = MagicMock()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': mock_frida, 'pyqbdi': None}):
                    from modules.analysis.dynamic.dynamic_taint import create_dynamic_taint_tracker, FridaTaintTracker

                    tracker = create_dynamic_taint_tracker('/fake/binary', 'frida')

                    self.assertIsInstance(tracker, FridaTaintTracker)

    def test_create_qbdi_tracker(self):
        mock_qbdi = MagicMock()

        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': None, 'pyqbdi': mock_qbdi}):
                    from modules.analysis.dynamic.dynamic_taint import create_dynamic_taint_tracker, QBDITaintTracker

                    tracker = create_dynamic_taint_tracker('/fake/binary', 'qbdi')

                    self.assertIsInstance(tracker, QBDITaintTracker)

    def test_create_tracker_none_available(self):
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': None, 'pyqbdi': None}):
                    from modules.analysis.dynamic.dynamic_taint import create_dynamic_taint_tracker

                    tracker = create_dynamic_taint_tracker('/fake/binary', 'frida')

                    self.assertIsNone(tracker)


class TestRunDynamicTaintAnalysis(unittest.TestCase):
    """
    测试 run_dynamic_taint_analysis 函数
    """

    def setUp(self):
        for mod in ['modules.dynamic_taint', 'frida', 'pyqbdi']:
            if mod in sys.modules:
                del sys.modules[mod]

    def test_run_analysis_no_tracker_available(self):
        """
        测试当没有可用的追踪器时的行为
        """
        with patch('os.path.exists', return_value=True):
            with patch('os.path.isfile', return_value=True):
                with patch.dict('sys.modules', {'frida': None, 'pyqbdi': None}):
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
