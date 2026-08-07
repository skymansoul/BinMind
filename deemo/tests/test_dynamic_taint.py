"""
动态污点测试 — 数据类与基础功能.

测试内容:
- DynamicTaintSource / DynamicTaintSink / DynamicTaintFlow / DynamicVulnerability
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


class TestDynamicTaintSource(unittest.TestCase):
    """测试 DynamicTaintSource 数据类"""

    def test_create_taint_source(self):
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintSource

        source = DynamicTaintSource(
            name='read', address=0x400000,
            type='input', description='标准输入读取'
        )

        self.assertEqual(source.name, 'read')
        self.assertEqual(source.address, 0x400000)
        self.assertEqual(source.type, 'input')
        self.assertEqual(source.description, '标准输入读取')
        self.assertEqual(source.data_size, 0)
        self.assertEqual(source.registers, set())
        self.assertIsNone(source.memory_range)

    def test_create_taint_source_with_registers(self):
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintSource

        source = DynamicTaintSource(
            name='recv', address=0x400100,
            type='network', registers={'rdi', 'rsi', 'rdx'},
            memory_range=(0x7fffffff0000, 0x7fffffff1000),
            data_size=4096, description='网络接收'
        )

        self.assertEqual(source.name, 'recv')
        self.assertIn('rdi', source.registers)
        self.assertEqual(source.data_size, 4096)
        self.assertEqual(source.memory_range, (0x7fffffff0000, 0x7fffffff1000))


class TestDynamicTaintSink(unittest.TestCase):
    """测试 DynamicTaintSink 数据类"""

    def test_create_taint_sink(self):
        from modules.analysis.dynamic.dynamic_taint import DynamicTaintSink

        sink = DynamicTaintSink(
            name='system', address=0x400200,
            type='system', argument_positions=[0],
            description='命令执行'
        )

        self.assertEqual(sink.name, 'system')
        self.assertEqual(sink.address, 0x400200)
        self.assertEqual(sink.type, 'system')
        self.assertEqual(sink.argument_positions, [0])
        self.assertEqual(sink.tainted_args, [])


class TestDynamicTaintFlow(unittest.TestCase):
    """测试 DynamicTaintFlow 数据类"""

    def test_create_taint_flow(self):
        from modules.analysis.dynamic.dynamic_taint import (
            DynamicTaintFlow, DynamicTaintSource, DynamicTaintSink
        )

        source = DynamicTaintSource(
            name='read', address=0x400000,
            type='input', description='标准输入'
        )
        sink = DynamicTaintSink(
            name='system', address=0x400200,
            type='system', argument_positions=[0],
            description='命令执行'
        )
        flow = DynamicTaintFlow(
            source=source, sink=sink,
            path=[0x400000, 0x400100, 0x400200],
            tainted_variables=['0x7fffffffd000'],
            confidence=0.95, execution_count=3
        )

        self.assertEqual(flow.source, source)
        self.assertEqual(flow.sink, sink)
        self.assertEqual(len(flow.path), 3)
        self.assertEqual(flow.confidence, 0.95)
        self.assertEqual(flow.execution_count, 3)


class TestDynamicVulnerability(unittest.TestCase):
    """测试 DynamicVulnerability 数据类"""

    def test_create_dynamic_vulnerability(self):
        from modules.analysis.dynamic.dynamic_taint import (
            DynamicVulnerability, DynamicTaintFlow,
            DynamicTaintSource, DynamicTaintSink
        )

        source = DynamicTaintSource(
            name='read', address=0x400000,
            type='input', description='标准输入'
        )
        sink = DynamicTaintSink(
            name='system', address=0x400200,
            type='system', argument_positions=[0],
            description='命令执行'
        )
        taint_flow = DynamicTaintFlow(
            source=source, sink=sink,
            path=[0x400000, 0x400200],
            tainted_variables=['0x7fffffffd000'],
            confidence=0.9
        )
        vuln = DynamicVulnerability(
            type='command_injection', function_name='system',
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


if __name__ == '__main__':
    unittest.main()
