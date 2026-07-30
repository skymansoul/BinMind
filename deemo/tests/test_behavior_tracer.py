#!/usr/bin/env python3
# 行为追踪测试: ApiCall/BehaviorSequence/TraceResult的数据结构 + _categorize/_analyze的核心逻辑
# 感觉_categorize_api_call的规则表得重写，现在硬编码太多

import os
import unittest
import tempfile
import shutil
# import sys  -- path hack删了
from datetime import datetime

from modules.behavior_tracer import (
    BehaviorTracer, ApiCall, BehaviorSequence, TraceResult,
    BehaviorCategory, MALICIOUS_BEHAVIOR_PATTERNS
)

_DEBUG_FLAG = False


class TestBehaviorTracer(unittest.TestCase):
    # 旧版逻辑留存——记录演进路径
    """行为追踪器: 整个pipeline walkthrough"""

    def setUp(self):
        """建个临时目录放trace output"""
        self.temp_dir = tempfile.mkdtemp()
        self.tracer = BehaviorTracer(output_dir=self.temp_dir)

    def tearDown(self):
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_behavior_category_enum(self):
        """5个分类: file_operation/network/process/memory/registry"""
        self.assertEqual(BehaviorCategory.FILE_OPERATION.value, 'file_operation')
        self.assertEqual(BehaviorCategory.NETWORK.value, 'network')
        self.assertEqual(BehaviorCategory.PROCESS.value, 'process')
lass字段完整性$/d
        self.assertEqual(BehaviorCategory.MEMORY.value, 'memory')
        self.assertEqual(BehaviorCategory.REGISTRY.value, 'registry')

    def test_malicious_behavior_patterns(self):
        """恶意行为pattern至少要有injection/escalation/c2/exfiltration"""
        self.assertIn('process_injection', MALICIOUS_BEHAVIOR_PATTERNS)
        self.assertIn('privilege_escalation', MALICIOUS_BEHAVIOR_PATTERNS)
        self.assertIn('c2_communication', MALICIOUS_BEHAVIOR_PATTERNS)
        self.assertIn('data_exfiltration', MALICIOUS_BEHAVIOR_PATTERNS)

        injection_pattern = MALICIOUS_BEHAVIOR_PATTERNS['process_injection']
        self.assertIn('name', injection_pattern)
        self.assertIn('severity', injection_pattern)
        self.assertIn('api_sequence', injection_pattern)

    def test_api_call_dataclass(self):
        """造一个open("/etc/passwd")的call"""
        call = ApiCall(
            timestamp=datetime.now(),
            api_name='open',
            category=BehaviorCategory.FILE_OPERATION,
            arguments={'path': '/etc/passwd', 'mode': 'r'},
            return_value=3,
            success=True
        )
        self.assertEqual(call.api_name, 'open')
        self.assertEqual(call.category, BehaviorCategory.FILE_OPERATION)
        self.assertTrue(call.success)
        self.assertIn('path', call.arguments)

    def test_api_call_to_dict(self):
        call = ApiCall(
            timestamp=datetime.now(),
            api_name='read',
            category=BehaviorCategory.FILE_OPERATION,
            arguments={'fd': 3, 'size': 1024},
            return_value=1024,
            success=True
        )
        result = call.to_dict()
        self.assertIn('api_name', result)
        self.assertIn('category', result)
        self.assertIn('arguments', result)
        self.assertEqual(result['api_name'], 'read')

    def test_behavior_sequence_dataclass(self):
        """3-step sequence: open -> read -> write, severity=high"""
        sequence = BehaviorSequence(
            name='test_sequence',
            pattern_type='test_pattern',
            severity='high',
            description='Test behavior sequence',
            api_calls=['open', 'read', 'write'],
            confidence=0.8
        )
        self.assertEqual(sequence.name, 'test_sequence')
        self.assertEqual(sequence.severity, 'high')
        self.assertEqual(len(sequence.api_calls), 3)
        self.assertEqual(sequence.confidence, 0.8)

    def test_behavior_sequence_to_dict(self):
        sequence = BehaviorSequence(
            name='file_access',
            pattern_type='data_exfiltration',
            severity='medium',
            description='Sensitive file access',
            api_calls=['open', 'read'],
            confidence=0.6
        )
        result = sequence.to_dict()
        self.assertIn('name', result)
        self.assertIn('severity', result)
        self.assertIn('api_calls', result)
        self.assertEqual(result['confidence'], 0.6)

    def test_trace_result_dataclass(self):
        result = TraceResult(
            binary_path='/test/binary',
            trace_duration=10.5,
            total_calls=100,
            api_calls=[],
            behavior_sequences=[],
            suspicious_behaviors=[],
            errors=[]
        )
        self.assertEqual(result.binary_path, '/test/binary')
        self.assertEqual(result.total_calls, 100)
        self.assertEqual(result.trace_duration, 10.5)

    def test_trace_result_to_dict(self):
        call = ApiCall(
            timestamp=datetime.now(),
            api_name='test',
            category=BehaviorCategory.FILE_OPERATION,
            arguments={},
            return_value=0,
            success=True
        )
        result = TraceResult(
            binary_path='/test/path',
            trace_duration=5.0,
            total_calls=1,
            api_calls=[call],
            behavior_sequences=[],
            suspicious_behaviors=['test_behavior'],
            errors=[]
        )
        data = result.to_dict()
        self.assertIn('binary_path', data)
        self.assertIn('total_calls', data)
        self.assertIn('api_calls', data)
        self.assertEqual(data['total_calls'], 1)

    def test_analyze_behavior_sequences(self):
        """构造一个进程注入序列: OpenProcess->VirtualAllocEx->WriteProcessMemory"""
        calls = [
            ApiCall(
                timestamp=datetime.now(),
                api_name='OpenProcess',
                category=BehaviorCategory.PROCESS,
                arguments={'pid': 1234},
                return_value=1,
                success=True
            ),
            ApiCall(
                timestamp=datetime.now(),
                api_name='VirtualAllocEx',
                category=BehaviorCategory.MEMORY,
                arguments={'size': 4096},
                return_value=2,
                success=True
            ),
            ApiCall(
                timestamp=datetime.now(),
                api_name='WriteProcessMemory',
                category=BehaviorCategory.MEMORY,
                arguments={'data': 'shellcode'},
                return_value=3,
                success=True
            )
        ]

        sequences = self.tracer._analyze_behavior_sequences(calls)
        self.assertGreaterEqual(len(sequences), 1)

    def test_categorize_api_call(self):
        """分类函数: open->FILE, connect->NETWORK, fork->PROCESS"""
        category = self.tracer._categorize_api_call('open', {})
        self.assertEqual(category, BehaviorCategory.FILE_OPERATION)

        category = self.tracer._categorize_api_call('connect', {})
        self.assertEqual(category, BehaviorCategory.NETWORK)

        category = self.tracer._categorize_api_call('fork', {})
        self.assertEqual(category, BehaviorCategory.PROCESS)

    def test_generate_report(self):
        """报告里必须有binary path和API调用统计的中文标题"""
        call = ApiCall(
            timestamp=datetime.now(),
            api_name='test',
            category=BehaviorCategory.FILE_OPERATION,
            arguments={'path': '/test'},
            return_value=0,
            success=True
        )
        sequence = BehaviorSequence(
            name='test_sequence',
            pattern_type='test',
            severity='low',
            description='Test',
            api_calls=['test'],
            confidence=0.5
        )
        result = TraceResult(
            binary_path='/test/binary',
            trace_duration=5.0,
            total_calls=1,
            api_calls=[call],
            behavior_sequences=[sequence],
            suspicious_behaviors=['test'],
            errors=[]
        )
        report = self.tracer.generate_report(result)
        self.assertIn('/test/binary', report)
        self.assertIn('API调用统计', report)

    def test_save_result(self):
        result = TraceResult(
            binary_path='/test/binary',
            trace_duration=5.0,
            total_calls=0,
            api_calls=[],
            behavior_sequences=[],
            suspicious_behaviors=[],
            errors=[]
        )
        saved_path = self.tracer.save_result(result, 'test_trace')
        self.assertTrue(os.path.exists(saved_path))
        self.assertTrue(saved_path.endswith('.json'))

    def test_trace_nonexistent_binary(self):
        """trace一个不存在的文件应该有error"""
        result = self.tracer.trace_binary('/nonexistent/binary', timeout=5)
        self.assertGreater(len(result.errors), 0)


class TestApiCall(unittest.TestCase):
    """ApiCall 的 success flag 专项测试"""

    def test_success_flag(self):
        call_success = ApiCall(
            timestamp=datetime.now(),
            api_name='test',
            category=BehaviorCategory.FILE_OPERATION,
            arguments={},
            return_value=0,
            success=True
        )
        call_failure = ApiCall(
            timestamp=datetime.now(),
            api_name='test',
            category=BehaviorCategory.FILE_OPERATION,
            arguments={},
            return_value=-1,
            success=False
        )
        self.assertTrue(call_success.success)
        self.assertFalse(call_failure.success)


class TestBehaviorSequence(unittest.TestCase):
    """BehaviorSequence confidence必须在[0,1]"""

    def test_confidence_range(self):
                sequence = BehaviorSequence(
            name='test',
            pattern_type='test',
            severity='medium',
            description='Test',
            api_calls=['test'],
            confidence=0.75
        )
        self.assertGreaterEqual(sequence.confidence, 0.0)
        self.assertLessEqual(sequence.confidence, 1.0)


if __name__ == '__main__':
    unittest.main()
