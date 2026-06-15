#!/usr/bin/env python3
"""
API调用追踪模块测试
"""
import os
import sys
import unittest
import tempfile
import shutil
from datetime import datetime

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.behavior_tracer import (
    BehaviorTracer, ApiCall, BehaviorSequence, TraceResult,
    BehaviorCategory, MALICIOUS_BEHAVIOR_PATTERNS
)


class TestBehaviorTracer(unittest.TestCase):
    """API调用追踪器测试类"""

    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.tracer = BehaviorTracer(output_dir=self.temp_dir)

    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)

    def test_behavior_category_enum(self):
        """测试行为分类枚举"""
        self.assertEqual(BehaviorCategory.FILE_OPERATION.value, 'file_operation')
        self.assertEqual(BehaviorCategory.NETWORK.value, 'network')
        self.assertEqual(BehaviorCategory.PROCESS.value, 'process')
        self.assertEqual(BehaviorCategory.MEMORY.value, 'memory')
        self.assertEqual(BehaviorCategory.REGISTRY.value, 'registry')

    def test_malicious_behavior_patterns(self):
        """测试恶意行为模式定义"""
        # 检查常见恶意行为模式存在
        self.assertIn('process_injection', MALICIOUS_BEHAVIOR_PATTERNS)
        self.assertIn('privilege_escalation', MALICIOUS_BEHAVIOR_PATTERNS)
        self.assertIn('c2_communication', MALICIOUS_BEHAVIOR_PATTERNS)
        self.assertIn('data_exfiltration', MALICIOUS_BEHAVIOR_PATTERNS)
        
        # 检查模式结构
        injection_pattern = MALICIOUS_BEHAVIOR_PATTERNS['process_injection']
        self.assertIn('name', injection_pattern)
        self.assertIn('severity', injection_pattern)
        self.assertIn('api_sequence', injection_pattern)

    def test_api_call_dataclass(self):
        """测试 ApiCall 数据类"""
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
        """测试 ApiCall 转换为字典"""
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
        """测试 BehaviorSequence 数据类"""
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
        """测试 BehaviorSequence 转换为字典"""
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
        """测试 TraceResult 数据类"""
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
        """测试 TraceResult 转换为字典"""
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
        """测试分析行为序列"""
        # 创建测试 API 调用序列
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
        
        # 应该检测到进程注入模式
        self.assertGreaterEqual(len(sequences), 1)

    def test_categorize_api_call(self):
        """测试 API 调用分类"""
        # 测试文件操作
        category = self.tracer._categorize_api_call('open', {})
        self.assertEqual(category, BehaviorCategory.FILE_OPERATION)
        
        # 测试网络操作
        category = self.tracer._categorize_api_call('connect', {})
        self.assertEqual(category, BehaviorCategory.NETWORK)
        
        # 测试进程操作
        category = self.tracer._categorize_api_call('fork', {})
        self.assertEqual(category, BehaviorCategory.PROCESS)

    def test_generate_report(self):
        """测试生成报告"""
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
        """测试保存结果"""
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
        """测试追踪不存在的二进制"""
        result = self.tracer.trace_binary('/nonexistent/binary', timeout=5)
        
        self.assertGreater(len(result.errors), 0)


class TestApiCall(unittest.TestCase):
    """ApiCall 数据类测试"""

    def test_success_flag(self):
        """测试成功标志"""
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
    """BehaviorSequence 数据类测试"""

    def test_confidence_range(self):
        """测试置信度范围"""
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