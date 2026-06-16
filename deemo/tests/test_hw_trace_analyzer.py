#!/usr/bin/env python3
"""
硬件跟踪分析器单元测试
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.hw_trace_analyzer import (
    HWTraceAnalyzer, IntelPTDecoder, PerfDecoder, TraceAnalysisResult,
    TracePacket, TraceInstruction, TraceFunction, TracePath, DataFlow,
    TraceType, TraceStatus
)


class TestTraceTypeEnum(unittest.TestCase):
    """跟踪类型枚举测试"""
    
    def test_trace_type_values(self):
        """测试跟踪类型枚举值"""
        self.assertEqual(TraceType.INTEL_PT.value, "intel_pt")
        self.assertEqual(TraceType.ARM_ETM.value, "arm_etm")
        self.assertEqual(TraceType.PERF_RECORD.value, "perf_record")


class TestTraceStatusEnum(unittest.TestCase):
    """跟踪状态枚举测试"""
    
    def test_trace_status_values(self):
        """测试跟踪状态枚举值"""
        self.assertEqual(TraceStatus.COLLECTING.value, "collecting")
        self.assertEqual(TraceStatus.DECODED.value, "decoded")
        self.assertEqual(TraceStatus.ANALYZED.value, "analyzed")
        self.assertEqual(TraceStatus.ERROR.value, "error")


class TestTracePacketDataclass(unittest.TestCase):
    """TracePacket数据类测试"""
    
    def test_trace_packet_creation(self):
        """测试跟踪包创建"""
        packet = TracePacket(
            timestamp=123456,
            type="TIP",
            payload=b"\x00\x01\x02\x03",
            address=0x401000
        )
        
        self.assertEqual(packet.timestamp, 123456)
        self.assertEqual(packet.type, "TIP")
        self.assertEqual(packet.address, 0x401000)


class TestTraceInstructionDataclass(unittest.TestCase):
    """TraceInstruction数据类测试"""
    
    def test_trace_instruction_creation(self):
        """测试跟踪指令创建"""
        instr = TraceInstruction(
            address=0x401000,
            mnemonic="mov",
            executed=True,
            timestamp=123456,
            cycle_count=10
        )
        
        self.assertEqual(instr.address, 0x401000)
        self.assertTrue(instr.executed)
        self.assertEqual(instr.cycle_count, 10)


class TestTraceFunctionDataclass(unittest.TestCase):
    """TraceFunction数据类测试"""
    
    def test_trace_function_creation(self):
        """测试跟踪函数创建"""
        func = TraceFunction(
            name="main",
            start_address=0x401000,
            end_address=0x401050,
            entry_count=1,
            exit_count=1
        )
        
        self.assertEqual(func.name, "main")
        self.assertEqual(func.start_address, 0x401000)
        self.assertEqual(func.end_address, 0x401050)


class TestTracePathDataclass(unittest.TestCase):
    """TracePath数据类测试"""
    
    def test_trace_path_creation(self):
        """测试执行路径创建"""
        instr = TraceInstruction(
            address=0x401000,
            mnemonic="mov",
            executed=True,
            timestamp=123456
        )
        
        path = TracePath(
            instructions=[instr],
            function_calls=[(0x401000, 0x402000)],
            is_complete=True
        )
        
        self.assertEqual(len(path.instructions), 1)
        self.assertEqual(len(path.function_calls), 1)
        self.assertTrue(path.is_complete)


class TestDataFlowDataclass(unittest.TestCase):
    """DataFlow数据类测试"""
    
    def test_data_flow_creation(self):
        """测试数据流创建"""
        flow = DataFlow(
            source=0x1000,
            destination=0x2000,
            value=42,
            size=4,
            operation="mov"
        )
        
        self.assertEqual(flow.source, 0x1000)
        self.assertEqual(flow.destination, 0x2000)
        self.assertEqual(flow.value, 42)


class TestIntelPTDecoder(unittest.TestCase):
    """Intel PT解码器测试"""
    
    def test_decode_empty_data(self):
        """测试解码空数据"""
        decoder = IntelPTDecoder("/nonexistent")
        result = decoder.decode(b"")
        
        self.assertEqual(len(result), 0)
    
    def test_decode_sample_data(self):
        """测试解码样本数据"""
        decoder = IntelPTDecoder("/nonexistent")
        sample_data = b"\x00\x00\x00\x00\x01\x00\x00\x00\x40\x10\x00\x00"
        
        result = decoder.decode(sample_data)
        
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0].type, "TNT")


class TestPerfDecoder(unittest.TestCase):
    """Perf解码器测试"""
    
    def test_decode_empty_data(self):
        """测试解码空数据"""
        decoder = PerfDecoder()
        result = decoder.decode(b"")
        
        self.assertEqual(len(result), 0)
    
    def test_decode_sample_data(self):
        """测试解码样本数据"""
        decoder = PerfDecoder()
        sample_data = b"\x18\x00\x00\x00\x00\x00\x00\x00\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        
        result = decoder.decode(sample_data)
        
        self.assertEqual(len(result), 1)


class TestHWTraceAnalyzer(unittest.TestCase):
    """硬件跟踪分析器测试"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_analyzer_creation(self):
        """测试分析器创建"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x7fELF" + b"\x00" * 100)
        
        analyzer = HWTraceAnalyzer(test_file, TraceType.INTEL_PT)
        
        self.assertEqual(analyzer.binary_path, test_file)
        self.assertEqual(analyzer.trace_type, TraceType.INTEL_PT)
    
    def test_analyzer_missing_binary(self):
        """测试分析器处理不存在的二进制"""
        with self.assertRaises(FileNotFoundError):
            HWTraceAnalyzer("/nonexistent/file.bin")
    
    def test_analyze_empty_trace(self):
        """测试分析空跟踪数据"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x00" * 100)
        
        analyzer = HWTraceAnalyzer(test_file)
        result = analyzer.analyze_trace(b"")
        
        self.assertFalse(result.success)
        self.assertEqual(result.status, TraceStatus.ERROR)
    
    def test_analyze_valid_trace(self):
        """测试分析有效跟踪数据"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x00" * 100)
        
        analyzer = HWTraceAnalyzer(test_file)
        
        # 生成模拟跟踪数据
        sample_trace = b"\x00\x00\x00\x00\x01\x00\x00\x00\x40\x10\x00\x00"
        
        result = analyzer.analyze_trace(sample_trace)
        
        self.assertTrue(result.success)
        self.assertEqual(result.status, TraceStatus.ANALYZED)
    
    def test_generate_report(self):
        """测试生成报告"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x00" * 100)
        
        analyzer = HWTraceAnalyzer(test_file)
        
        result = TraceAnalysisResult(
            success=True,
            status=TraceStatus.ANALYZED,
            trace_path=TracePath(instructions=[], function_calls=[]),
            functions=[],
            data_flows=[]
        )
        
        report = analyzer.generate_report(result)
        
        self.assertIn("硬件跟踪分析报告", report)
    
    def test_save_result(self):
        """测试保存结果"""
        test_file = os.path.join(self.temp_dir, "test.bin")
        with open(test_file, "wb") as f:
            f.write(b"\x00" * 100)
        
        analyzer = HWTraceAnalyzer(test_file)
        
        result = TraceAnalysisResult(
            success=True,
            status=TraceStatus.ANALYZED,
            trace_path=TracePath(instructions=[], function_calls=[]),
            functions=[],
            data_flows=[]
        )
        
        output_path = os.path.join(self.temp_dir, "result.json")
        success = analyzer.save_result(result, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))


class TestTraceAnalysisResultDataclass(unittest.TestCase):
    """TraceAnalysisResult数据类测试"""
    
    def test_trace_analysis_result_creation(self):
        """测试跟踪分析结果创建"""
        result = TraceAnalysisResult(
            success=True,
            status=TraceStatus.ANALYZED,
            trace_path=TracePath(instructions=[], function_calls=[]),
            functions=[],
            data_flows=[],
            control_flow_graph={},
            warnings=["警告"],
            errors=[]
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.status, TraceStatus.ANALYZED)
        self.assertEqual(len(result.warnings), 1)


if __name__ == '__main__':
    unittest.main()