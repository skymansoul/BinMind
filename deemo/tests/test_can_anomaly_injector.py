#!/usr/bin/env python3
"""
CAN异常注入引擎单元测试
"""

import os
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.can_anomaly_injector import (
    CANAnomalyInjector, ArbitrationErrorInjector, BitFlipInjector, CRCErrorInjector,
    CANFrame, AnomalyConfig, InjectionResult, Vulnerability, CANAnalysisResult,
    CANFrameType, AnomalyType, ResponseType, SeverityLevel
)


class TestCANFrameTypeEnum(unittest.TestCase):
    """CAN帧类型枚举测试"""
    
    def test_can_frame_type_values(self):
        """测试CAN帧类型枚举值"""
        self.assertEqual(CANFrameType.DATA_FRAME.value, "data_frame")
        self.assertEqual(CANFrameType.REMOTE_FRAME.value, "remote_frame")
        self.assertEqual(CANFrameType.ERROR_FRAME.value, "error_frame")
        self.assertEqual(CANFrameType.OVERLOAD_FRAME.value, "overload_frame")


class TestAnomalyTypeEnum(unittest.TestCase):
    """异常类型枚举测试"""
    
    def test_anomaly_type_values(self):
        """测试异常类型枚举值"""
        self.assertEqual(AnomalyType.ARBITRATION_ERROR.value, "arbitration_error")
        self.assertEqual(AnomalyType.BIT_FLIP.value, "bit_flip")
        self.assertEqual(AnomalyType.CRC_ERROR.value, "crc_error")
        self.assertEqual(AnomalyType.ACK_ERROR.value, "ack_error")
        self.assertEqual(AnomalyType.FORM_ERROR.value, "form_error")


class TestResponseTypeEnum(unittest.TestCase):
    """响应类型枚举测试"""
    
    def test_response_type_values(self):
        """测试响应类型枚举值"""
        self.assertEqual(ResponseType.NORMAL.value, "normal")
        self.assertEqual(ResponseType.RESTART.value, "restart")
        self.assertEqual(ResponseType.DEADLOCK.value, "deadlock")
        self.assertEqual(ResponseType.TIMEOUT.value, "timeout")


class TestSeverityLevelEnum(unittest.TestCase):
    """严重程度枚举测试"""
    
    def test_severity_level_values(self):
        """测试严重程度枚举值"""
        self.assertEqual(SeverityLevel.INFO.value, "info")
        self.assertEqual(SeverityLevel.WARNING.value, "warning")
        self.assertEqual(SeverityLevel.ERROR.value, "error")
        self.assertEqual(SeverityLevel.CRITICAL.value, "critical")


class TestCANFrameDataclass(unittest.TestCase):
    """CANFrame数据类测试"""
    
    def test_can_frame_creation(self):
        """测试CAN帧创建"""
        frame = CANFrame(
            can_id=0x123,
            data=b"\x01\x02\x03\x04",
            dlc=4,
            is_extended=False,
            is_remote=False,
            timestamp=12345
        )
        
        self.assertEqual(frame.can_id, 0x123)
        self.assertEqual(frame.data, b"\x01\x02\x03\x04")
        self.assertEqual(frame.dlc, 4)
        self.assertFalse(frame.is_extended)


class TestAnomalyConfigDataclass(unittest.TestCase):
    """AnomalyConfig数据类测试"""
    
    def test_anomaly_config_creation(self):
        """测试异常配置创建"""
        config = AnomalyConfig(
            anomaly_type=AnomalyType.BIT_FLIP,
            probability=0.5,
            target_id=0x123,
            bit_position=5,
            description="测试位翻转"
        )
        
        self.assertEqual(config.anomaly_type, AnomalyType.BIT_FLIP)
        self.assertEqual(config.probability, 0.5)
        self.assertEqual(config.bit_position, 5)


class TestArbitrationErrorInjector(unittest.TestCase):
    """仲裁错误注入器测试"""
    
    def test_inject(self):
        """测试注入仲裁错误"""
        injector = ArbitrationErrorInjector()
        frame = CANFrame(can_id=0x123, data=b"\x00" * 8)
        
        result = injector.inject(frame, AnomalyConfig(anomaly_type=AnomalyType.ARBITRATION_ERROR))
        
        self.assertNotEqual(result.can_id, 0x123)


class TestBitFlipInjector(unittest.TestCase):
    """位翻转变压器测试"""
    
    def test_inject_with_position(self):
        """测试注入指定位置的位翻转"""
        injector = BitFlipInjector()
        frame = CANFrame(can_id=0x123, data=b"\x00\x00\x00\x00")
        
        config = AnomalyConfig(anomaly_type=AnomalyType.BIT_FLIP, bit_position=0)
        result = injector.inject(frame, config)
        
        self.assertEqual(result.data[0], 0x01)
    
    def test_inject_random_position(self):
        """测试注入随机位置的位翻转"""
        injector = BitFlipInjector()
        frame = CANFrame(can_id=0x123, data=b"\xFF\xFF\xFF\xFF")
        
        config = AnomalyConfig(anomaly_type=AnomalyType.BIT_FLIP)
        result = injector.inject(frame, config)
        
        self.assertNotEqual(result.data, b"\xFF\xFF\xFF\xFF")


class TestCRCErrorInjector(unittest.TestCase):
    """CRC错误注入器测试"""
    
    def test_inject(self):
        """测试注入CRC错误"""
        injector = CRCErrorInjector()
        frame = CANFrame(can_id=0x123, data=b"\x01\x02\x03\x04")
        
        result = injector.inject(frame, AnomalyConfig(anomaly_type=AnomalyType.CRC_ERROR))
        
        self.assertNotEqual(result.data[-1], 0x04)


class TestCANAnomalyInjector(unittest.TestCase):
    """CAN异常注入引擎测试"""
    
    def setUp(self):
        """测试前准备"""
        self.temp_dir = tempfile.mkdtemp()
        self.injector = CANAnomalyInjector()
    
    def tearDown(self):
        """测试后清理"""
        if os.path.exists(self.temp_dir):
            shutil.rmtree(self.temp_dir)
    
    def test_load_firmware(self):
        """测试加载固件"""
        test_file = os.path.join(self.temp_dir, "firmware.bin")
        with open(test_file, 'wb') as f:
            f.write(b"\x00" * 100)
        
        result = self.injector.load_firmware(test_file)
        
        self.assertTrue(result)
    
    def test_load_missing_firmware(self):
        """测试加载不存在的固件"""
        result = self.injector.load_firmware("/nonexistent/firmware.bin")
        
        self.assertFalse(result)
    
    def test_inject_anomaly(self):
        """测试注入异常"""
        frame = CANFrame(can_id=0x123, data=b"\x00" * 8)
        
        result = self.injector.inject_anomaly(frame, AnomalyType.BIT_FLIP)
        
        self.assertIsInstance(result, InjectionResult)
        self.assertEqual(result.anomaly_type, AnomalyType.BIT_FLIP)
    
    def test_run_test_suite(self):
        """测试运行测试套件"""
        frames = [
            CANFrame(can_id=0x123, data=b"\x00" * 8),
            CANFrame(can_id=0x456, data=b"\x11" * 8)
        ]
        
        result = self.injector.run_test_suite(frames, [AnomalyType.BIT_FLIP, AnomalyType.CRC_ERROR])
        
        self.assertTrue(result.success)
        self.assertEqual(result.total_injections, 4)
    
    def test_generate_test_frames(self):
        """测试生成测试帧"""
        frames = self.injector.generate_test_frames([0x123, 0x456], count=2)
        
        self.assertEqual(len(frames), 4)
        self.assertEqual(frames[0].can_id, 0x123)
    
    def test_generate_report(self):
        """测试生成报告"""
        result = CANAnalysisResult(
            success=True,
            total_injections=10,
            successful_injections=2,
            vulnerabilities=[],
            injection_results=[]
        )
        
        report = self.injector.generate_report(result)
        
        self.assertIn("CAN异常注入分析报告", report)
    
    def test_save_result(self):
        """测试保存结果"""
        result = CANAnalysisResult(
            success=True,
            total_injections=10,
            successful_injections=2,
            vulnerabilities=[],
            injection_results=[]
        )
        
        output_path = os.path.join(self.temp_dir, "result.json")
        success = self.injector.save_result(result, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))
    
    def test_analyze_firmware(self):
        """测试分析固件"""
        test_file = os.path.join(self.temp_dir, "firmware.bin")
        with open(test_file, 'wb') as f:
            f.write(b"\x00" * 100)
        
        frames = [CANFrame(can_id=0x123, data=b"\x00" * 8)]
        
        result = self.injector.analyze_firmware(test_file, frames)
        
        self.assertTrue(result.success)


class TestVulnerabilityDataclass(unittest.TestCase):
    """Vulnerability数据类测试"""
    
    def test_vulnerability_creation(self):
        """测试漏洞创建"""
        vuln = Vulnerability(
            anomaly_type=AnomalyType.BIT_FLIP,
            can_id=0x123,
            response_type=ResponseType.RESTART,
            severity=SeverityLevel.CRITICAL,
            description="测试漏洞",
            location=0x1000,
            recommended_fix="修复建议"
        )
        
        self.assertEqual(vuln.anomaly_type, AnomalyType.BIT_FLIP)
        self.assertEqual(vuln.can_id, 0x123)
        self.assertEqual(vuln.severity, SeverityLevel.CRITICAL)


class TestCANAnalysisResultDataclass(unittest.TestCase):
    """CANAnalysisResult数据类测试"""
    
    def test_can_analysis_result_creation(self):
        """测试CAN分析结果创建"""
        result = CANAnalysisResult(
            success=True,
            total_injections=10,
            successful_injections=5,
            vulnerabilities=[],
            injection_results=[],
            warnings=["警告"]
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.total_injections, 10)


if __name__ == '__main__':
    unittest.main()