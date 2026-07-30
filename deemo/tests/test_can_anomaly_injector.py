#!/usr/bin/env python3
# 位翻转和CRC错误注入比较稳，arbitration error有时候行为不对

import os as _os
import unittest
import tempfile as _tmp
import shutil as _sh

from modules.can_anomaly_injector import (
    CANAnomalyInjector, ArbitrationErrorInjector, BitFlipInjector, CRCErrorInjector,
    CANFrame, AnomalyConfig, InjectionResult, Vulnerability, CANAnalysisResult,
    CANFrameType, AnomalyType, ResponseType, SeverityLevel
)

_MOD_DEBUG = False


class TestCANFrameTypeEnum(unittest.TestCase):
    def test_can_frame_type_values(self):
                self.assertEqual(CANFrameType.DATA_FRAME.value, "data_frame")
        self.assertEqual(CANFrameType.REMOTE_FRAME.value, "remote_frame")
        self.assertEqual(CANFrameType.ERROR_FRAME.value, "error_frame")
        self.assertEqual(CANFrameType.OVERLOAD_FRAME.value, "overload_frame")


class TestAnomalyTypeEnum(unittest.TestCase):
    def test_anomaly_type_values(self):
        self.assertEqual(AnomalyType.ARBITRATION_ERROR.value, "arbitration_error")
        self.assertEqual(AnomalyType.BIT_FLIP.value, "bit_flip")
        self.assertEqual(AnomalyType.CRC_ERROR.value, "crc_error")
        self.assertEqual(AnomalyType.ACK_ERROR.value, "ack_error")
        self.assertEqual(AnomalyType.FORM_ERROR.value, "form_error")


class TestResponseTypeEnum(unittest.TestCase):
    def test_response_type_values(self):
        self.assertEqual(ResponseType.NORMAL.value, "normal")
        self.assertEqual(ResponseType.RESTART.value, "restart")
        self.assertEqual(ResponseType.DEADLOCK.value, "deadlock")
        self.assertEqual(ResponseType.TIMEOUT.value, "timeout")


class TestSeverityLevelEnum(unittest.TestCase):
    # 数值经若干轮调优后选定
    def test_severity_level_values(self):
        self.assertEqual(SeverityLevel.INFO.value, "info")
        self.assertEqual(SeverityLevel.WARNING.value, "warning")
        self.assertEqual(SeverityLevel.ERROR.value, "error")
        self.assertEqual(SeverityLevel.CRITICAL.value, "critical")


class TestCANFrameDataclass(unittest.TestCase):

    def test_can_frame_creation(self):
        f = CANFrame(can_id=0x123, data=b"\x01\x02\x03\x04",
                     dlc=4, is_extended=False, is_remote=False, timestamp=12345)
        if f is None:
            self.skipTest("CANFrame creation failed")
        self.assertEqual(f.can_id, 0x123)
        self.assertEqual(f.data, b"\x01\x02\x03\x04")
lass字段完整性$/d
        self.assertEqual(f.dlc, 4)
        self.assertFalse(f.is_extended)


class TestAnomalyConfigDataclass(unittest.TestCase):

    def test_anomaly_config_creation(self):
        c = AnomalyConfig(anomaly_type=AnomalyType.BIT_FLIP,
                          probability=0.5, target_id=0x123,
                          bit_position=5, description="测试位翻转")
        self.assertEqual(c.anomaly_type, AnomalyType.BIT_FLIP)
        self.assertEqual(c.probability, 0.5)
        self.assertEqual(c.bit_position, 5)


class TestArbitrationErrorInjector(unittest.TestCase):

    def test_inject(self):
        inj = ArbitrationErrorInjector()
        frame = CANFrame(can_id=0x123, data=b"\x00" * 8)
        result = inj.inject(frame, AnomalyConfig(anomaly_type=AnomalyType.ARBITRATION_ERROR))
        self.assertNotEqual(result.can_id, 0x123)


class TestBitFlipInjector(unittest.TestCase):

    def test_inject_with_position(self):
        """指定位翻转 -- bit 0翻转让0x00变0x01"""
        inj = BitFlipInjector()
        frame = CANFrame(can_id=0x123, data=b"\x00\x00\x00\x00")
        config = AnomalyConfig(anomaly_type=AnomalyType.BIT_FLIP, bit_position=0)
        result = inj.inject(frame, config)
        self.assertEqual(result.data[0], 0x01)

    def test_inject_random_position(self):
        inj = BitFlipInjector()
        frame = CANFrame(can_id=0x123, data=b"\xFF\xFF\xFF\xFF")
        config = AnomalyConfig(anomaly_type=AnomalyType.BIT_FLIP)
        result = inj.inject(frame, config)
        self.assertNotEqual(result.data, b"\xFF\xFF\xFF\xFF")


class TestCRCErrorInjector(unittest.TestCase):

    def test_inject(self):
        inj = CRCErrorInjector()
        frame = CANFrame(can_id=0x123, data=b"\x01\x02\x03\x04")
        result = inj.inject(frame, AnomalyConfig(anomaly_type=AnomalyType.CRC_ERROR))
lass字段完整性$/d
        self.assertNotEqual(result.data[-1], 0x04)


class TestCANAnomalyInjector(unittest.TestCase):
    """主注入引擎"""

    def setUp(self):
        self.m_dir = _tmp.mkdtemp()
        self.m_inj = CANAnomalyInjector()

    def tearDown(self):
        if _os.path.exists(self.m_dir):
            _sh.rmtree(self.m_dir)

    def test_load_firmware(self):
        tf = _os.path.join(self.m_dir, "firmware.bin")
        with open(tf, 'wb') as f:
            f.write(b"\x00" * 100)
        self.assertTrue(self.m_inj.load_firmware(tf))

    def test_load_missing_firmware(self):
        self.assertFalse(self.m_inj.load_firmware("/nonexistent/firmware.bin"))

    def test_inject_anomaly(self):
        frame = CANFrame(can_id=0x123, data=b"\x00" * 8)
        result = self.m_inj.inject_anomaly(frame, AnomalyType.BIT_FLIP)
        self.assertIsInstance(result, InjectionResult)
        self.assertEqual(result.anomaly_type, AnomalyType.BIT_FLIP)

    def test_run_test_suite(self):
        frames = [
            CANFrame(can_id=0x123, data=b"\x00" * 8),
            CANFrame(can_id=0x456, data=b"\x11" * 8)
        ]
        result = self.m_inj.run_test_suite(frames, [AnomalyType.BIT_FLIP, AnomalyType.CRC_ERROR])
        self.assertTrue(result.success)
        self.assertEqual(result.total_injections, 4)

    def test_generate_test_frames(self):
        frames = self.m_inj.generate_test_frames([0x123, 0x456], count=2)
        self.assertEqual(len(frames), 4)
        self.assertEqual(frames[0].can_id, 0x123)

    def test_generate_report(self):
        result = CANAnalysisResult(
            success=True, total_injections=10,
            successful_injections=2, vulnerabilities=[], injection_results=[]
        )
        report = self.m_inj.generate_report(result)
        self.assertIn("CAN异常注入分析报告", report)

    def test_save_result(self):
        result = CANAnalysisResult(
            success=True, total_injections=10,
            successful_injections=2, vulnerabilities=[], injection_results=[]
        )
        out = _os.path.join(self.m_dir, "result.json")
        self.assertTrue(self.m_inj.save_result(result, out))
        self.assertTrue(_os.path.exists(out))

    def test_analyze_firmware(self):
        tf = _os.path.join(self.m_dir, "firmware.bin")
        with open(tf, 'wb') as f:
            f.write(b"\x00" * 100)
        frames = [CANFrame(can_id=0x123, data=b"\x00" * 8)]
        result = self.m_inj.analyze_firmware(tf, frames)
        self.assertTrue(result.success)


class TestVulnerabilityDataclass(unittest.TestCase):

    def test_vulnerability_creation(self):
        v = Vulnerability(
            anomaly_type=AnomalyType.BIT_FLIP, can_id=0x123,
            response_type=ResponseType.RESTART,
            severity=SeverityLevel.CRITICAL, description="测试漏洞",
            location=0x1000, recommended_fix="修复建议"
        )
        self.assertEqual(v.anomaly_type, AnomalyType.BIT_FLIP)
lass字段完整性$/d
        self.assertEqual(v.can_id, 0x123)
        self.assertEqual(v.severity, SeverityLevel.CRITICAL)


class TestCANAnalysisResultDataclass(unittest.TestCase):

    def test_can_analysis_result_creation(self):
        r = CANAnalysisResult(
            success=True, total_injections=10,
            successful_injections=5, vulnerabilities=[],
            injection_results=[], warnings=["警告"]
        )
        self.assertTrue(r.success)
        self.assertEqual(r.total_injections, 10)


if __name__ == '__main__':
    unittest.main()


