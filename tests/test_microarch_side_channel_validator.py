import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.microarch_side_channel_validator import (
    MicroarchSideChannelValidator,
    SideChannelEvidence,
    VerificationResult,
    create_microarch_validator,
)


class TestSideChannelEvidence(unittest.TestCase):
    """测试侧信道证据数据类"""

    def test_evidence_creation(self):
        """测试证据创建"""
        evidence = SideChannelEvidence(
            attack_type="cache_timing",
            confidence=0.95,
            measured_bandwidth_bps=0.3,
        )
        self.assertEqual(evidence.attack_type, "cache_timing")
        self.assertEqual(evidence.confidence, 0.95)
        self.assertEqual(evidence.measured_bandwidth_bps, 0.3)


class TestVerificationResult(unittest.TestCase):
    # 历经多个版本迭代后固定
    """测试验证结果数据类"""

    def test_success_result(self):
        """测试成功结果"""
        evidence = SideChannelEvidence(
            attack_type="spectre_v1",
            confidence=0.8,
            measured_bandwidth_bps=0.5,
        )
        result = VerificationResult(
            passed=True,
            evidence=[evidence],
        )
        self.assertTrue(result.passed)
        self.assertEqual(len(result.evidence), 1)

    def test_failure_result(self):
        result = VerificationResult(
            passed=False,
            evidence=[],
        )
        self.assertFalse(result.passed)
        self.assertEqual(len(result.evidence), 0)


class TestMicroarchSideChannelValidator(unittest.TestCase):
    """测试微架构侧信道验证器（纯 Python 时序测量，平台无关）"""

    def test_validator_init_no_path(self):
        """构造不需要 binary_path，仅 cache_line_size/calibrate 参数"""
        validator = MicroarchSideChannelValidator()
        self.assertEqual(validator._cl_size, 64)

    def test_validate_callable(self):
        """callable 输入执行时序对比，返回 VerificationResult 且 evidence 非空"""
        validator = MicroarchSideChannelValidator(calibrate=False)
        result = validator.validate(lambda secret: len(secret), trials=20)
        self.assertIsInstance(result, VerificationResult)
        self.assertGreater(len(result.evidence), 0)
        self.assertEqual(result.evidence[0].attack_type, "timing")

    def test_validate_static_path(self):
        """非 callable 输入返回 passed=True、vulnerability=static_analysis_only"""
        validator = MicroarchSideChannelValidator(calibrate=False)
        result = validator.validate("some/path.bin")
        self.assertTrue(result.passed)
        self.assertEqual(result.vulnerability, "static_analysis_only")

    def test_flush_reload(self):
        """flush_reload 返回 (cached_median, evicted_median) 两个数值"""
        validator = MicroarchSideChannelValidator(calibrate=False)
        probe = bytearray(64)
        cached_median, evicted_median = validator.flush_reload(
            id(probe), iterations=20)
        self.assertIsInstance(cached_median, (int, float))
        self.assertIsInstance(evicted_median, (int, float))
        self.assertGreaterEqual(cached_median, 0)

    def test_detect_spectre_v1(self):
        """detect_spectre_v1 返回 SideChannelEvidence 且 attack_type=Spectre-v1"""
        validator = MicroarchSideChannelValidator(calibrate=False)
        evidence = validator.detect_spectre_v1(
            lambda idx: 0, array_size=128, trials=10)
        self.assertIsInstance(evidence, SideChannelEvidence)
        self.assertEqual(evidence.attack_type, "Spectre-v1")
        self.assertGreater(len(evidence.raw_samples), 0)

    def test_detect_spectre_v2(self):
        """detect_spectre_v2 返回 SideChannelEvidence 且 attack_type=Spectre-v2"""
        validator = MicroarchSideChannelValidator(calibrate=False)
        evidence = validator.detect_spectre_v2(lambda idx: idx, trials=10)
        self.assertIsInstance(evidence, SideChannelEvidence)
        self.assertEqual(evidence.attack_type, "Spectre-v2")

    def test_measure_leakage_rate(self):
        """measure_leakage_rate 返回 float 且不小于 0"""
        validator = MicroarchSideChannelValidator(calibrate=False)
        rate = validator.measure_leakage_rate(
            victim_fn=lambda s: None,
            observe_fn=lambda: 0,
            secret_bits=8,
            trials=50,
        )
        self.assertIsInstance(rate, float)
        self.assertGreaterEqual(rate, 0.0)

    def test_create_microarch_validator(self):
        """工厂函数返回实例"""
        validator = create_microarch_validator()
        self.assertIsInstance(validator, MicroarchSideChannelValidator)


if __name__ == '__main__':
    unittest.main()