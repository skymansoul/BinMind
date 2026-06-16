"""
测试微架构侧信道验证器模块
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from modules.microarch_side_channel_validator import (
    SideChannelValidator,
    TimingProbe,
    SideChannelType,
    ExploitReliability,
    ValidationReport,
    validate_spectre,
    validate_meltdown
)


class TestTimingProbe(unittest.TestCase):
    """测试时序探测"""
    
    def test_probe_init(self):
        """测试探测初始化"""
        probe = TimingProbe()
        self.assertEqual(probe.cache_line_size, 64)
    
    def test_measure_access_time(self):
        """测试测量访问时间"""
        probe = TimingProbe()
        access_time = probe.measure_access_time(0x1000)
        self.assertIsInstance(access_time, (int, float))
        self.assertGreater(access_time, 0)
    
    def test_flush_cache(self):
        """测试刷新缓存"""
        probe = TimingProbe()
        # 应该不会抛出异常
        probe.flush_cache(0x1000)
    
    def test_is_cache_hit(self):
        """测试缓存命中判断"""
        probe = TimingProbe()
        result = probe.is_cache_hit(0x1000)
        self.assertIsInstance(result, bool)


class TestSideChannelValidator(unittest.TestCase):
    """测试侧信道验证器"""
    
    def test_validator_init(self):
        """测试验证器初始化"""
        validator = SideChannelValidator()
        self.assertIsNotNone(validator.probe)
        self.assertIsNotNone(validator.hardware_info)
    
    def test_detect_hardware(self):
        """测试硬件检测"""
        validator = SideChannelValidator()
        self.assertIn('platform', validator.hardware_info)
        self.assertIn('cpu_count', validator.hardware_info)
    
    def test_run_spectre_test(self):
        """测试运行Spectre测试"""
        validator = SideChannelValidator()
        secret_data = b'Hello, World!'
        report = validator.run_spectre_test(0x1000, secret_data, iterations=100)
        
        self.assertIsInstance(report, ValidationReport)
        self.assertEqual(report.exploit_type, SideChannelType.SPECTRE_V1)
        self.assertEqual(report.target_address, 0x1000)
        self.assertGreater(report.total_bits_leaked, 0)
        self.assertIsInstance(report.accuracy, float)
        self.assertIsInstance(report.reliability, ExploitReliability)
    
    def test_run_meltdown_test(self):
        """测试运行Meltdown测试"""
        validator = SideChannelValidator()
        report = validator.run_meltdown_test(0xffff800000000000, iterations=50)
        
        self.assertIsInstance(report, ValidationReport)
        self.assertEqual(report.exploit_type, SideChannelType.MELTDOWN)
        self.assertEqual(report.total_bits_leaked, 64)
    
    def test_calculate_reliability(self):
        """测试可靠性计算"""
        validator = SideChannelValidator()
        
        self.assertEqual(validator._calculate_reliability(0.95), ExploitReliability.VERY_HIGH)
        self.assertEqual(validator._calculate_reliability(0.75), ExploitReliability.HIGH)
        self.assertEqual(validator._calculate_reliability(0.5), ExploitReliability.MEDIUM)
        self.assertEqual(validator._calculate_reliability(0.25), ExploitReliability.LOW)
        self.assertEqual(validator._calculate_reliability(0.05), ExploitReliability.VERY_LOW)
        self.assertEqual(validator._calculate_reliability(0.0), ExploitReliability.UNDETERMINED)
    
    def test_generate_notes(self):
        """测试生成备注"""
        validator = SideChannelValidator()
        notes = validator._generate_notes(0.95, ExploitReliability.VERY_HIGH)
        self.assertIsInstance(notes, list)
        self.assertGreater(len(notes), 0)
    
    def test_generate_report_text(self):
        """测试生成报告文本"""
        validator = SideChannelValidator()
        secret_data = b'Test'
        report = validator.run_spectre_test(0x1000, secret_data, iterations=50)
        
        report_text = validator.generate_report_text(report)
        self.assertIsInstance(report_text, str)
        self.assertIn("微架构侧信道利用验证报告", report_text)
        # 检查准确率是否在报告中（格式化后的形式）
        self.assertIn(f"{report.accuracy:.2%}", report_text)


class TestConvenienceFunctions(unittest.TestCase):
    """测试便捷函数"""
    
    def test_validate_spectre(self):
        """测试验证Spectre"""
        report = validate_spectre(0x1000, b'Test', iterations=50)
        self.assertIsInstance(report, ValidationReport)
    
    def test_validate_meltdown(self):
        """测试验证Meltdown"""
        report = validate_meltdown(0xffff800000000000, iterations=50)
        self.assertIsInstance(report, ValidationReport)


if __name__ == '__main__':
    unittest.main()