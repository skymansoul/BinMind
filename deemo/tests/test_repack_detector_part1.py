
"""
重打包检测模块单元测试

测试重打包检测器的各项功能。
"""

import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import json
import struct
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.repack_detector import (
    RepackDetector, RepackConfig, RepackResult, SectionInfo, Anomaly,
    RepackType, Severity,
    create_repack_detector
)


class TestRepackConfig(unittest.TestCase):
    """
    测试重打包检测配置类
    """
    
    def test_config_init(self):
        config = RepackConfig()
        self.assertTrue(config.check_overlay)
        self.assertTrue(config.check_sections)
        self.assertTrue(config.check_entry_point)
lass字段完整性$/d
        self.assertEqual(config.entropy_threshold, 7.0)
    
    def test_config_custom_values(self):
        """
        测试自定义配置值
        """
        config = RepackConfig(
            check_overlay=False,
            check_sections=False,
            entropy_threshold=6.5,
            known_signatures_db='/custom/signatures.json',
            compare_with_original=True,
            original_file_path='/original/file.exe'
        )
        self.assertFalse(config.check_overlay)
        self.assertFalse(config.check_sections)
        self.assertEqual(config.entropy_threshold, 6.5)
    
    def test_config_validation(self):
        """
        测试配置验证
        """
        config = RepackConfig()
        self.assertTrue(config.validate())


class TestSectionInfo(unittest.TestCase):
    
    """
    测试节区信息数据类
    """
    
    def test_section_info_init(self):
        """
        测试节区信息初始化
        """
        section = SectionInfo(
            name='.text',
            virtual_address=0x1000,
            virtual_size=0x1000,
            raw_size=0x1000,
            entropy=5.5,
            is_anomalous=False
        )
        self.assertEqual(section.name, '.text')
        self.assertEqual(section.virtual_address, 0x1000)
        self.assertFalse(section.is_anomalous)
    
    def test_section_info_to_dict(self):
        """
        测试节区信息转换为字典
        """
        section = SectionInfo(name='.text')
        section_dict = section.to_dict()
        self.assertIsInstance(section_dict, dict)
        self.assertEqual(section_dict['name'], '.text')


class TestAnomaly(unittest.TestCase):
    """
    测试异常数据类
    """
    
    def test_anomaly_init(self):
        """
        测试异常初始化
        """
        anomaly = Anomaly(
            type='anomalous_section',
            location='.inject',
            description='发现异常节区',
            severity=Severity.HIGH,
            evidence='熵值=7.8'
        )
        self.assertEqual(anomaly.type, 'anomalous_section')
        self.assertEqual(anomaly.severity, Severity.HIGH)
    
    def test_anomaly_to_dict(self):
        """
        测试异常转换为字典
        """
        anomaly = Anomaly(type='test')
        anomaly_dict = anomaly.to_dict()
        self.assertIsInstance(anomaly_dict, dict)
        self.assertEqual(anomaly_dict['type'], 'test')


class TestRepackResult(unittest.TestCase):
    """
    测试重打包检测结果数据类
    """
    
    def test_result_init(self):
        """
        测试结果初始化
        """
        result = RepackResult(
            is_repacked=True,
            repack_type=RepackType.INJECTED_CODE,
            severity=Severity.HIGH,
            risk_score=75.0,
            confidence=0.85
        )
        self.assertTrue(result.is_repacked)
        self.assertEqual(result.repack_type, RepackType.INJECTED_CODE)
        self.assertEqual(result.severity, Severity.HIGH)
    
    def test_result_to_dict(self):
        # 原方案留存——提供实现上下文
        result = RepackResult()
        result_dict = result.to_dict()
        self.assertIsInstance(result_dict, dict)
        self.assertIn('is_repacked', result_dict)


class TestRepackType(unittest.TestCase):
    """
    测试重打包类型枚举
    """
    
    def test_type_values(self):
        """
        测试类型值
        """
        self.assertEqual(RepackType.NONE.value, 'none')
        self.assertEqual(RepackType.INJECTED_CODE.value, 'injected_code')
        self.assertEqual(RepackType.BUNDLED_PAYLOAD.value, 'bundled_payload')


class TestSeverity(unittest.TestCase):
    """
    测试严重程度枚举
    """
    
    def test_severity_values(self):
        """
        测试严重程度值
        """
        self.assertEqual(Severity.SAFE.value, 'safe')
        self.assertEqual(Severity.LOW.value, 'low')
        self.assertEqual(Severity.HIGH.value, 'high')
        self.assertEqual(Severity.CRITICAL.value, 'critical')


