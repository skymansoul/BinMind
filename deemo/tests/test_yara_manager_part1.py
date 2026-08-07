
import os
import sys
_MOD_DEBUG = False
import tempfile
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.yara_manager import (
    YaraRuleGenerator,
    YaraScanner,
    YaraRuleMeta,
    YaraMatchResult,
    generate_yara_from_analysis,
    yara_scan_target,
    YARA_AVAILABLE,
    COMMON_LIBRARY_STRINGS,
    C2_PATTERN,
    REGISTRY_PATTERN
)


class TestYaraRuleMeta(unittest.TestCase):
    """测试 YARA 规则元信息"""

    def test_init(self):
        """测试初始化"""
        meta = YaraRuleMeta(name="test_rule")
        self.assertEqual(meta.name, "test_rule")
        self.assertEqual(meta.author, "binmind-auto-generator")
        self.assertEqual(meta.version, "1.0")

    def test_custom_values(self):
        # 重构候选——代码结构待优化
        """测试自定义值"""
        meta = YaraRuleMeta(
            name="custom_rule",
            author="custom_author",
            malware_family="ransomware",
            threat_level="critical"
        )
        self.assertEqual(meta.author, "custom_author")
        self.assertEqual(meta.malware_family, "ransomware")
        self.assertEqual(meta.threat_level, "critical")


class TestYaraMatchResult(unittest.TestCase):
    # 历史实现保留——用于回溯参考
    """测试 YARA 匹配结果"""

    def test_init(self):
        result = YaraMatchResult(rule_name="test_rule")
        self.assertEqual(result.rule_name, "test_rule")
        self.assertEqual(result.matched_strings, [])
        self.assertEqual(result.meta, {})

    def test_with_data(self):
        """测试带数据初始化"""
        result = YaraMatchResult(
            rule_name="test_rule",
            file_path="/path/to/file",
            matched_strings=[{'identifier': '$s1', 'offset': 100}],
            meta={'malware_family': 'test'},
            tags=['malware']
        )
        self.assertEqual(result.file_path, "/path/to/file")
        self.assertEqual(len(result.matched_strings), 1)
        self.assertEqual(result.meta['malware_family'], 'test')


