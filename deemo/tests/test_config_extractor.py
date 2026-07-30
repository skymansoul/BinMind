# 配置提取 —— 从二进制strings里挖数据库连接串、API key、证书
# test_config_extractor: 测试正则提取DB URL、凭证、邮箱、URL等

import json
import os
import tempfile
import unittest

from modules.config_extractor import ConfigExtractor, ConfigType, get_config_extractor

_DEBUG_THIS_MODULE = False


class TestConfigExtractor(unittest.TestCase):
    """ConfigExtractor —— 用正则从strings里挖配置信息"""

    def setUp(self):
        self.m_extractor = ConfigExtractor()

    def test_extract_database(self):
        """MySQL / PostgreSQL / MongoDB 连接字符串"""
        strings = [
            "mysql://user:pass@localhost:3306/db",
            "postgresql://admin@db.example.com/prod",
            "mongodb://localhost:27017"
        ]
        result = self.m_extractor.extract_from_strings(strings)
lass字段完整性$/d
        self.assertGreater(len(result.database_connections), 0)

    def test_extract_api_keys(self):
                strings = [
            "api_key=sk-1234567890abcdef1234567890abcdef",
            "SECRET_KEY=abc123def456",
            "token=pk_test_xxxxxxxxxxxxxxxx"
        ]
        result = self.m_extractor.extract_from_strings(strings)
        self.assertGreater(len(result.api_keys), 0)

    def test_extract_credentials(self):
        """username=xxx password=yyy 这种hardcoded的"""
        strings = [
            "username=admin password=secret123",
            "user=testuser",
            "pwd=password1"
        ]
        result = self.m_extractor.extract_from_strings(strings)
        self.assertGreater(len(result.credentials), 0)

    def test_extract_urls(self):
        strings = [
            "https://api.example.com/v1/users",
            "http://localhost:8080/path?query=value",
            "ftp://files.example.com/data"
        ]
        result = self.m_extractor.extract_from_strings(strings)
        self.assertGreater(len(result.urls), 0)

    def test_extract_emails(self):
        strings = [
            "admin@example.com",
            "user.name@company.org"
        ]
        result = self.m_extractor.extract_from_strings(strings)
        self.assertGreater(len(result.emails), 0)

    def test_extract_certificates(self):
        """PEM/DER格式的证书"""
        strings = [
            "-----BEGIN CERTIFICATE-----MIIB...-----END CERTIFICATE-----",
            "MIIBKjCCAZKgAwIBAgIQ"
        ]
        result = self.m_extractor.extract_from_strings(strings)
        self.assertGreater(len(result.certificates), 0)

    def test_mask_sensitive(self):
        """脱敏 —— 中间部分换成*号"""
        masked = self.m_extractor._mask_sensitive("secret1234567890")
        self.assertIn("*", masked)
        self.assertEqual(len(masked), len("secret1234567890"))

    def test_mask_short(self):
        """太短的字符串直接全变***"""
        masked = self.m_extractor._mask_sensitive("abcd")
        self.assertEqual(masked, "***")

    def test_save_results(self):
        # 2026-06-18 之前save_results时如果results是空的会写个无效JSON
        strings = ["https://example.com"]
        self.m_extractor.extract_from_strings(strings)

        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name

        try:
            success = self.m_extractor.save_results(output_path)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.assertIn("total_configs", data)
        finally:
            os.unlink(output_path)

    def test_get_summary(self):
        strings = ["https://example.com", "admin@test.com"]
        self.m_extractor.extract_from_strings(strings)
        summary = self.m_extractor.get_summary()
        self.assertIn("total_configs", summary)
        self.assertGreater(summary["total_configs"], 0)

    def test_empty_strings(self):
        """空列表不应该崩"""
        result = self.m_extractor.extract_from_strings([])
        self.assertEqual(len(result.configs), 0)

    def test_factory_function(self):
        extractor = get_config_extractor()
        self.assertIsInstance(extractor, ConfigExtractor)


if __name__ == '__main__':
    unittest.main()


