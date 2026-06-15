import unittest
import os
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.config_extractor import ConfigExtractor, ConfigType, get_config_extractor


class TestConfigExtractor(unittest.TestCase):
    """测试配置提取器"""

    def setUp(self):
        """设置测试环境"""
        self.extractor = ConfigExtractor()

    def test_extract_database(self):
        """测试提取数据库连接字符串"""
        strings = [
            "mysql://user:pass@localhost:3306/db",
            "postgresql://admin@db.example.com/prod",
            "mongodb://localhost:27017"
        ]
        result = self.extractor.extract_from_strings(strings)
        self.assertGreater(len(result.database_connections), 0)

    def test_extract_api_keys(self):
        """测试提取API密钥"""
        strings = [
            "api_key=sk-1234567890abcdef1234567890abcdef",
            "SECRET_KEY=abc123def456",
            "token=pk_test_xxxxxxxxxxxxxxxx"
        ]
        result = self.extractor.extract_from_strings(strings)
        self.assertGreater(len(result.api_keys), 0)

    def test_extract_credentials(self):
        """测试提取凭据"""
        strings = [
            "username=admin password=secret123",
            "user=testuser",
            "pwd=password1"
        ]
        result = self.extractor.extract_from_strings(strings)
        self.assertGreater(len(result.credentials), 0)

    def test_extract_urls(self):
        """测试提取URL"""
        strings = [
            "https://api.example.com/v1/users",
            "http://localhost:8080/path?query=value",
            "ftp://files.example.com/data"
        ]
        result = self.extractor.extract_from_strings(strings)
        self.assertGreater(len(result.urls), 0)

    def test_extract_emails(self):
        """测试提取邮箱"""
        strings = [
            "admin@example.com",
            "user.name@company.org"
        ]
        result = self.extractor.extract_from_strings(strings)
        self.assertGreater(len(result.emails), 0)

    def test_extract_certificates(self):
        """测试提取证书"""
        strings = [
            "-----BEGIN CERTIFICATE-----MIIB...-----END CERTIFICATE-----",
            "MIIBKjCCAZKgAwIBAgIQ"
        ]
        result = self.extractor.extract_from_strings(strings)
        self.assertGreater(len(result.certificates), 0)

    def test_mask_sensitive(self):
        """测试敏感数据脱敏"""
        masked = self.extractor._mask_sensitive("secret1234567890")
        self.assertIn("*", masked)
        self.assertEqual(len(masked), len("secret1234567890"))

    def test_mask_short(self):
        """测试短字符串脱敏"""
        masked = self.extractor._mask_sensitive("abcd")
        self.assertEqual(masked, "***")

    def test_save_results(self):
        """测试保存结果"""
        import tempfile
        import json
        strings = ["https://example.com"]
        self.extractor.extract_from_strings(strings)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            output_path = f.name
        
        try:
            success = self.extractor.save_results(output_path)
            self.assertTrue(success)
            self.assertTrue(os.path.exists(output_path))
            with open(output_path, 'r', encoding='utf-8') as f:
                data = json.load(f)
                self.assertIn("total_configs", data)
        finally:
            os.unlink(output_path)

    def test_get_summary(self):
        """测试获取摘要"""
        strings = ["https://example.com", "admin@test.com"]
        self.extractor.extract_from_strings(strings)
        summary = self.extractor.get_summary()
        self.assertIn("total_configs", summary)
        self.assertGreater(summary["total_configs"], 0)

    def test_empty_strings(self):
        """测试空字符串列表"""
        result = self.extractor.extract_from_strings([])
        self.assertEqual(len(result.configs), 0)

    def test_factory_function(self):
        """测试工厂函数"""
        extractor = get_config_extractor()
        self.assertIsInstance(extractor, ConfigExtractor)


if __name__ == '__main__':
    unittest.main()