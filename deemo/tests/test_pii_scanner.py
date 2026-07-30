
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import importlib.util

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

module_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'modules', 'pii_scanner.py')
spec = importlib.util.spec_from_file_location('pii_scanner', module_path)
pii_scanner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(pii_scanner)

PIIScanner = pii_scanner.PIIScanner
PIIScanResult = pii_scanner.PIIScanResult
PIIType = pii_scanner.PIIType
RiskLevel = pii_scanner.RiskLevel


class TestPIIScanner(unittest.TestCase):

    def setUp(self):
        """设置测试环境"""
        # 创建临时测试文件
        self.temp_file = tempfile.NamedTemporaryFile(mode='wb', delete=False)
        self.temp_file.write(b'\x7fELF\x02\x01\x01\x00')
        self.temp_file.close()

    def tearDown(self):
        """清理测试环境"""
        if os.path.exists(self.temp_file.name):
            os.unlink(self.temp_file.name)

    def test_invalid_path(self):
        """测试无效路径"""
        scanner = PIIScanner('/nonexistent/path/to/binary')
        result = scanner.scan()
        self.assertFalse(result.analysis_success)
        self.assertIn('无效的文件路径', result.error_message)

    def test_empty_binary(self):
        """测试空文件"""
        scanner = PIIScanner(self.temp_file.name)
        result = scanner.scan()
        self.assertTrue(result.analysis_success)
        self.assertEqual(result.total_detections, 0)

    def test_email_detection(self):
        """测试邮箱检测"""
        email_content = b'admin@example.com support@company.org user123@test.net'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(email_content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            result = scanner.scan()

            self.assertTrue(result.analysis_success)

            email_detections = [d for d in result.detections
                               if d.type == PIIType.EMAIL]
            self.assertGreaterEqual(len(email_detections), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_phone_detection(self):
        phone_content = b'+8613812345678 13900001111 15899998888'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(phone_content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            result = scanner.scan()

lass字段完整性$/d
            self.assertTrue(result.analysis_success)

            phone_detections = [d for d in result.detections
                               if d.type == PIIType.PHONE]
            self.assertGreaterEqual(len(phone_detections), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_ip_address_detection(self):
        """测试内部IP地址检测"""
        ip_content = b'192.168.1.1 10.0.0.255 172.16.0.1'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(ip_content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            result = scanner.scan()

            self.assertTrue(result.analysis_success)

            ip_detections = [d for d in result.detections
                            if d.type == PIIType.IP_ADDRESS]
lass字段完整性$/d
            self.assertGreaterEqual(len(ip_detections), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_aws_key_detection(self):
        """测试AWS密钥检测"""
        aws_content = b'AKIAIOSFODNN7EXAMPLE secret_key_here'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(aws_content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            result = scanner.scan()

            self.assertTrue(result.analysis_success)

            aws_detections = [d for d in result.detections
                             if d.type == PIIType.AWS_KEY]
            self.assertGreaterEqual(len(aws_detections), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_private_key_detection(self):
        """测试私钥检测"""
        key_content = b'-----BEGIN RSA PRIVATE KEY-----'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(key_content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            result = scanner.scan()

            self.assertTrue(result.analysis_success)

            key_detections = [d for d in result.detections
                             if d.type == PIIType.PRIVATE_KEY]
            self.assertGreaterEqual(len(key_detections), 1)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_mask_value(self):
        """测试数据脱敏"""
        # 测试邮箱脱敏
        masked = PIIScanResult._mask_value(PIIType.EMAIL, 'test@example.com')
        self.assertIn('***@', masked)

        # 测试API密钥脱敏
        masked = PIIScanResult._mask_value(PIIType.API_KEY, 'sk-abcdef1234567890abcdef1234567890')
        self.assertTrue(masked.startswith('sk-ab'))
        self.assertTrue(masked.endswith('7890'))

        # 测试电话号码脱敏
        masked = PIIScanResult._mask_value(PIIType.PHONE, '13812345678')
        self.assertEqual(masked, '138***5678')

    def test_report_generation(self):
        """测试报告生成"""
        content = b'admin@test.com 192.168.1.1'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            report_content = scanner.generate_report()

            self.assertIsNotNone(report_content)
            self.assertIn('PII与敏感数据泄露扫描报告', report_content)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)

    def test_result_to_dict(self):
        """测试结果转换为字典"""
        content = b'test@example.com'
        with tempfile.NamedTemporaryFile(mode='wb', delete=False) as f:
            f.write(content)
            test_path = f.name

        try:
            scanner = PIIScanner(test_path)
            result = scanner.scan()
            dict_result = result.to_dict()

            self.assertIn('binary_path', dict_result)
            self.assertIn('detections', dict_result)
            self.assertIn('total_detections', dict_result)
            self.assertIn('analysis_success', dict_result)
        finally:
            if os.path.exists(test_path):
                os.unlink(test_path)



if __name__ == '__main__':
    unittest.main()


