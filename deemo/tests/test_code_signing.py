#!/usr/bin/env python3
"""
代码签名验证模块单元测试

测试代码签名验证器的各项功能。
"""

import os
import sys
import unittest
import tempfile
import json
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.code_signing import (
    CodeSigningChecker, SigningConfig, CertificateInfo, SignatureResult,
    SignatureStatus, AlgorithmStrength,
    create_signing_checker
)


class TestSigningConfig(unittest.TestCase):
    """
    测试签名验证配置类
    """
    
    def test_config_init(self):
        """
        测试配置初始化
        """
        config = SigningConfig()
        self.assertTrue(config.check_revocation)
        self.assertTrue(config.check_leaked_db)
        self.assertTrue(config.verify_chain)
    
    def test_config_custom_values(self):
        """
        测试自定义配置值
        """
        config = SigningConfig(
            check_revocation=False,
            check_leaked_db=False,
            leaked_db_path='/custom/leaked.json',
            weak_algorithms=['md5', 'sha1', 'sha256_weak']
        )
        self.assertFalse(config.check_revocation)
        self.assertFalse(config.check_leaked_db)
        self.assertEqual(config.leaked_db_path, '/custom/leaked.json')
    
    def test_config_validation(self):
        """
        测试配置验证
        """
        config = SigningConfig()
        self.assertTrue(config.validate())


class TestCertificateInfo(unittest.TestCase):
    """
    测试证书信息数据类
    """
    
    def test_certificate_info_init(self):
        """
        测试证书信息初始化
        """
        cert = CertificateInfo(
            subject='CN=Test Cert',
            issuer='CN=Test CA',
            serial_number='123456',
            algorithm='sha256RSA',
            is_self_signed=False,
            is_trusted=True
        )
        self.assertEqual(cert.subject, 'CN=Test Cert')
        self.assertEqual(cert.algorithm, 'sha256RSA')
        self.assertFalse(cert.is_self_signed)
    
    def test_certificate_info_to_dict(self):
        """
        测试证书信息转换为字典
        """
        cert = CertificateInfo(subject='Test')
        cert_dict = cert.to_dict()
        self.assertIsInstance(cert_dict, dict)
        self.assertEqual(cert_dict['subject'], 'Test')
    
    def test_certificate_is_expired(self):
        """
        测试证书过期检查
        """
        # 过期证书
        cert = CertificateInfo(not_after='2020-01-01 00:00:00')
        self.assertTrue(cert.is_expired())
        
        # 有效证书
        cert = CertificateInfo(not_after='2030-01-01 00:00:00')
        self.assertFalse(cert.is_expired())


class TestSignatureResult(unittest.TestCase):
    """
    测试签名验证结果数据类
    """
    
    def test_signature_result_init(self):
        """
        测试签名结果初始化
        """
        result = SignatureResult(
            status=SignatureStatus.VALID,
            algorithm_strength=AlgorithmStrength.STRONG,
            file_hash='abc123',
            is_abused=False
        )
        self.assertEqual(result.status, SignatureStatus.VALID)
        self.assertEqual(result.algorithm_strength, AlgorithmStrength.STRONG)
    
    def test_signature_result_to_dict(self):
        """
        测试签名结果转换为字典
        """
        result = SignatureResult(status=SignatureStatus.UNSIGNED)
        result_dict = result.to_dict()
        self.assertIsInstance(result_dict, dict)
        self.assertEqual(result_dict['status'], 'unsigned')


class TestSignatureStatus(unittest.TestCase):
    """
    测试签名状态枚举
    """
    
    def test_status_values(self):
        """
        测试状态值
        """
        self.assertEqual(SignatureStatus.VALID.value, 'valid')
        self.assertEqual(SignatureStatus.INVALID.value, 'invalid')
        self.assertEqual(SignatureStatus.EXPIRED.value, 'expired')
        self.assertEqual(SignatureStatus.LEAKED.value, 'leaked')


class TestAlgorithmStrength(unittest.TestCase):
    """
    测试算法强度枚举
    """
    
    def test_strength_values(self):
        """
        测试强度值
        """
        self.assertEqual(AlgorithmStrength.STRONG.value, 'strong')
        self.assertEqual(AlgorithmStrength.WEAK.value, 'weak')
        self.assertEqual(AlgorithmStrength.DEPRECATED.value, 'deprecated')


class TestCodeSigningChecker(unittest.TestCase):
    """
    测试代码签名验证器类
    """
    
    def setUp(self):
        """
        设置测试环境
        """
        self.temp_dir = tempfile.mkdtemp()
        self.config = SigningConfig(
            leaked_db_path=os.path.join(self.temp_dir, 'leaked_certs.json')
        )
        
        # 创建包含已知泄露证书的数据库
        leaked_serials = CodeSigningChecker.KNOWN_LEAKED_CERTS.copy()
        with open(self.config.leaked_db_path, 'w', encoding='utf-8') as f:
            json.dump({'serial_numbers': leaked_serials}, f)
        
        self.checker = CodeSigningChecker(self.config)
    
    def tearDown(self):
        """
        清理测试环境
        """
        import shutil
        shutil.rmtree(self.temp_dir, ignore_errors=True)
    
    def test_checker_init(self):
        """
        测试验证器初始化
        """
        self.assertIsInstance(self.checker, CodeSigningChecker)
        self.assertEqual(self.checker.config.check_revocation, True)
    
    def test_get_algorithm_strength(self):
        """
        测试获取算法强度
        """
        # 强算法
        strength = self.checker._get_algorithm_strength('sha256RSA')
        self.assertEqual(strength, AlgorithmStrength.STRONG)
        
        # 弱算法
        strength = self.checker._get_algorithm_strength('sha1RSA')
        self.assertEqual(strength, AlgorithmStrength.WEAK)
        
        # 已弃用算法
        strength = self.checker._get_algorithm_strength('md5RSA')
        self.assertEqual(strength, AlgorithmStrength.DEPRECATED)
    
    def test_check_leaked_certificate(self):
        """
        测试泄露证书检查
        """
        cert = CertificateInfo(serial_number='not_leaked')
        self.assertFalse(self.checker._check_leaked_certificate(cert))
        
        # 使用已知泄露的序列号
        cert = CertificateInfo(serial_number=self.checker.KNOWN_LEAKED_CERTS[0])
        self.assertTrue(self.checker._check_leaked_certificate(cert))
    
    def test_check_abuse_patterns(self):
        """
        测试滥用模式检查
        """
        certs = [CertificateInfo(subject='D-Link Corporation')]
        indicators = self.checker._check_abuse_patterns(certs)
        self.assertGreater(len(indicators), 0)
    
    def test_check_signature_unsigned_file(self):
        """
        测试未签名文件检查
        """
        # 创建一个简单的测试文件
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test content')
        
        result = self.checker.check_signature(test_file)
        self.assertEqual(result.status, SignatureStatus.UNSIGNED)
    
    def test_generate_recommendation(self):
        """
        测试生成建议
        """
        # 有效签名
        result = SignatureResult(status=SignatureStatus.VALID)
        recommendation = self.checker._generate_recommendation(result)
        self.assertIn('有效', recommendation)
        
        # 过期签名
        result = SignatureResult(status=SignatureStatus.EXPIRED)
        recommendation = self.checker._generate_recommendation(result)
        self.assertIn('过期', recommendation)
        
        # 泄露签名
        result = SignatureResult(status=SignatureStatus.LEAKED)
        recommendation = self.checker._generate_recommendation(result)
        self.assertIn('泄露', recommendation)
    
    def test_generate_report(self):
        """
        测试生成报告
        """
        result = SignatureResult(
            status=SignatureStatus.VALID,
            file_hash='abc123',
            certificates=[CertificateInfo(subject='Test')]
        )
        
        report = self.checker.generate_report(result, 'test.exe')
        self.assertIsInstance(report, dict)
        self.assertIn('signature_status', report)
        self.assertIn('recommendation', report)
    
    def test_save_report(self):
        """
        测试保存报告
        """
        result = SignatureResult(status=SignatureStatus.UNSIGNED)
        test_file = os.path.join(self.temp_dir, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')
        
        report_path = self.checker.save_report(result, test_file)
        self.assertTrue(os.path.exists(report_path))


class TestCodeSigningCheckerFunctions(unittest.TestCase):
    """
    测试代码签名验证器便捷函数
    """
    
    def test_create_signing_checker(self):
        """
        测试创建验证器便捷函数
        """
        checker = create_signing_checker()
        self.assertIsInstance(checker, CodeSigningChecker)


if __name__ == '__main__':
    unittest.main(verbosity=2)