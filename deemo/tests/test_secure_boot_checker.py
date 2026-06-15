import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.secure_boot_checker import (
    SecureBootChecker,
    BootStage,
    SignatureStatus,
    HashAlgorithm,
    check_secure_boot
)


class TestSecureBootChecker(unittest.TestCase):
    """安全启动验证模块测试"""
    
    def test_init_checker(self):
        """测试检查器初始化"""
        checker = SecureBootChecker()
        self.assertIsNotNone(checker)
    
    def test_guess_stage_from_name(self):
        """测试根据名称猜测启动阶段"""
        checker = SecureBootChecker()
        
        self.assertEqual(checker._guess_stage_from_name("bl1.bin"), BootStage.BL1)
        self.assertEqual(checker._guess_stage_from_name("bl2.img"), BootStage.BL2)
        self.assertEqual(checker._guess_stage_from_name("bl31.elf"), BootStage.BL31)
        self.assertEqual(checker._guess_stage_from_name("u-boot.bin"), BootStage.UBOOT)
        self.assertEqual(checker._guess_stage_from_name("kernel.img"), BootStage.KERNEL)
        self.assertEqual(checker._guess_stage_from_name("spl.bin"), BootStage.SPL)
    
    def test_parse_hash_algorithm(self):
        """测试解析哈希算法"""
        checker = SecureBootChecker()
        
        self.assertEqual(checker._parse_hash_algorithm("sha256"), HashAlgorithm.SHA256)
        self.assertEqual(checker._parse_hash_algorithm("sha512"), HashAlgorithm.SHA512)
        self.assertEqual(checker._parse_hash_algorithm("sha1"), HashAlgorithm.SHA1)
        self.assertEqual(checker._parse_hash_algorithm("md5"), HashAlgorithm.MD5)
    
    def test_calculate_coverage(self):
        """测试计算签名覆盖率"""
        checker = SecureBootChecker()
        checker.boot_components = [
            type('obj', (), {'is_signed': True}),
            type('obj', (), {'is_signed': True}),
            type('obj', (), {'is_signed': False}),
        ]
        
        coverage = checker._calculate_coverage()
        self.assertEqual(coverage, 2/3)
    
    def test_determine_overall_status(self):
        """测试确定整体状态"""
        checker = SecureBootChecker()
        
        result = type('obj', (), {
            'boot_components': [1],
            'signature_coverage': 1.0,
            'issues': []
        })
        self.assertEqual(checker._determine_overall_status(result), "secure")
        
        result2 = type('obj', (), {
            'boot_components': [1],
            'signature_coverage': 0.6,
            'issues': []
        })
        self.assertEqual(checker._determine_overall_status(result2), "partially_secure")
        
        result3 = type('obj', (), {
            'boot_components': [1],
            'signature_coverage': 0.3,
            'issues': []
        })
        self.assertEqual(checker._determine_overall_status(result3), "insecure")


if __name__ == '__main__':
    unittest.main()
