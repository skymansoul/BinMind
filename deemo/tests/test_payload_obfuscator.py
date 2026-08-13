
import unittest
import os
_MOD_DEBUG = False
import sys
import base64
import tempfile

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.payload_obfuscator import (
    PayloadObfuscator,
    XOREncryptionEngine,
    Base64EncodingEngine,
    CompressionEngine,
    PolymorphicEngine,
    ObfuscationTechnique
)


class TestPayloadObfuscator(unittest.TestCase):
    """测试payload混淆模块"""

    def setUp(self):
        self.obfuscator = PayloadObfuscator()
        self.test_payload = b'Test payload for obfuscation'

    def test_validate_input(self):
        """测试输入验证"""
        # 有效输入
        valid, error = self.obfuscator.validate_input(payload=self.test_payload)
        self.assertTrue(valid)
        self.assertIsNone(error)

        # 缺少payload
        valid, error = self.obfuscator.validate_input()
        self.assertFalse(valid)
        self.assertEqual(error, "缺少必需参数: payload")

        # 空payload
        valid, error = self.obfuscator.validate_input(payload=b'')
        self.assertFalse(valid)
        self.assertEqual(error, "payload 不能为空")

        # 非bytes类型
        valid, error = self.obfuscator.validate_input(payload="string")
        self.assertFalse(valid)
        self.assertEqual(error, "payload 必须是 bytes 类型")

    def test_xor_encryption(self):
        engine = XOREncryptionEngine()
        key = b'secretkey123456'

        result = engine.obfuscate(self.test_payload, key=key)
        self.assertEqual(result.technique, ObfuscationTechnique.XOR_ENCRYPTION)
        self.assertNotEqual(result.obfuscated_payload, self.test_payload)

        # 验证解密
        decrypted = bytes(b ^ key[i % len(key)] for i, b in enumerate(result.obfuscated_payload))
        self.assertEqual(decrypted, self.test_payload)

    def test_base64_encoding(self):
        """测试Base64编码引擎"""
        engine = Base64EncodingEngine()

        result = engine.obfuscate(self.test_payload)
        self.assertEqual(result.technique, ObfuscationTechnique.BASE64_ENCODING)

        # 验证解码
        decoded = base64.b64decode(result.obfuscated_payload)
        self.assertEqual(decoded, self.test_payload)

    def test_compression(self):
        """测试压缩引擎"""
        engine = CompressionEngine()

        result = engine.obfuscate(self.test_payload)
        self.assertEqual(result.technique, ObfuscationTechnique.COMPRESSION)

        # 验证解压
        import zlib
        decompressed = zlib.decompress(result.obfuscated_payload)
        self.assertEqual(decompressed, self.test_payload)

    def test_polymorphic(self):
        engine = PolymorphicEngine()

        result = engine.obfuscate(self.test_payload)
        self.assertEqual(result.technique, ObfuscationTechnique.POLYMORPHIC)
        self.assertGreater(len(result.obfuscated_payload), len(self.test_payload))

    def test_analyze_basic(self):
        """测试基本分析功能"""
        result = self.obfuscator.analyze(
            payload=self.test_payload,
            techniques=['xor_encryption']
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['technique'], 'xor_encryption')
        self.assertIsNotNone(result['key'])
        self.assertIsNotNone(result['obfuscated_payload_hex'])

    def test_chain_obfuscation(self):
        """测试链式混淆"""
        result = self.obfuscator.analyze(
            payload=self.test_payload,
            techniques=['xor_encryption', 'base64_encoding'],
            add_anti_debug=False
        )

        self.assertTrue(result['success'])
        self.assertEqual(result['technique'], 'base64_encoding')
        self.assertIn('xor_encryption', result['techniques_used'])
        self.assertIn('base64_encoding', result['techniques_used'])

    def test_anti_debug(self):
        result = self.obfuscator.analyze(
            payload=self.test_payload,
            techniques=['xor_encryption'],
            add_anti_debug=True
        )

        self.assertTrue(result['success'])
        self.assertTrue(result.get('anti_debug_enabled', False))
        self.assertIn('timing_analysis', [r['type'] for r in result.get('anti_detection_rules', [])])


class TestObfuscatePayloadFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_obfuscate_payload(self):
        # 早期实现保留——记录设计决策
        """测试obfuscate_payload便捷函数"""
        payload = b'Test payload'
        obfuscator = PayloadObfuscator()

        result = obfuscator.analyze(payload=payload)

        self.assertTrue(result['success'])
        self.assertIsNotNone(result['obfuscated_payload_hex'])



if __name__ == '__main__':
    unittest.main()


