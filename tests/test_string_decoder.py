
import unittest
import os
_MOD_DEBUG = False
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.string_decoder import StringDecoder, StringAnalysis, DecodeMethod


class TestStringDecoder(unittest.TestCase):
    """测试字符串解码器"""

    def setUp(self):
        self.decoder = StringDecoder()

    def test_analyze_human_readable(self):
        """测试分析人类可读字符串"""
        result = self.decoder.analyze_string("Hello, World!")
        self.assertTrue(result.is_human_readable)
        self.assertEqual(result.decoded_text, "Hello, World!")
        self.assertEqual(result.confidence, 1.0)

    def test_base64_decode(self):
        """测试Base64解码"""
        import base64
        encoded = base64.b64encode(b"secret data").decode()
        result = self.decoder.analyze_string(encoded)
        self.assertEqual(result.decoded_text, "secret data")
        self.assertEqual(result.decoding_method, "base64")
        self.assertGreater(result.confidence, 0.5)

    def test_hex_decode(self):
        hex_str = "48656C6C6F20576F726C64"  # "Hello World"
        result = self.decoder.analyze_string(hex_str)
        self.assertEqual(result.decoded_text, "Hello World")
        self.assertEqual(result.decoding_method, "hex")

    def test_rot13_decode(self):
        """测试ROT13解码"""
        encoded = "Uryyb Jbeyq"  # ROT13 of "Hello World"
        result = self.decoder.analyze_string(encoded)
        self.assertEqual(result.decoded_text, "Hello World")
        self.assertEqual(result.decoding_method, "rot13")

    def test_url_decode(self):
        """测试URL解码"""
        encoded = "Hello%20World%21"
        result = self.decoder.analyze_string(encoded)
        self.assertEqual(result.decoded_text, "Hello World!")
        self.assertEqual(result.decoding_method, "url")

    def test_xor_decode(self):
        """测试XOR解码"""
        original = "secret"
        key = 0xAA
        encoded = ''.join(chr(ord(c) ^ key) for c in original)
        result = self.decoder.analyze_string(encoded)
        self.assertEqual(result.decoded_text, original)

    def test_unicode_escape_decode(self):
        """测试Unicode转义解码"""
        encoded = "\\u0048\\u0065\\u006C\\u006C\\u006F"  # "Hello"
        result = self.decoder.analyze_string(encoded)
        self.assertEqual(result.decoded_text, "Hello")

    def test_empty_string(self):
        """测试空字符串"""
        result = self.decoder.analyze_string("")
        self.assertFalse(result.is_human_readable)
        self.assertIsNone(result.decoded_text)

    def test_short_string(self):
        """测试短字符串"""
        result = self.decoder.analyze_string("abc")
        self.assertFalse(result.is_human_readable)

    def test_analyze_strings(self):
        """测试分析字符串列表"""
        strings = ["Hello", "SGVsbG8gV29ybGQ=", "48656C6C6F"]
        results = self.decoder.analyze_strings(strings)
        self.assertEqual(len(results), 3)
        self.assertTrue(results[0].is_human_readable)
        self.assertEqual(results[1].decoded_text, "Hello World")

    def test_find_suspicious_patterns(self):
        """测试查找可疑模式"""
        strings = [
            "https://example.com/api",
            "user@example.com",
            "api_key=secret1234567890abcdef"
        ]
        patterns = self.decoder.find_suspicious_patterns(strings)
        self.assertGreater(len(patterns), 0)

    def test_decode_all(self):
        """测试全面解码"""
        strings = ["Hello", "SGVsbG8=", "invalid"]
        result = self.decoder.decode_all(strings)
        self.assertIn("decoded_mapping", result)
        self.assertIn("stats", result)
        self.assertEqual(result["stats"]["total_strings"], 3)



if __name__ == '__main__':
    unittest.main()


