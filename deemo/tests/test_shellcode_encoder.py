"""
Shellcode编码器模块单元测试
"""

import os
import sys
import unittest
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.shellcode_encoder import (
    ShellcodeEncoder,
    EncoderType,
    BadCharInfo,
    EncodeResult,
    encode_shellcode
)


class TestBadCharInfo(unittest.TestCase):
    """测试坏字符信息数据类"""

    def test_init_with_int(self):
        """测试整数初始化"""
        info = BadCharInfo(char=0x00)
        
        self.assertEqual(info.char, 0)
        self.assertEqual(info.hex_repr, "\\x00")
        self.assertEqual(info.name, "NULL")

    def test_init_with_string(self):
        """测试字符串初始化"""
        info = BadCharInfo(char="\x0a")
        
        self.assertEqual(info.char, 10)

    def test_custom_name(self):
        """测试自定义名称"""
        info = BadCharInfo(char=0x41, name="CUSTOM")
        
        self.assertEqual(info.name, "CUSTOM")


class TestEncodeResult(unittest.TestCase):
    """测试编码结果数据类"""

    def test_init(self):
        """测试初始化"""
        result = EncodeResult(
            original_shellcode=b"test",
            encoded_shellcode=b"encoded",
            decoder_stub=b"decoder",
            encoder_type=EncoderType.XOR
        )
        
        self.assertEqual(result.encoder_type, EncoderType.XOR)
        self.assertFalse(result.contains_bad_chars)

    def test_to_dict(self):
        """测试转换为字典"""
        result = EncodeResult(
            original_shellcode=b"test",
            encoded_shellcode=b"enc",
            decoder_stub=b"dec",
            encoder_type=EncoderType.XOR,
            key=0x42
        )
        
        data = result.to_dict()
        self.assertEqual(data["encoder_type"], "xor")
        self.assertEqual(data["key"], 0x42)


class TestShellcodeEncoder(unittest.TestCase):
    """测试Shellcode编码器"""

    def setUp(self):
        """设置测试环境"""
        self.encoder = ShellcodeEncoder(arch="amd64", bad_chars=[0x00, 0x0a])

    def test_init(self):
        """测试初始化"""
        self.assertEqual(self.encoder.arch, "amd64")
        self.assertIn(0x00, self.encoder.bad_chars)
        self.assertIn(0x0a, self.encoder.bad_chars)

    def test_xor_encode_no_bad_chars(self):
        """测试XOR编码（无坏字符）"""
        shellcode = b"\x90" * 10  # NOP sled
        
        result = self.encoder.encode(shellcode, EncoderType.XOR)
        
        self.assertEqual(result.encoder_type, EncoderType.XOR)
        self.assertIsNotNone(result.encoded_shellcode)
        self.assertIsNotNone(result.key)
        self.assertNotIn(0x00, result.encoded_shellcode)

    def test_xor_encode_with_bad_chars_in_result(self):
        """测试XOR编码（结果包含坏字符）"""
        # 测试会包含坏字符的情况
        shellcode = bytes([0x00, 0x01, 0x02])
        
        result = self.encoder.encode(shellcode, EncoderType.XOR)
        
        self.assertIsInstance(result, EncodeResult)
        # 编码应该尝试避免坏字符

    def test_add_encode(self):
        """测试加法编码"""
        shellcode = b"\x01\x02\x03\x04"
        
        result = self.encoder.encode(shellcode, EncoderType.ADD)
        
        self.assertEqual(result.encoder_type, EncoderType.ADD)
        self.assertIsNotNone(result.key)

    def test_sub_encode(self):
        """测试减法编码"""
        shellcode = b"\x10\x20\x30\x40"
        
        result = self.encoder.encode(shellcode, EncoderType.SUB)
        
        self.assertEqual(result.encoder_type, EncoderType.SUB)

    def test_not_encode(self):
        """测试NOT编码"""
        shellcode = b"\x01\x02\x03\x04"
        
        result = self.encoder.encode(shellcode, EncoderType.NOT)
        
        self.assertEqual(result.encoder_type, EncoderType.NOT)

    def test_rol_encode(self):
        """测试循环左移编码"""
        shellcode = b"\x01\x02\x03\x04"
        
        result = self.encoder.encode(shellcode, EncoderType.ROL)
        
        self.assertEqual(result.encoder_type, EncoderType.ROL)

    def test_ror_encode(self):
        """测试循环右移编码"""
        shellcode = b"\x10\x20\x30\x40"
        
        result = self.encoder.encode(shellcode, EncoderType.ROR)
        
        self.assertEqual(result.encoder_type, EncoderType.ROR)

    def test_find_best_xor_key(self):
        """测试搜索最佳XOR密钥"""
        shellcode = b"AAAA"
        
        key, encoded = self.encoder.find_best_xor_key(shellcode)
        
        self.assertIsInstance(key, int)
        self.assertIsInstance(encoded, bytes)
        self.assertEqual(len(encoded), len(shellcode))

    def test_auto_select_encoder(self):
        """测试自动选择编码器"""
        shellcode = b"\x01\x02\x03\x04"
        
        result = self.encoder.encode(shellcode, auto_select=True)
        
        self.assertIsInstance(result.encoder_type, EncoderType)

    def test_generate_final_shellcode(self):
        """测试生成最终shellcode"""
        shellcode = b"\x90" * 10
        result = self.encoder.encode(shellcode, EncoderType.XOR)
        
        final = self.encoder.generate_final_shellcode(result)
        
        self.assertIsInstance(final, bytes)
        # 应该包含解码器 + 编码后的 shellcode
        self.assertGreaterEqual(len(final), len(result.encoded_shellcode))

    def test_verify_encode_result(self):
        """测试验证编码结果"""
        # 不包含坏字符
        result = EncodeResult(
            original_shellcode=b"test",
            encoded_shellcode=bytes([0x01, 0x02]),
            decoder_stub=b"dec",
            encoder_type=EncoderType.XOR
        )
        
        verified = self.encoder._verify_encode_result(result)
        
        self.assertFalse(verified.contains_bad_chars)

    def test_verify_encode_result_with_bad_chars(self):
        """测试验证包含坏字符的结果"""
        result = EncodeResult(
            original_shellcode=b"test",
            encoded_shellcode=bytes([0x00, 0x02]),
            decoder_stub=b"dec",
            encoder_type=EncoderType.XOR
        )
        
        # 手动添加坏字符
        result.encoded_shellcode = bytes([0x00, 0x01])
        
        verified = self.encoder._verify_encode_result(result)
        
        self.assertTrue(verified.contains_bad_chars)

    def test_empty_shellcode(self):
        """测试空shellcode"""
        with self.assertRaises(ValueError):
            self.encoder.encode(b"")

    def test_rol_byte_array(self):
        """测试循环左移字节数组"""
        data = bytes([0x01, 0x02, 0x04, 0x08])
        
        result = self.encoder._rol_byte_array(data, 1)
        
        self.assertEqual(len(result), len(data))
        # 应该每个字节都被移位

    def test_ror_byte_array(self):
        """测试循环右移字节数组"""
        data = bytes([0x80, 0x40, 0x20, 0x10])
        
        result = self.encoder._ror_byte_array(data, 1)
        
        self.assertEqual(len(result), len(data))


class TestShellcodeEncoderEdgeCases(unittest.TestCase):
    """测试Shellcode编码器边界情况"""

    def setUp(self):
        """设置测试环境"""
        self.encoder = ShellcodeEncoder()

    def test_all_bad_chars(self):
        """测试所有字符都是坏字符"""
        # 大部分字符被禁止
        encoder = ShellcodeEncoder(bad_chars=list(range(256)))
        
        # 可能无法找到有效的编码
        shellcode = b"test"
        result = encoder.encode(shellcode, EncoderType.XOR)
        
        self.assertIsInstance(result, EncodeResult)

    def test_single_byte_shellcode(self):
        """测试单字节shellcode"""
        shellcode = b"\x41"
        
        result = self.encoder.encode(shellcode, EncoderType.XOR)
        
        self.assertIsInstance(result, EncodeResult)

    def test_large_shellcode(self):
        """测试大shellcode"""
        shellcode = b"A" * 10000
        
        result = self.encoder.encode(shellcode, EncoderType.XOR)
        
        self.assertIsInstance(result, EncodeResult)
        self.assertGreater(result.encoded_size, 0)

    def test_generate_pwntools_script(self):
        """测试生成pwntools脚本"""
        shellcode = b"\x90" * 10
        result = self.encoder.encode(shellcode, EncoderType.XOR)
        
        script = self.encoder.generate_pwntools_script(result)
        
        self.assertIsInstance(script, str)
        self.assertIn("from pwn import", script)
        self.assertIn("context.arch", script)


class TestConvenienceFunction(unittest.TestCase):
    """测试便捷函数"""

    def test_encode_shellcode(self):
        """测试便捷编码函数"""
        shellcode = b"\x01\x02\x03\x04"
        
        result = encode_shellcode(
            shellcode,
            arch="amd64",
            bad_chars=[0x00],
            encoder_type="xor"
        )
        
        self.assertIsInstance(result, EncodeResult)
        self.assertEqual(result.encoder_type, EncoderType.XOR)


if __name__ == '__main__':
    unittest.main()