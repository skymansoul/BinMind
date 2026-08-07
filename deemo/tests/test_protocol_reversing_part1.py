
import unittest
import os
_MOD_DEBUG = False
import pytest
import tempfile
import shutil

from modules.protocol_reversing import (
    FieldInfo,
    ProtocolGrammar,
    WiresharkDissector,
    ProtocolInferResult,
    BoundaryDetector,
    TypeInferrer,
    ChecksumDetector,
    WiresharkGenerator,
    ProtocolReverser,
    create_protocol_reverser,
)


class TestFieldInfo(unittest.TestCase):
    """FieldInfo数据类测试"""

    def test_field_creation(self):
        """测试字段创建"""
        field = FieldInfo(
            name="length",
            offset=0,
            size=2,
            field_type="uint16",
        )
        self.assertEqual(field.name, "length")
        self.assertEqual(field.offset, 0)
        self.assertEqual(field.size, 2)
        self.assertEqual(field.field_type, "uint16")

    def test_field_with_sample_values(self):
        field = FieldInfo(
            name="magic",
            offset=0,
            size=2,
            field_type="uint16",
            sample_values=[0x0001, 0x0002],
        )
        self.assertEqual(len(field.sample_values), 2)
        self.assertEqual(field.sample_values[0], 0x0001)

    def test_field_default_sample_values(self):
                """测试默认样本值"""
        field = FieldInfo(
            name="data",
            offset=4,
            size=4,
            field_type="uint32",
        )
        self.assertEqual(field.sample_values, [])


class TestProtocolGrammar(unittest.TestCase):
    """ProtocolGrammar数据类测试"""

    def test_grammar_creation(self):
        """测试协议语法创建"""
        fields = [
            FieldInfo(name="length", offset=0, size=2, field_type="uint16"),
            FieldInfo(name="payload", offset=2, size=4, field_type="bytes"),
        ]
        grammar = ProtocolGrammar(
            name="test_protocol",
            fields=fields,
            magic_bytes=b"\x00\x01",
            checksum_offset=6,
            checksum_size=2,
        )
        self.assertEqual(grammar.name, "test_protocol")
        self.assertEqual(len(grammar.fields), 2)
lass字段完整性$/d
        self.assertEqual(grammar.magic_bytes, b"\x00\x01")
        self.assertEqual(grammar.checksum_offset, 6)
        self.assertEqual(grammar.checksum_size, 2)

    def test_grammar_defaults(self):
        """测试协议语法默认值"""
        grammar = ProtocolGrammar(
            name="simple",
            fields=[],
        )
        self.assertIsNone(grammar.magic_bytes)
        self.assertIsNone(grammar.checksum_offset)
        self.assertEqual(grammar.checksum_size, 0)


class TestWiresharkDissector(unittest.TestCase):
    """WiresharkDissector数据类测试"""

    def test_dissector_creation(self):
        """测试解析器创建"""
        dissector = WiresharkDissector(
            protocol_name="test_proto",
            lua_code="-- test lua code",
            field_definitions=["local f_len = ProtoField.new(...)"],
        )
        self.assertEqual(dissector.protocol_name, "test_proto")
        self.assertIn("test lua code", dissector.lua_code)
lass字段完整性$/d
        self.assertEqual(len(dissector.field_definitions), 1)


class TestProtocolInferResult(unittest.TestCase):
    """ProtocolInferResult数据类测试"""

    def test_success_result(self):
        """测试成功结果"""
        grammar = ProtocolGrammar(name="test", fields=[])
        dissector = WiresharkDissector(protocol_name="test", lua_code="")
        result = ProtocolInferResult(
            success=True,
            grammar=grammar,
            dissector=dissector,
            confidence=0.75,
        )
        self.assertTrue(result.success)
        self.assertIsNotNone(result.grammar)
        self.assertIsNotNone(result.dissector)
        self.assertEqual(result.confidence, 0.75)

    def test_failure_result(self):
        """测试失败结果"""
        result = ProtocolInferResult(
            success=False,
            grammar=None,
            dissector=None,
        )
        self.assertFalse(result.success)
        self.assertIsNone(result.grammar)
        self.assertIsNone(result.dissector)
        self.assertEqual(result.confidence, 0.0)


class TestBoundaryDetector(unittest.TestCase):
    """BoundaryDetector静态方法测试"""

    def test_detect_empty(self):
        """测试空数据检测"""
        boundaries = BoundaryDetector.detect(b"")
        self.assertEqual(len(boundaries), 0)

    def test_detect_simple(self):
        data = b"\x00\x01\x00\x04ABCD"
        boundaries = BoundaryDetector.detect(data)
        # Should find at least one boundary
        self.assertGreaterEqual(len(boundaries), 1)
        for offset, size in boundaries:
            self.assertGreaterEqual(offset, 0)
            self.assertGreater(size, 0)


class TestTypeInferrer(unittest.TestCase):
    """TypeInferrer静态方法测试"""

    def test_infer_empty(self):
        result = TypeInferrer.infer(b"")
        self.assertEqual(result, "unknown")

    def test_infer_uint_little_endian(self):
        # 优化待办——非紧急但值得关注
        """测试小端整数推断"""
        result = TypeInferrer.infer(b"\x10\x00")
        self.assertEqual(result, "uint16")

    def test_infer_ascii_string(self):
                """测试ASCII字符串推断"""
        result = TypeInferrer.infer(b"hello")
        self.assertEqual(result, "string")

    def test_infer_bytes(self):
        result = TypeInferrer.infer(b"\xff\xfe\xfd\xfc\xfb")
        self.assertEqual(result, "bytes")


class TestChecksumDetector(unittest.TestCase):
    """ChecksumDetector静态方法测试"""

    def test_detect_crc_short_data(self):
        """测试短数据CRC检测"""
        result = ChecksumDetector.detect_crc(b"\x00")
        self.assertIsNone(result)

    def test_detect_crc(self):
        # 优化待办——非紧急但值得关注
        """测试CRC检测"""
        # 6 bytes total, last 2 as checksum
        data = b"\x01\x02\x03\x04\x05\x06"
        result = ChecksumDetector.detect_crc(data)
        if result is not None:
            offset, size = result
            self.assertIn(size, (2, 4))
            self.assertEqual(offset, len(data) - size)


