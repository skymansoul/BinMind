
import unittest
import os
_MOD_DEBUG = False
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

    def test_field_to_dict(self):
        """测试序列化字典"""
        field = FieldInfo(
            name="magic", offset=0, size=2,
            field_type="uint16", hypothesis="magic",
            confidence=0.9, sample_values=[1, 2],
        )
        d = field.to_dict()
        self.assertEqual(d["name"], "magic")
        self.assertEqual(d["offset"], 0)
        self.assertEqual(d["size"], 2)
        self.assertEqual(d["field_type"], "uint16")
        self.assertEqual(d["hypothesis"], "magic")
        self.assertEqual(d["confidence"], 0.9)
        self.assertEqual(d["sample_values"], [1, 2])


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
        self.assertEqual(grammar.endianness, "unknown")

    def test_add_field(self):
        """测试添加字段"""
        grammar = ProtocolGrammar(name="p")
        grammar.add_field(FieldInfo(name="len", offset=0, size=2, field_type="uint16"))
        self.assertEqual(len(grammar.fields), 1)
        self.assertEqual(grammar.fields[0].name, "len")

    def test_get_total_size(self):
        """测试计算报文总长度"""
        grammar = ProtocolGrammar(name="p", fields=[
            FieldInfo(name="hdr", offset=0, size=4, field_type="bytes"),
            FieldInfo(name="payload", offset=4, size=8, field_type="bytes"),
        ])
        self.assertEqual(grammar.get_total_size(), 12)
        empty = ProtocolGrammar(name="empty")
        self.assertEqual(empty.get_total_size(), 0)

    def test_to_dict(self):
        """测试语法序列化"""
        grammar = ProtocolGrammar(name="p", fields=[
            FieldInfo(name="len", offset=0, size=2, field_type="uint16"),
        ])
        d = grammar.to_dict()
        self.assertEqual(d["name"], "p")
        self.assertEqual(d["endianness"], "unknown")
        self.assertIsNone(d["magic_bytes"])
        self.assertIsNone(d["checksum_offset"])
        self.assertEqual(d["checksum_size"], 0)
        self.assertEqual(len(d["fields"]), 1)
        self.assertEqual(d["fields"][0]["name"], "len")


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

    def test_infer_with_size(self):
        """测试指定偏移与大小的推断"""
        raw = b"\x00\x02\x04hello"
        self.assertEqual(TypeInferrer.infer(raw, 0, 2), "uint16")
        self.assertEqual(TypeInferrer.infer(raw, 3, 5), "ascii_string")
        self.assertEqual(TypeInferrer.infer(b"\x05", 0, 1), "uint8")
        self.assertEqual(TypeInferrer.infer(raw, 0, 4), "uint32")
        self.assertEqual(TypeInferrer.infer(b"\x00\x00\x00\x00\x00\x00\x00\x00", 0, 8), "padding")
        self.assertEqual(TypeInferrer.infer(b"\x01\x00\x00\x00", 0, 4), "flags")
        self.assertEqual(TypeInferrer.infer(raw, 100, 2), "unknown")


class TestChecksumDetector(unittest.TestCase):
    """ChecksumDetector静态方法测试"""

    def test_detect_crc_short_data(self):
        """测试短数据CRC检测"""
        result = ChecksumDetector.detect_crc(b"\x00")
        self.assertIsNone(result)

    def test_detect_crc(self):
        """测试CRC检测"""
        # 6 bytes total, last 2 as checksum
        data = b"\x01\x02\x03\x04\x05\x06"
        result = ChecksumDetector.detect_crc(data)
        if result is not None:
            offset, size = result
            self.assertIn(size, (2, 4))
            self.assertEqual(offset, len(data) - size)




class TestWiresharkGenerator(unittest.TestCase):
    """WiresharkGenerator静态方法测试"""

    def test_generate(self):
        """测试生成Wireshark解析器"""
        fields = [
            FieldInfo(name="length", offset=0, size=2, field_type="uint16"),
            FieldInfo(name="payload", offset=2, size=4, field_type="bytes"),
        ]
        grammar = ProtocolGrammar(name="test_proto", fields=fields)
        dissector = WiresharkGenerator.generate(grammar)
        self.assertIsInstance(dissector, WiresharkDissector)

        self.assertEqual(dissector.protocol_name, "test_proto")
        self.assertIn("Proto.new", dissector.lua_code)
        self.assertIn("ProtoField.new", dissector.lua_code)


class TestProtocolReverser(unittest.TestCase):
    """协议逆向器测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.m_tmp, ignore_errors=True)

    def test_validate_path(self):
        """测试路径验证"""
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'\x7fELF\x02\x01\x01\x00')

        reverser = ProtocolReverser(test_file)
        self.assertEqual(reverser.binary_path, os.path.abspath(test_file))

    def test_reverse(self):
        """测试协议逆向"""
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')

        reverser = ProtocolReverser(test_file, sample_data=b"\x00\x08\x01\x02hello")
        result = reverser.reverse()
        self.assertTrue(result.success)
        self.assertIsNotNone(result.grammar)
        self.assertIsNotNone(result.dissector)
        self.assertGreater(result.confidence, 0.0)

    def test_create_protocol_reverser(self):
        """测试便捷工厂函数"""
        test_file = os.path.join(self.m_tmp, 'test.bin')
        with open(test_file, 'wb') as f:
            f.write(b'test')

        reverser = create_protocol_reverser(test_file)
        self.assertIsInstance(reverser, ProtocolReverser)


class TestLegacyProtocolFormatInferrer(unittest.TestCase):
    """旧版ProtocolFormatInferrer测试（已并入真实API测试）"""

    def test_validate_path_empty(self):
        """空路径不抛异常，binary_path 为空串"""
        reverser = ProtocolReverser("")
        self.assertEqual(reverser.binary_path, "")
        self.assertEqual(reverser.sample_data, b"")

    def test_validate_path_nonexistent(self):
        """不存在路径不抛异常，binary_path 归一化为绝对路径"""
        reverser = ProtocolReverser("nonexistent_xxx.bin")
        self.assertEqual(reverser.binary_path, os.path.abspath("nonexistent_xxx.bin"))

    def test_create_protocol_inferrer(self):
        """create_protocol_reverser 无路径返回分析器字典"""
        analyzers = create_protocol_reverser("")
        self.assertIsInstance(analyzers, dict)
        for key in ("boundary", "length_field", "checksum", "magic", "type_inferrer", "dissector_gen"):
            self.assertIn(key, analyzers)

    def test_add_raw_sample(self):
        """构造时传入 sample_data 参与逆向"""
        reverser = ProtocolReverser("", sample_data=b"\x00\x08\x01\x02hello")
        self.assertEqual(reverser.sample_data, b"\x00\x08\x01\x02hello")

    def test_infer_protocol_basic(self):
        """reverse() 返回成功结果"""
        reverser = ProtocolReverser("", sample_data=b"\x00\x08\x01\x02hello")
        result = reverser.reverse()
        self.assertTrue(result.success)
        self.assertIsNotNone(result.grammar)
        self.assertIsNotNone(result.dissector)

    def test_generate_protocol_spec(self):
        """WiresharkGenerator.generate 生成 Lua 解析器"""
        grammar = ProtocolGrammar(name="p", fields=[
            FieldInfo(name="len", offset=0, size=2, field_type="uint16"),
        ])
        dissector = WiresharkGenerator.generate(grammar)
        self.assertIsInstance(dissector, WiresharkDissector)
        self.assertIn("Proto.new", dissector.lua_code)
        self.assertIn("ProtoField.new", dissector.lua_code)
        self.assertEqual(len(dissector.field_definitions), 1)


if __name__ == '__main__':
    unittest.main()


