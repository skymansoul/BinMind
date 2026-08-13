"""

协议逆向工程引擎单元测试 -- enriched with edge cases and error paths.
"""
import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.protocol_infer import (
    ProtocolInferEngine, HeuristicFieldInferrer, MagicDetector, ChecksumDetector,
    ProtocolDefinition, ProtocolMessage, ProtocolField, ProtocolInferenceResult,
    ProtocolFieldType, FieldEndianness
)


class TestProtocolFieldTypeEnum(unittest.TestCase):
    """协议字段类型枚举测试"""

    def test_protocol_field_type_values(self):
        self.assertEqual(ProtocolFieldType.UINT8.value, "uint8")
        self.assertEqual(ProtocolFieldType.UINT32.value, "uint32")
        self.assertEqual(ProtocolFieldType.STRING.value, "string")
        self.assertEqual(ProtocolFieldType.BYTES.value, "bytes")
        self.assertEqual(ProtocolFieldType.CHECKSUM.value, "checksum")
        self.assertEqual(ProtocolFieldType.MAGIC.value, "magic")


class TestFieldEndiannessEnum(unittest.TestCase):
    """字段字节序枚举测试"""

    def test_field_endianness_values(self):
        self.assertEqual(FieldEndianness.LITTLE_ENDIAN.value, "little")
        self.assertEqual(FieldEndianness.BIG_ENDIAN.value, "big")
        self.assertEqual(FieldEndianness.NATIVE.value, "native")


class TestProtocolFieldDataclass(unittest.TestCase):
    """ProtocolField数据类测试"""

    def test_protocol_field_creation(self):
        field = ProtocolField(
            name="length",
            type=ProtocolFieldType.UINT32,
            offset=0,
            size=4,
            description="数据包长度",
            endianness=FieldEndianness.LITTLE_ENDIAN,
            is_variable_length=True
        )
        self.assertEqual(field.name, "length")
        self.assertEqual(field.type, ProtocolFieldType.UINT32)
        self.assertEqual(field.offset, 0)
        self.assertTrue(field.is_variable_length)

    def test_minimal_field(self):
        """最小字段：仅 name 和 type"""
        field = ProtocolField(name="flag", type=ProtocolFieldType.UINT8, offset=2, size=1)
        self.assertEqual(field.offset, 2)
        self.assertEqual(field.size, 1)
        self.assertFalse(field.is_variable_length)

    def test_field_defaults(self):
        """默认字段值"""
        field = ProtocolField(name="data", type=ProtocolFieldType.BYTES, offset=0, size=0)
        self.assertEqual(field.description, "")
        self.assertFalse(field.is_variable_length)


class TestProtocolMessageDataclass(unittest.TestCase):
    """ProtocolMessage数据类测试"""

    def test_protocol_message_creation(self):
        fields = [
            ProtocolField(name="magic", type=ProtocolFieldType.MAGIC, offset=0, size=4),
            ProtocolField(name="length", type=ProtocolFieldType.UINT32, offset=4, size=4)
        ]
        message = ProtocolMessage(
            name="request",
            fields=fields,
            magic=0x41424344,
            description="请求消息",
            min_length=8,
            max_length=1024
        )
        self.assertEqual(message.name, "request")
        self.assertEqual(len(message.fields), 2)
        self.assertEqual(message.magic, 0x41424344)

    def test_empty_message(self):
        """无字段消息"""
        msg = ProtocolMessage(name="empty", fields=[], description="空消息")
        self.assertEqual(len(msg.fields), 0)

    def test_message_direction(self):
        """消息方向字段"""
        field = ProtocolField(name="cmd", type=ProtocolFieldType.UINT8, offset=0, size=1)
        msg = ProtocolMessage(name="req", fields=[field], direction="client_to_server")
        self.assertEqual(msg.direction, "client_to_server")


class TestProtocolDefinitionDataclass(unittest.TestCase):
    """ProtocolDefinition数据类测试"""

    def test_protocol_definition_creation(self):
        message = ProtocolMessage(name="default", fields=[], description="默认消息")
        protocol = ProtocolDefinition(
            name="MyProtocol",
            messages=[message],
            port=8080,
            transport="tcp",
            description="自定义协议"
        )
        self.assertEqual(protocol.name, "MyProtocol")
        self.assertEqual(protocol.port, 8080)
        self.assertEqual(protocol.transport, "tcp")

    def test_empty_protocol(self):
        """空消息列表协议"""
        proto = ProtocolDefinition(name="Empty", messages=[], transport="udp")
        self.assertEqual(len(proto.messages), 0)
        self.assertEqual(proto.transport, "udp")


class TestProtocolInferenceResultDataclass(unittest.TestCase):
    """ProtocolInferenceResult数据类测试"""

    def test_protocol_inference_result_creation(self):
        protocol = ProtocolDefinition(name="test", messages=[])
        result = ProtocolInferenceResult(
            success=True, protocol=protocol, samples_analyzed=10,
            warnings=["警告"], errors=[]
        )
        self.assertTrue(result.success)
        self.assertEqual(result.samples_analyzed, 10)

    def test_failed_result(self):
        """失败推断结果"""
        result = ProtocolInferenceResult(
            success=False, protocol=None, samples_analyzed=0, errors=["No data"]
        )
        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)




"""
协议逆向工程引擎单元测试 -- enriched with edge cases and error paths.
"""
import os
_MOD_DEBUG = False
import sys
import unittest
import tempfile
import shutil

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.protocol_infer import (
    ProtocolInferEngine, HeuristicFieldInferrer, MagicDetector, ChecksumDetector,
    ProtocolDefinition, ProtocolMessage, ProtocolField, ProtocolInferenceResult,
    ProtocolFieldType, FieldEndianness
)



class TestMagicDetector(unittest.TestCase):
    """魔数检测器测试"""

    def test_detect_magic(self):
        detector = MagicDetector()
        samples = [
            b"\x41\x42\x43\x44\x00\x01",
            b"\x41\x42\x43\x44\x00\x02",
            b"\x41\x42\x43\x44\x00\x03"
        ]
        magic = detector.detect(samples)
        self.assertIsNotNone(magic)
        self.assertEqual(magic, 0x44434241)  # 小端序

    def test_no_common_magic(self):
        detector = MagicDetector()
        samples = [b"\x01\x02\x03\x04", b"\x05\x06\x07\x08"]
        magic = detector.detect(samples)
        self.assertIsNone(magic)

    def test_single_sample(self):
        """单样本：应返回该样本的魔数"""
        detector = MagicDetector()
        samples = [b"\xDE\xAD\xBE\xEF\x00\x01"]
        magic = detector.detect(samples)
        self.assertIsNotNone(magic)

    def test_empty_samples(self):
        """空样本列表→None"""
        detector = MagicDetector()
        magic = detector.detect([])
        self.assertIsNone(magic)


class TestChecksumDetector(unittest.TestCase):
    """校验和检测器测试"""

    def test_detect_checksum(self):
        detector = ChecksumDetector()
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        results = detector.detect(data)
        self.assertGreater(len(results), 0)

    def test_detect_empty_data(self):
        """空数据→空结果"""
        detector = ChecksumDetector()
        results = detector.detect(b"")
        self.assertEqual(len(results), 0)

    def test_detect_short_data(self):
        """数据太短无法检测→空"""
        detector = ChecksumDetector()
        results = detector.detect(b"\x00")
        self.assertEqual(len(results), 0)


class TestHeuristicFieldInferrer(unittest.TestCase):
    """启发式字段推断器测试"""

    def test_infer_fields(self):
        inferrer = HeuristicFieldInferrer()
        samples = [
            b"\x41\x42\x43\x44\x08\x00\x00\x00hello",
            b"\x41\x42\x43\x44\x06\x00\x00\x00world"
        ]
        fields = inferrer.infer(samples)
        self.assertGreater(len(fields), 0)

    def test_infer_empty_samples(self):
        """空样本列表→空字段"""
        inferrer = HeuristicFieldInferrer()
        fields = inferrer.infer([])
        self.assertEqual(len(fields), 0)

    def test_infer_single_byte(self):
        """单字节样本"""
        inferrer = HeuristicFieldInferrer()
        fields = inferrer.infer([b"\x42"])
        self.assertIsInstance(fields, list)


class TestProtocolInferEngine(unittest.TestCase):
    """协议逆向引擎测试"""

    def setUp(self):
        self.m_tmp = tempfile.mkdtemp()
        self.engine = ProtocolInferEngine()

    def tearDown(self):
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)

    def test_analyze_empty_samples(self):
        result = self.engine.analyze_samples([])
        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)

    def test_analyze_valid_samples(self):
        samples = [
            b"\x41\x42\x43\x44\x08\x00\x00\x00hello\x00",
            b"\x41\x42\x43\x44\x06\x00\x00\x00world\x00"
        ]
        result = self.engine.analyze_samples(samples, "TestProtocol")
        self.assertTrue(result.success)
        self.assertEqual(result.protocol.name, "TestProtocol")
        self.assertEqual(len(result.protocol.messages), 1)

    def test_analyze_pcap_missing_file(self):
        result = self.engine.analyze_pcap("/nonexistent/file.pcap")
        self.assertFalse(result.success)

    def test_generate_scapy_code(self):
        fields = [
            ProtocolField(name="magic", type=ProtocolFieldType.UINT32, offset=0, size=4),
            ProtocolField(name="length", type=ProtocolFieldType.UINT32, offset=4, size=4),
            ProtocolField(name="data", type=ProtocolFieldType.STRING, offset=8, size=10)
        ]
        message = ProtocolMessage(name="test", fields=fields)
        protocol = ProtocolDefinition(name="TestProtocol", messages=[message])
        code = self.engine.generate_scapy_code(protocol)
        self.assertIn("from scapy.all import", code)
        self.assertIn("Packet", code)
        self.assertIn("IntField", code)

    def test_generate_wireshark_lua(self):
        fields = [
            ProtocolField(name="magic", type=ProtocolFieldType.UINT32, offset=0, size=4),
            ProtocolField(name="length", type=ProtocolFieldType.UINT32, offset=4, size=4)
        ]
        message = ProtocolMessage(name="test", fields=fields)
        protocol = ProtocolDefinition(name="TestProtocol", messages=[message])
        code = self.engine.generate_wireshark_lua(protocol)
        self.assertIn("Proto(", code)
        self.assertIn("dissect", code)

    def test_generate_report(self):
        protocol = ProtocolDefinition(name="TestProtocol", messages=[])
        result = ProtocolInferenceResult(success=True, protocol=protocol, samples_analyzed=5)
        report = self.engine.generate_report(result)
        self.assertIn("协议逆向工程分析报告", report)
        self.assertIn("TestProtocol", report)

    def test_save_result(self):
        protocol = ProtocolDefinition(name="TestProtocol", messages=[])
        result = ProtocolInferenceResult(success=True, protocol=protocol, samples_analyzed=5)
        output_path = os.path.join(self.m_tmp, "result.json")
        success = self.engine.save_result(result, output_path)
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))


if __name__ == '__main__':
    unittest.main()
