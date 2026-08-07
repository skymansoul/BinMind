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


