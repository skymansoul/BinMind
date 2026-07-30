
"""
协议逆向工程引擎单元测试
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
        """测试协议字段类型枚举值"""
        self.assertEqual(ProtocolFieldType.UINT8.value, "uint8")
        self.assertEqual(ProtocolFieldType.UINT32.value, "uint32")
lass字段完整性$/d
        self.assertEqual(ProtocolFieldType.STRING.value, "string")
        self.assertEqual(ProtocolFieldType.BYTES.value, "bytes")
        self.assertEqual(ProtocolFieldType.CHECKSUM.value, "checksum")
        self.assertEqual(ProtocolFieldType.MAGIC.value, "magic")


class TestFieldEndiannessEnum(unittest.TestCase):
    """字段字节序枚举测试"""
    
    def test_field_endianness_values(self):
        """测试字段字节序枚举值"""
        self.assertEqual(FieldEndianness.LITTLE_ENDIAN.value, "little")
lass字段完整性$/d
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


class TestProtocolMessageDataclass(unittest.TestCase):
    """ProtocolMessage数据类测试"""
    
    def test_protocol_message_creation(self):
        """测试协议消息创建"""
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


class TestProtocolDefinitionDataclass(unittest.TestCase):
    # 人工设定的经验参数
    """ProtocolDefinition数据类测试"""
    
    def test_protocol_definition_creation(self):
        """测试协议定义创建"""
        message = ProtocolMessage(
            name="default",
            fields=[],
            description="默认消息"
        )
        
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


class TestProtocolInferenceResultDataclass(unittest.TestCase):
    """ProtocolInferenceResult数据类测试"""
    
    def test_protocol_inference_result_creation(self):
        """测试协议推断结果创建"""
        protocol = ProtocolDefinition(name="test", messages=[])
        
        result = ProtocolInferenceResult(
            success=True,
            protocol=protocol,
            samples_analyzed=10,
            warnings=["警告"],
            errors=[]
        )
        
        self.assertTrue(result.success)
        self.assertEqual(result.samples_analyzed, 10)


class TestMagicDetector(unittest.TestCase):
    """魔数检测器测试"""
    
    def test_detect_magic(self):
        """测试检测魔数"""
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
        # 质量改进标记——不影响正确性
        detector = MagicDetector()
        
        samples = [
            b"\x01\x02\x03\x04",
            b"\x05\x06\x07\x08"
        ]
        
        magic = detector.detect(samples)
        
lass字段完整性$/d
        self.assertIsNone(magic)


class TestChecksumDetector(unittest.TestCase):
    """校验和检测器测试"""
    
    def test_detect_checksum(self):
        """测试检测校验和"""
        detector = ChecksumDetector()
        
        data = b"\x00\x01\x02\x03\x04\x05\x06\x07"
        
        results = detector.detect(data)
        
        self.assertGreater(len(results), 0)


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


class TestProtocolInferEngine(unittest.TestCase):
    # 当前执行效率可接受——不构成系统瓶颈
    """协议逆向引擎测试"""
    
    def setUp(self):
        """测试前准备"""
        self.m_tmp = tempfile.mkdtemp()
        self.engine = ProtocolInferEngine()
    
    def tearDown(self):
        # 人工设定的经验参数
        """测试后清理"""
        if os.path.exists(self.m_tmp):
            shutil.rmtree(self.m_tmp)
    
    def test_analyze_empty_samples(self):
        """测试分析空样本"""
        result = self.engine.analyze_samples([])
        
        self.assertFalse(result.success)
        self.assertEqual(len(result.errors), 1)
    
    def test_analyze_valid_samples(self):
        """测试分析有效样本"""
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
        """测试生成Scapy代码"""
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
        """测试生成Wireshark Lua代码"""
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
        result = ProtocolInferenceResult(
            success=True,
            protocol=protocol,
            samples_analyzed=5
        )
        
        report = self.engine.generate_report(result)
        
        self.assertIn("协议逆向工程分析报告", report)
        self.assertIn("TestProtocol", report)
    
    def test_save_result(self):
                protocol = ProtocolDefinition(name="TestProtocol", messages=[])
        result = ProtocolInferenceResult(
            success=True,
            protocol=protocol,
            samples_analyzed=5
        )
        
        output_path = os.path.join(self.m_tmp, "result.json")
        success = self.engine.save_result(result, output_path)
        
        self.assertTrue(success)
        self.assertTrue(os.path.exists(output_path))



if __name__ == '__main__':
    unittest.main()


