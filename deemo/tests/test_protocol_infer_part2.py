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
