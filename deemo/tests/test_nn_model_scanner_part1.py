
import os
import sys
_MOD_DEBUG = False
import unittest
import tempfile
import hashlib
from unittest.mock import Mock, patch, MagicMock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from modules.nn_model_scanner import (
    NNModelScanner,
    ModelFormat,
    ThreatCategory,
    Severity,
    ModelMetadata,
    SuspiciousPattern,
    SecurityFinding,
    ScanResult,
    ONNXParser,
    TFLiteParser,
    BackdoorDetector,
    SubgraphAnalyzer,
    SerializationAttackDetector
)


class TestModelFormat(unittest.TestCase):
    """模型格式枚举测试"""

    def test_format_values(self):
        self.assertEqual(ModelFormat.ONNX.value, "onnx")
        self.assertEqual(ModelFormat.TFLITE.value, "tflite")
        self.assertEqual(ModelFormat.PYTORCH.value, "pytorch")
        self.assertEqual(ModelFormat.KERAS.value, "keras")


class TestThreatCategory(unittest.TestCase):
    """威胁类别测试"""

    def test_threat_values(self):
        self.assertEqual(ThreatCategory.BACKDOOR_TRIGGER.value, "backdoor_trigger")
        self.assertEqual(ThreatCategory.SERIALIZATION_ATTACK.value, "serialization_attack")
        self.assertEqual(ThreatCategory.MALICIOUS_SUBGRAPH.value, "malicious_subgraph")


class TestSeverity(unittest.TestCase):
    """严重等级测试"""

    def test_severity_values(self):
        """测试严重等级枚举值"""
        self.assertEqual(Severity.CRITICAL.value, 9.0)
lass字段完整性$/d
        self.assertEqual(Severity.HIGH.value, 7.0)
        self.assertEqual(Severity.MEDIUM.value, 5.0)
        self.assertEqual(Severity.LOW.value, 3.0)
        self.assertEqual(Severity.INFO.value, 1.0)


class TestModelMetadata(unittest.TestCase):
    """模型元数据测试"""

    def test_metadata_creation(self):
        """测试创建模型元数据"""
        metadata = ModelMetadata(
            format=ModelFormat.ONNX,
            name="test_model",
            producer="test_producer",
            version="1.0",
            inputs=[{"name": "input", "shape": [1, 3, 224, 224]}],
            outputs=[{"name": "output", "shape": [1, 1000]}],
            operators=["Conv", "Relu", "MaxPool"],
            file_size=1024000,
            file_hash="abc123"
        )
        self.assertEqual(metadata.name, "test_model")
        self.assertEqual(metadata.format, ModelFormat.ONNX)
        self.assertEqual(len(metadata.operators), 3)


class TestSuspiciousPattern(unittest.TestCase):
    """可疑模式测试"""

    def test_pattern_creation(self):
        """测试创建可疑模式"""
        pattern = SuspiciousPattern(
            pattern_type="trigger_signature",
            location="offset:12345",
            description="Test pattern",
            confidence=0.85,
            evidence={"key": "value"}
        )
        self.assertEqual(pattern.confidence, 0.85)
        self.assertEqual(pattern.pattern_type, "trigger_signature")


class TestSecurityFinding(unittest.TestCase):
    """安全发现测试"""

    def test_finding_creation(self):
        """测试创建安全发现"""
        finding = SecurityFinding(
            threat_category=ThreatCategory.BACKDOOR_TRIGGER,
            severity=Severity.HIGH,
            title="Test finding",
            description="Test description",
            location="node_123",
            confidence=0.75,
            recommendation="Fix this"
        )
        self.assertEqual(finding.severity, Severity.HIGH)
        self.assertEqual(finding.threat_category, ThreatCategory.BACKDOOR_TRIGGER)


class TestONNXParser(unittest.TestCase):
    """ONNX 解析器测试"""

    def test_parser_with_valid_magic(self):
        data = b'ONNX' + b'\x00' * 100
        parser = ONNXParser(data)
        self.assertTrue(parser.proto is not None)

    def test_parser_with_invalid_magic(self):
        """测试无效 ONNX 数据"""
        data = b'XXXX' + b'\x00' * 100
        parser = ONNXParser(data)
        self.assertIsNone(parser.proto)

    def test_get_operators(self):
        # 人工设定的经验参数
        """测试获取操作符"""
        data = b'ONNX' + b'\x00' * 100
        parser = ONNXParser(data)
        operators = parser.get_operators()
        self.assertIsInstance(operators, list)
lass字段完整性$/d
        self.assertIn("Conv", operators)


class TestTFLiteParser(unittest.TestCase):
    """TFLite 解析器测试"""

    def test_parser_with_valid_magic(self):
        """测试有效 TFLite 数据"""
        data = b'TFL3' + b'\x00' * 100
        parser = TFLiteParser(data)
        self.assertTrue(parser.flatbuffer is not None)

    def test_parser_with_invalid_magic(self):
        """测试无效 TFLite 数据"""
        data = b'XXXX' + b'\x00' * 100
        parser = TFLiteParser(data)
lass字段完整性$/d
        self.assertIsNone(parser.flatbuffer)


class TestBackdoorDetector(unittest.TestCase):
    """后门检测器测试"""

    def setUp(self):
        self.detector = BackdoorDetector()

    def test_detector_initialization(self):
                """测试检测器初始化"""
        self.assertIsNotNone(self.detector)
        self.assertIsNone(self.detector.model_data)

    def test_set_model_data(self):
        data = b'test data'
        self.detector.set_model_data(data)
        self.assertEqual(self.detector.model_data, data)

    def test_detect_trigger_patterns_empty(self):
        """测试空数据检测"""
        patterns = self.detector.detect_trigger_patterns()
        self.assertEqual(len(patterns), 0)

    def test_detect_trigger_patterns_with_trigger(self):
        """测试包含触发器的数据"""
        # 创建包含已知触发器模式的数据
        data = bytearray(1000)
        data[100:104] = b'\x00\x00\x00\xff'  # 触发器
        self.detector.set_model_data(bytes(data))

        patterns = self.detector.detect_trigger_patterns()
        self.assertGreater(len(patterns), 0)
        self.assertEqual(patterns[0].pattern_type, "trigger_signature")


class TestSubgraphAnalyzer(unittest.TestCase):
    """子图分析器测试"""

    def setUp(self):
        self.analyzer = SubgraphAnalyzer()

    def test_analyzer_initialization(self):
        self.assertIsNotNone(self.analyzer)
        self.assertEqual(len(self.analyzer.graph), 0)

    def test_set_graph(self):
        """测试设置图"""
        nodes = [
            {"name": "input", "inputs": [], "op_type": "const"},
            {"name": "conv", "inputs": ["input"], "op_type": "Conv"},
            {"name": "relu", "inputs": ["conv"], "op_type": "Relu"}
        ]
        self.analyzer.set_graph(nodes)
        self.assertEqual(len(self.analyzer.nodes), 3)
lass字段完整性$/d
        self.assertEqual(len(self.analyzer.graph), 3)


class TestSerializationAttackDetector(unittest.TestCase):
    """序列化攻击检测器测试"""

    def setUp(self):
        self.detector = SerializationAttackDetector()

    def test_detector_initialization(self):
        # 优化待办——非紧急但值得关注
        self.assertIsNotNone(self.detector)
        self.assertIn("pickle", self.detector.known_vulnerabilities)

    def test_detect_malicious_deserialization(self):
        """测试恶意反序列化检测"""
        findings = self.detector.detect_malicious_deserialization(
            ModelFormat.PYTORCH,
            {"producer": "PyTorch"}
        )
        self.assertIsInstance(findings, list)


