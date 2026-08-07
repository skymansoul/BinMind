
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



class TestNNModelScanner(unittest.TestCase):
    """神经网络模型扫描器测试"""

    def setUp(self):
        self.config = {
            "enabled": True,
            "formats": ["onnx", "tflite"],
            "check_backdoors": True,
            "confidence_threshold": 0.6
        }
        self.scanner = NNModelScanner(config=self.config)

    def test_scanner_initialization(self):
        """测试扫描器初始化"""
        self.assertIsNotNone(self.scanner)
        self.assertEqual(self.scanner._config["enabled"], True)

    def test_metadata(self):
        """测试元数据"""
        metadata = NNModelScanner.get_metadata()
        self.assertEqual(metadata.name, "NNModelScanner")
        self.assertEqual(metadata.type.value, "static_analyzer")

    def test_validate_input_no_path(self):
        """测试无路径验证"""
        is_valid, error = self.scanner.validate_input()
        self.assertFalse(is_valid)
        self.assertIn("model_path", error)

    def test_validate_input_nonexistent(self):
        is_valid, error = self.scanner.validate_input(model_path="/nonexistent/model.onnx")
        self.assertFalse(is_valid)

    def test_validate_input_with_data(self):
        """测试有模型数据验证"""
        is_valid, error = self.scanner.validate_input(model_data=b'test data')
        self.assertTrue(is_valid)

    def test_detect_format_onnx(self):
        data = b'ONNX' + b'\x00' * 100
        format_detected = self.scanner._detect_format(data, None)
        self.assertEqual(format_detected, ModelFormat.ONNX)

    def test_detect_format_tflite(self):
        data = b'TFL3' + b'\x00' * 100
        format_detected = self.scanner._detect_format(data, None)
        self.assertEqual(format_detected, ModelFormat.TFLITE)

    def test_detect_format_specified(self):
        """测试指定格式检测"""
        data = b'random data'
        format_detected = self.scanner._detect_format(data, "onnx")
        self.assertEqual(format_detected, ModelFormat.ONNX)

    def test_filter_by_confidence(self):
        """测试置信度过滤"""
        findings = [
            SecurityFinding(
                ThreatCategory.BACKDOOR_TRIGGER,
                Severity.HIGH,
                "High confidence",
                "Desc",
                "loc",
                0.8,
                "Rec"
            ),
            SecurityFinding(
                ThreatCategory.BACKDOOR_TRIGGER,
                Severity.LOW,
                "Low confidence",
                "Desc",
                "loc",
                0.4,
                "Rec"
            )
        ]

        filtered = self.scanner._filter_by_confidence(findings)
        self.assertEqual(len(filtered), 1)
        self.assertEqual(filtered[0].confidence, 0.8)

    def test_calculate_risk_score_empty(self):
        """测试空结果风险分数"""
        score = self.scanner._calculate_risk_score([])
        self.assertEqual(score, 0.0)

    def test_calculate_risk_score_with_findings(self):
        findings = [
            SecurityFinding(
                ThreatCategory.BACKDOOR_TRIGGER,
                Severity.HIGH,
                "Test",
                "Desc",
                "loc",
                0.9,
                "Rec"
            )
        ]
        score = self.scanner._calculate_risk_score(findings)
        self.assertGreater(score, 0.0)
        self.assertLessEqual(score, 10.0)

    def test_serialize_result(self):
        """测试结果序列化"""
        metadata = ModelMetadata(
            format=ModelFormat.ONNX,
            name="test",
            producer="test",
            version="1.0",
            inputs=[],
            outputs=[],
            operators=[],
            file_size=1000,
            file_hash="abc123"
        )

        result = ScanResult(
            model_metadata=metadata,
            findings=[],
            risk_score=5.0,
            safe=False,
            scan_time=1.5
        )

        serialized = self.scanner._serialize_result(result)

        self.assertEqual(serialized["risk_score"], 5.0)
        self.assertEqual(serialized["safe"], False)
        self.assertEqual(serialized["model"]["name"], "test")

    def test_format_text_result(self):
        """测试文本格式结果"""
        metadata = ModelMetadata(
            format=ModelFormat.ONNX,
            name="test",
            producer="test",
            version="1.0",
            inputs=[],
            outputs=[],
            operators=[],
            file_size=1000,
            file_hash="abc123"
        )

        result = ScanResult(
            model_metadata=metadata,
            findings=[],
            risk_score=5.0,
            safe=False,
            scan_time=1.5
        )

        text = self.scanner._format_text_result(result)

        self.assertIn("test", text)
        self.assertIn("Risk Score", text)


class TestIntegration(unittest.TestCase):
    """集成测试"""

    def setUp(self):
        self.scanner = NNModelScanner()

    def test_analyze_with_bytes(self):
        # 创建模拟 ONNX 数据
        onnx_data = b'ONNX' + b'\x00' * 1000

        result = self.scanner.analyze(
            model_data=onnx_data,
            output_format="json"
        )

        self.assertTrue(result["success"])
        self.assertIn("result", result)

    def test_analyze_with_model_format(self):
        """测试指定模型格式分析"""
        data = b'test data'

        result = self.scanner.analyze(
            model_data=data,
            format="onnx",
            output_format="json"
        )

        self.assertTrue(result["success"])



if __name__ == "__main__":
    unittest.main()


