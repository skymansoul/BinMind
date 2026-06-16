"""Tests for ML function boundary detection module"""

import pytest
from modules.function_boundary import (
    BoundaryDetectionMethod,
    FunctionType,
    ConfidenceLevel,
    FunctionBoundary,
    BoundaryDetectionResult,
    MLFeatureVector,
    MLModelInterface,
    HeuristicAnalyzer,
    FunctionBoundaryDetector
)


class TestBoundaryDetectionMethodEnum:
    def test_boundary_detection_method_values(self):
        assert BoundaryDetectionMethod.ML_MODEL.value == "ml_model"
        assert BoundaryDetectionMethod.HEURISTIC.value == "heuristic"
        assert BoundaryDetectionMethod.HYBRID.value == "hybrid"


class TestFunctionTypeEnum:
    def test_function_type_values(self):
        assert FunctionType.NORMAL.value == "normal"
        assert FunctionType.THUNK.value == "thunk"
        assert FunctionType.INTERRUPT_HANDLER.value == "interrupt_handler"
        assert FunctionType.STUB.value == "stub"
        assert FunctionType.INLINE.value == "inline"


class TestConfidenceLevelEnum:
    def test_confidence_level_values(self):
        assert ConfidenceLevel.HIGH.value == "high"
        assert ConfidenceLevel.MEDIUM.value == "medium"
        assert ConfidenceLevel.LOW.value == "low"


class TestFunctionBoundaryDataclass:
    def test_function_boundary_creation(self):
        boundary = FunctionBoundary(
            start_address=0x1000,
            end_address=0x1100,
            function_type=FunctionType.NORMAL,
            confidence=ConfidenceLevel.HIGH
        )
        assert boundary.start_address == 0x1000
        assert boundary.end_address == 0x1100
        assert boundary.function_type == FunctionType.NORMAL
        assert boundary.confidence == ConfidenceLevel.HIGH


class TestBoundaryDetectionResultDataclass:
    def test_boundary_detection_result_creation(self):
        boundaries = [
            FunctionBoundary(
                start_address=0x1000,
                end_address=0x1100,
                function_type=FunctionType.NORMAL,
                confidence=ConfidenceLevel.HIGH
            )
        ]
        result = BoundaryDetectionResult(
            boundaries=boundaries,
            method=BoundaryDetectionMethod.HYBRID,
            total_functions=1,
            confidence_summary={"high": 1, "medium": 0, "low": 0},
            runtime_ms=10.5
        )
        assert len(result.boundaries) == 1
        assert result.method == BoundaryDetectionMethod.HYBRID
        assert result.total_functions == 1


class TestMLFeatureVectorDataclass:
    def test_ml_feature_vector_creation(self):
        features = MLFeatureVector(
            bytes_before=b"\x55\x48",
            bytes_after=b"\x89\xe5",
            instruction_pattern="push rbp",
            section_info="code",
            entropy=0.85,
            opcode_frequency={"0x55": 1, "0x48": 1},
            function_call_density=0.2
        )
        assert features.entropy == 0.85
        assert features.section_info == "code"


class TestMLModelInterface:
    def test_model_interface_initialization(self):
        model = MLModelInterface()
        assert model.model_path is None
        assert model._model is None

    def test_model_prediction(self):
        model = MLModelInterface()
        features = MLFeatureVector(
            bytes_before=b"",
            bytes_after=b"\x55",
            instruction_pattern="",
            section_info="",
            entropy=0.9,
            opcode_frequency={},
            function_call_density=0.5
        )
        prediction, confidence = model.predict(features)
        assert prediction in [0, 1]
        assert 0 <= confidence <= 1


class TestHeuristicAnalyzer:
    def test_heuristic_analyzer_initialization(self):
        analyzer = HeuristicAnalyzer()
        assert 'function_start' in analyzer.opcode_patterns

    def test_detect_boundary(self):
        analyzer = HeuristicAnalyzer()
        data = b"\x55\x00\x00\x00\x00"
        assert analyzer.detect_boundary(data, 0) is True
        assert analyzer.detect_boundary(data, 1) is False

    def test_find_candidate_boundaries(self):
        analyzer = HeuristicAnalyzer()
        data = b"\x55\x00" * 100
        boundaries = analyzer.find_candidate_boundaries(data)
        assert len(boundaries) > 0


class TestFunctionBoundaryDetector:
    def setup_method(self):
        self.detector = FunctionBoundaryDetector()

    def test_detector_initialization(self):
        assert self.detector.method == BoundaryDetectionMethod.HYBRID

    def test_get_metadata(self):
        metadata = self.detector.get_metadata()
        assert metadata.name == "FunctionBoundaryDetector"
        assert metadata.version == "1.0.0"

    def test_analyze_with_binary_data(self):
        binary_data = b"\x55\x48\x89\xe5\xc3" * 10
        result = self.detector.analyze(binary_data=binary_data)
        assert result["success"] is True
        assert "result" in result

    def test_analyze_missing_binary_data(self):
        result = self.detector.analyze()
        assert result["success"] is False
        assert "error" in result

    def test_analyze_with_ml_method(self):
        detector = FunctionBoundaryDetector(method=BoundaryDetectionMethod.ML_MODEL)
        binary_data = b"\x55\x48\x89\xe5\xc3" * 10
        result = detector.analyze(binary_data=binary_data)
        assert result["success"] is True

    def test_analyze_with_heuristic_method(self):
        detector = FunctionBoundaryDetector(method=BoundaryDetectionMethod.HEURISTIC)
        binary_data = b"\x55\x48\x89\xe5\xc3" * 10
        result = detector.analyze(binary_data=binary_data)
        assert result["success"] is True

    def test_analyze_with_hybrid_method(self):
        detector = FunctionBoundaryDetector(method=BoundaryDetectionMethod.HYBRID)
        binary_data = b"\x55\x48\x89\xe5\xc3" * 10
        result = detector.analyze(binary_data=binary_data)
        assert result["success"] is True

    def test_set_method(self):
        self.detector.set_method(BoundaryDetectionMethod.HEURISTIC)
        assert self.detector.method == BoundaryDetectionMethod.HEURISTIC
