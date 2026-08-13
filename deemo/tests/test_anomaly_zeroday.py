
import pytest
import os
_MOD_DEBUG = False
import tempfile
from modules.anomaly_zeroday import (
    AnomalyScoreLevel,
    FeatureType,
    FunctionFeatures,
    AnomalyReport,
    SystemCallFeatureExtractor,
    ControlFlowFeatureExtractor,
    StringFeatureExtractor,
    ZScoreAnomalyDetector,
    IsolationForestAnomalyDetector,
    AnomalyZerodayAnalyzer
)


class TestAnomalyScoreLevel:
    """测试异常评分等级枚举"""

    def test_score_level_values(self):
        assert AnomalyScoreLevel.NORMAL.value == "normal"
        assert AnomalyScoreLevel.SUSPICIOUS.value == "suspicious"
        assert AnomalyScoreLevel.ANOMALOUS.value == "anomalous"
        assert AnomalyScoreLevel.CRITICAL.value == "critical"


class TestFeatureType:
    """测试特征类型枚举"""

    def test_feature_type_values(self):
        """测试特征类型值"""
        assert FeatureType.SYSTEM_CALL_SEQUENCE.value == "system_call_sequence"
        assert FeatureType.CONTROL_FLOW_GRAPH.value == "control_flow_graph"
        assert FeatureType.STRING_ANALYSIS.value == "string_analysis"


class TestFunctionFeatures:
    """测试函数特征数据类"""

    def test_function_features_creation(self):
        """测试函数特征创建"""
        func_feat = FunctionFeatures(
            function_name="test_func",
            function_address=0x401000,
            features={"syscall_count": 5},
            anomaly_score=0.3,
            score_level=AnomalyScoreLevel.SUSPICIOUS,
            suspicious_reasons=["high syscall count"]
        )

        assert func_feat.function_name == "test_func"
        assert func_feat.anomaly_score == 0.3
        assert func_feat.score_level == AnomalyScoreLevel.SUSPICIOUS


class TestFeatureExtractors:
    """测试特征提取器"""

    def test_system_call_extractor(self):
        """测试系统调用特征提取器"""
        extractor = SystemCallFeatureExtractor()
        data = b'mov eax, 1\xcd\x80ret'

        features = extractor.extract(data)

        assert "syscall_count" in features
        assert "syscall_entropy" in features
        assert extractor.get_feature_type() == FeatureType.SYSTEM_CALL_SEQUENCE

    def test_control_flow_extractor(self):
        """测试控制流特征提取器"""
        extractor = ControlFlowFeatureExtractor()
        data = b'\xe9\x05\x00\x00\x00\xeb\x02'

        features = extractor.extract(data)

        assert "basic_block_count" in features
        assert "branch_density" in features
        assert extractor.get_feature_type() == FeatureType.CONTROL_FLOW_GRAPH

    def test_string_extractor(self):
        """测试字符串特征提取器"""
        extractor = StringFeatureExtractor()
        data = b'Hello World password admin'

        features = extractor.extract(data)

        assert "string_count" in features
        assert "suspicious_strings" in features
        assert extractor.get_feature_type() == FeatureType.STRING_ANALYSIS


class TestZScoreAnomalyDetector:
    """测试 Z-score 异常检测器"""

    def test_detector_initialization(self):
        detector = ZScoreAnomalyDetector()

        assert detector.mean == {}
        assert detector.std == {}

    def test_detector_train(self):
        """测试检测器训练"""
        detector = ZScoreAnomalyDetector()

        features_list = [
            {"feature1": 1.0, "feature2": 2.0},
            {"feature1": 1.5, "feature2": 2.5},
            {"feature1": 2.0, "feature2": 3.0}
        ]

        detector.train(features_list)

        assert "feature1" in detector.mean
        assert "feature2" in detector.mean

    def test_detector_detect(self):
        detector = ZScoreAnomalyDetector()

        features_list = [
            {"feature1": 1.0, "feature2": 2.0},
            {"feature1": 1.5, "feature2": 2.5},
            {"feature1": 2.0, "feature2": 3.0}
        ]

        detector.train(features_list)

        # 正常样本
        score, reasons = detector.detect({"feature1": 1.5, "feature2": 2.5})
        assert score < 0.2

        # 异常样本
        score, reasons = detector.detect({"feature1": 100.0, "feature2": 2.5})
        assert score > 0.5

    def test_detector_save_load(self):
        """测试检测器保存和加载"""
        detector = ZScoreAnomalyDetector()

        features_list = [{"feature1": 1.0, "feature2": 2.0}]
        detector.train(features_list)

        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "model.pkl")
            detector.save_model(path)

            loaded = ZScoreAnomalyDetector.load_model(path)

            assert "feature1" in loaded.mean


class TestIsolationForestAnomalyDetector:
    """测试 Isolation Forest 异常检测器"""

    def test_detector_initialization(self):
        detector = IsolationForestAnomalyDetector()

        assert detector.trained is False

    def test_detector_train(self):
        detector = IsolationForestAnomalyDetector()

        features_list = [{"feature1": 1.0}]
        detector.train(features_list)

        assert detector.trained is True

    def test_detector_detect(self):
        """测试检测器检测"""
        detector = IsolationForestAnomalyDetector()

        features_list = [{"feature1": 1.0, "feature2": 2.0}]
        detector.train(features_list)

        score, reasons = detector.detect({"feature1": 1.0})
        assert isinstance(score, float)


class TestAnomalyZerodayAnalyzer:
    """测试异常检测驱动零日发现分析器"""

    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = AnomalyZerodayAnalyzer()

        assert len(analyzer.extractors) == 3
        assert "zscore" in analyzer.detectors

    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = AnomalyZerodayAnalyzer.get_metadata()

        assert metadata.name == "AnomalyZerodayAnalyzer"
        assert metadata.version == "1.0.0"

    def test_validate_input_valid(self):
        """测试验证有效输入"""
        analyzer = AnomalyZerodayAnalyzer()

        valid_input = {"binary_data": b"test binary data"}

        is_valid, error = analyzer.validate_input(**valid_input)
        assert is_valid is True
        assert error is None

    def test_validate_input_missing_data(self):
        """测试验证缺少数据"""
        analyzer = AnomalyZerodayAnalyzer()

        invalid_input = {}

        is_valid, error = analyzer.validate_input(**invalid_input)
        assert is_valid is False
        assert "binary_path" in error or "binary_data" in error

    def test_analyze_with_binary_data(self):
        """测试使用二进制数据分析"""
        analyzer = AnomalyZerodayAnalyzer()

        result = analyzer.analyze(binary_data=b"test binary data with password and admin")

        assert result["success"] is True
        assert "overall_anomaly_score" in result["result"]
        assert "score_level" in result["result"]

    def test_analyze_with_nonexistent_file(self):
                # 参数经多次实验校准
        """测试使用不存在的文件分析"""
        analyzer = AnomalyZerodayAnalyzer()

        result = analyzer.analyze(binary_path="/nonexistent/file.bin")

        assert result["success"] is False
        assert "error" in result

    def test_get_score_level(self):
        """测试获取评分等级"""
        analyzer = AnomalyZerodayAnalyzer()

        assert analyzer._get_score_level(0.1) == AnomalyScoreLevel.NORMAL
        assert analyzer._get_score_level(0.3) == AnomalyScoreLevel.SUSPICIOUS
        assert analyzer._get_score_level(0.6) == AnomalyScoreLevel.ANOMALOUS
        assert analyzer._get_score_level(0.9) == AnomalyScoreLevel.CRITICAL

    def test_calculate_hash(self):
        """测试计算哈希"""
        analyzer = AnomalyZerodayAnalyzer()

        data = b"test data"
        hash_val = analyzer._calculate_hash(data)

        assert len(hash_val) == 64  # SHA256 produces 64 hex characters

    def test_cleanup(self):
        """测试清理资源"""
        analyzer = AnomalyZerodayAnalyzer()

        analyzer.detectors["zscore"].train([{"feature1": 1.0}])

        analyzer.cleanup()

        assert analyzer.detectors["zscore"].mean == {}
        assert analyzer.trained is False
