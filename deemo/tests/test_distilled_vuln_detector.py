import pytest
import tempfile
import os

# 测试是否安装了 transformers
try:
    from transformers import BertTokenizer
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False


class TestVulnerabilityDataGenerator:
    """漏洞数据生成器测试"""
    
    def test_generate_vulnerability_samples(self):
        """测试生成漏洞样本"""
        from modules.distilled_vuln_detector import VulnerabilityDataGenerator
        
        generator = VulnerabilityDataGenerator()
        samples = generator.generate_samples(["CWE-121", "CWE-78"], count_per_type=2)
        
        assert len(samples) == 4
        for sample in samples:
            assert sample.label == 1  # 漏洞样本
            assert sample.source == "generated"
            assert sample.id is not None
    
    def test_generate_benign_samples(self):
        """测试生成良性样本"""
        from modules.distilled_vuln_detector import VulnerabilityDataGenerator
        
        generator = VulnerabilityDataGenerator()
        samples = generator.generate_benign_samples(count=5)
        
        assert len(samples) == 5
        for sample in samples:
            assert sample.label == 0  # 良性样本
            assert sample.source == "generated"
    
    def test_sample_code_generation(self):
        """测试样本代码生成"""
        from modules.distilled_vuln_detector import VulnerabilityDataGenerator
        
        generator = VulnerabilityDataGenerator()
        code = generator._generate_sample_code("CWE-121", 0)
        
        assert "strcpy" in code
        assert "buffer" in code


@pytest.mark.skipif(not HAS_TRANSFORMERS, reason="transformers not installed")
class TestDistilledVulnerabilityDetector:
    """知识蒸馏漏洞检测器测试"""
    
    def test_detector_initialization(self):
        """测试检测器初始化"""
        from modules.distilled_vuln_detector import DistilledVulnerabilityDetector
        
        detector = DistilledVulnerabilityDetector()
        
        assert detector.tokenizer is not None
        assert detector.config is not None
        assert detector.model is None  # 模型未加载
    
    def test_prepare_dataset(self):
        """测试数据集准备"""
        from modules.distilled_vuln_detector import DistilledVulnerabilityDetector, VulnerabilitySample
        
        detector = DistilledVulnerabilityDetector()
        
        samples = [
            VulnerabilitySample(id="1", code="void test() {}", label=0),
            VulnerabilitySample(id="2", code="void test() { strcpy(buf, input); }", label=1)
        ]
        
        dataset = detector._prepare_dataset(samples)
        
        assert "text" in dataset.features
        assert "label" in dataset.features
        assert len(dataset) == 2
    
    def test_detect_without_model(self):
        """测试未加载模型时的检测"""
        from modules.distilled_vuln_detector import DistilledVulnerabilityDetector
        
        detector = DistilledVulnerabilityDetector()
        
        code = "void vulnerable() { strcpy(buffer, input); }"
        result = detector.detect(code)
        
        assert result.is_vulnerable is False
        assert result.confidence == 0.0
        assert "模型未加载" in result.explanation
    
    def test_vulnerability_type_prediction(self):
        """测试漏洞类型预测"""
        from modules.distilled_vuln_detector import DistilledVulnerabilityDetector
        
        detector = DistilledVulnerabilityDetector()
        
        test_cases = [
            ("void test() { strcpy(buffer, input); }", "CWE-121"),
            ("void test() { system(cmd); }", "CWE-78"),
            ("void test() { sprintf(buf, \"%s\", input); }", "CWE-20")
        ]
        
        for code, expected_type in test_cases:
            vuln_type = detector._predict_vulnerability_type(code)
            assert vuln_type == expected_type


@pytest.mark.skipif(not HAS_TRANSFORMERS, reason="transformers not installed")
class TestActiveLearningManager:
    """主动学习管理器测试"""
    
    def test_uncertainty_calculation(self):
        """测试不确定性计算"""
        from modules.distilled_vuln_detector import ActiveLearningManager, ActiveLearningConfig
        
        # 创建模拟检测器
        class MockDetector:
            def detect(self, code):
                from modules.distilled_vuln_detector import DetectionResult
                confidence = 0.6  # 中等置信度
                return DetectionResult(
                    function_name="test",
                    function_address=0,
                    is_vulnerable=True,
                    confidence=confidence,
                    vulnerability_type="CWE-121"
                )
        
        config = ActiveLearningConfig(strategy="least_confidence")
        manager = ActiveLearningManager(MockDetector(), config)
        
        uncertainty = manager._calculate_uncertainty(0.6)
        assert uncertainty == pytest.approx(0.4)
        
        # 测试熵计算
        config.strategy = "entropy"
        uncertainty = manager._calculate_uncertainty(0.5)
        assert uncertainty == pytest.approx(1.0)  # 最大熵
    
    def test_select_samples(self):
        """测试样本选择"""
        from modules.distilled_vuln_detector import (
            ActiveLearningManager, ActiveLearningConfig, 
            VulnerabilitySample, DetectionResult
        )
        
        class MockDetector:
            def __init__(self):
                self.confidence_values = [0.9, 0.5, 0.7, 0.3, 0.8]
                self.index = 0
            
            def detect(self, code):
                confidence = self.confidence_values[self.index % len(self.confidence_values)]
                self.index += 1
                return DetectionResult(
                    function_name="test",
                    function_address=0,
                    is_vulnerable=True,
                    confidence=confidence,
                    vulnerability_type="CWE-121"
                )
        
        config = ActiveLearningConfig(enabled=True, sample_count=2)
        manager = ActiveLearningManager(MockDetector(), config)
        
        unlabeled_samples = [
            VulnerabilitySample(id=f"sample_{i}", code=f"code_{i}", label=-1)
            for i in range(5)
        ]
        
        selected = manager.select_samples(unlabeled_samples)
        
        assert len(selected) == 2


@pytest.mark.skipif(not HAS_TRANSFORMERS, reason="transformers not installed")
class TestDistilledVulnDetectorAnalyzer:
    """知识蒸馏漏洞检测器分析器测试"""
    
    def test_analyze_detect_mode(self):
        """测试检测模式分析"""
        from modules.distilled_vuln_detector import DistilledVulnDetectorAnalyzer
        
        analyzer = DistilledVulnDetectorAnalyzer()
        
        code = "void test() { strcpy(buffer, input); }"
        result = analyzer.analyze(code=code, mode="detect")
        
        assert result["success"] is True
        assert len(result["detections"]) == 1
    
    def test_analyze_batch_detect(self):
        """测试批量检测"""
        from modules.distilled_vuln_detector import DistilledVulnDetectorAnalyzer
        
        analyzer = DistilledVulnDetectorAnalyzer()
        
        code_list = [
            "void test1() { strcpy(buffer, input); }",
            "void test2() { int a = 1; }"
        ]
        result = analyzer.analyze(code_list=code_list, mode="detect")
        
        assert result["success"] is True
        assert len(result["detections"]) == 2
    
    def test_validate_input(self):
        """测试输入验证"""
        from modules.distilled_vuln_detector import DistilledVulnDetectorAnalyzer
        
        analyzer = DistilledVulnDetectorAnalyzer()
        
        # 无效输入 - 检测模式缺少代码
        is_valid, error = analyzer.validate_input(mode="detect")
        assert is_valid is False
        assert "需要 code 或 code_list" in error
        
        # 有效输入
        is_valid, error = analyzer.validate_input(mode="detect", code="test")
        assert is_valid is True
        assert error is None
    
    def test_cleanup(self):
        """测试资源清理"""
        from modules.distilled_vuln_detector import DistilledVulnDetectorAnalyzer
        
        analyzer = DistilledVulnDetectorAnalyzer()
        analyzer.detector = object()
        analyzer.active_learning_manager = object()
        
        analyzer.cleanup()
        
        assert analyzer.detector is None
        assert analyzer.active_learning_manager is None