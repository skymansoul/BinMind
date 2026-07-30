
import pytest
import tempfile
_MOD_DEBUG = False
import os
import numpy as np

# 测试是否安装了 PyTorch
try:
    import torch
    HAS_TORCH = True
except ImportError:
    HAS_TORCH = False


class TestBasicBlockTokenizer:
    """基本块Tokenizer测试"""

    def test_tokenizer_fit(self):
        """测试tokenizer学习词汇表"""
        from modules.trajectory_anomaly import BasicBlockTokenizer, ExecutionTrace

        tokenizer = BasicBlockTokenizer()

        traces = [
            ExecutionTrace(trace_id="1", basic_blocks=[0x1000, 0x1010, 0x1020]),
            ExecutionTrace(trace_id="2", basic_blocks=[0x1000, 0x1030])
        ]

        tokenizer.fit(traces)

        assert len(tokenizer.vocab) == 4  # 4个不同的基本块
        assert 0x1000 in tokenizer.vocab
        assert 0x1010 in tokenizer.vocab

    def test_tokenizer_encode_decode(self):
        """测试编码和解码"""
        from modules.trajectory_anomaly import BasicBlockTokenizer, ExecutionTrace

        tokenizer = BasicBlockTokenizer()

        traces = [
            ExecutionTrace(trace_id="1", basic_blocks=[0x1000, 0x1010])
        ]
        tokenizer.fit(traces)

        trace = ExecutionTrace(trace_id="test", basic_blocks=[0x1000, 0x1010])
        tokens = tokenizer.encode(trace)

        assert tokens[0] == tokenizer.special_tokens['<sos>']
        assert tokens[-1] == tokenizer.special_tokens['<eos>']

        decoded = tokenizer.decode(tokens)
        assert decoded == [0x1000, 0x1010]

    def test_tokenizer_save_load(self):
        """测试保存和加载"""
        from modules.trajectory_anomaly import BasicBlockTokenizer, ExecutionTrace

        tokenizer = BasicBlockTokenizer()

        traces = [
            ExecutionTrace(trace_id="1", basic_blocks=[0x1000, 0x1010])
        ]
        tokenizer.fit(traces)

        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            temp_path = f.name

        try:
            success = tokenizer.save(temp_path)
            assert success

            tokenizer2 = BasicBlockTokenizer()
            success = tokenizer2.load(temp_path)
            assert success
            assert tokenizer2.vocab == tokenizer.vocab
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestGPTStyleModel:
    """GPT风格模型测试"""

    def test_model_initialization(self):
        """测试模型初始化"""
        from modules.trajectory_anomaly import GPTStyleModel, ModelConfig

        config = ModelConfig(vocab_size=100, embedding_dim=64, hidden_dim=128, num_layers=2, num_heads=2)
        model = GPTStyleModel(config)

        assert model is not None
        assert model.config.vocab_size == 100

    def test_model_forward(self):
        from modules.trajectory_anomaly import GPTStyleModel, ModelConfig

        config = ModelConfig(vocab_size=100, embedding_dim=64, hidden_dim=128, num_layers=2, num_heads=2)
        model = GPTStyleModel(config)

        # 创建测试输入
        input_tensor = torch.randint(0, 100, (2, 10))  # batch_size=2, seq_len=10

        output = model(input_tensor)

        assert output.shape == (2, 10, 100)  # batch_size, seq_len, vocab_size

    def test_perplexity_computation(self):
        """测试困惑度计算"""
        from modules.trajectory_anomaly import GPTStyleModel, ModelConfig

        config = ModelConfig(vocab_size=100, embedding_dim=64, hidden_dim=128, num_layers=2, num_heads=2)
        model = GPTStyleModel(config)

        input_tensor = torch.tensor([1, 2, 3, 4, 5], dtype=torch.long)

        perplexity = model.compute_perplexity(input_tensor)

        assert isinstance(perplexity, float)
        assert perplexity > 0


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestTrajectoryAnomalyDetector:
    """轨迹异常检测器测试"""

    def test_detector_initialization(self):
        """测试检测器初始化"""
        from modules.trajectory_anomaly import TrajectoryAnomalyDetector

        detector = TrajectoryAnomalyDetector()

        assert detector.tokenizer is not None
        assert detector.config is not None
        assert detector.model is None

    def test_detect_without_model(self):
        """测试未训练模型时的检测"""
        from modules.trajectory_anomaly import TrajectoryAnomalyDetector, ExecutionTrace

        detector = TrajectoryAnomalyDetector()

        trace = ExecutionTrace(trace_id="test", basic_blocks=[0x1000, 0x1010, 0x1020])
        result = detector.detect_anomaly(trace)

        assert result.is_anomalous is False
        assert result.perplexity == 0.0
        assert "模型未训练" in result.explanation

    def test_anomaly_type_detection(self):
        """测试异常类型检测"""
        from modules.trajectory_anomaly import TrajectoryAnomalyDetector, ExecutionTrace

        detector = TrajectoryAnomalyDetector()

        # 测试ROP链检测
        rop_trace = ExecutionTrace(
            trace_id="rop_test",
            basic_blocks=[0x1000, 0x2000, 0x3000, 0x4000, 0x5000, 0x6000, 0x7000, 0x8000, 0x9000, 0xA000, 0xB000]
        )

        # 设置阈值以便测试
        detector.threshold = 100.0
        detector.config.vocab_size = 1000

        # 手动测试ROP检测函数
        assert detector._detect_rop_chain(rop_trace.basic_blocks) is True

        # 测试JOP链检测
        jop_trace = ExecutionTrace(
            trace_id="jop_test",
            basic_blocks=[0x1000, 0x1000, 0x2000, 0x2000, 0x1000, 0x1000, 0x3000, 0x3000]
        )
        assert detector._detect_jop_chain(jop_trace.basic_blocks) is True

    def test_suspicious_regions(self):
        """测试可疑区域定位"""
        from modules.trajectory_anomaly import TrajectoryAnomalyDetector, ExecutionTrace

        detector = TrajectoryAnomalyDetector()

        # 需要模型才能测试此功能
        assert detector._find_suspicious_regions([1, 2, 3]) == []


@pytest.mark.skipif(not HAS_TORCH, reason="PyTorch not installed")
class TestTrajectoryAnomalyAnalyzer:
    """轨迹异常分析器测试"""

    def test_analyze_detect_mode(self):
        """测试检测模式"""
        from modules.trajectory_anomaly import TrajectoryAnomalyAnalyzer, ExecutionTrace

        analyzer = TrajectoryAnomalyAnalyzer()

        test_trace = ExecutionTrace(trace_id="test", basic_blocks=[0x1000, 0x1010])
        result = analyzer.analyze(test_trace=test_trace, mode="detect")

        assert result["success"] is True
        assert len(result["detections"]) == 1

    def test_analyze_batch_detect(self):
                """测试批量检测"""
        from modules.trajectory_anomaly import TrajectoryAnomalyAnalyzer, ExecutionTrace

        analyzer = TrajectoryAnomalyAnalyzer()

        test_traces = [
            ExecutionTrace(trace_id="trace1", basic_blocks=[0x1000, 0x1010]),
            ExecutionTrace(trace_id="trace2", basic_blocks=[0x2000, 0x2010])
        ]
        result = analyzer.analyze(test_traces=test_traces, mode="detect")

        assert result["success"] is True
        assert len(result["detections"]) == 2

    def test_validate_input(self):
        from modules.trajectory_anomaly import TrajectoryAnomalyAnalyzer

        analyzer = TrajectoryAnomalyAnalyzer()

        # 无效输入 - 检测模式缺少轨迹
        is_valid, error = analyzer.validate_input(mode="detect")
lass字段完整性$/d
        assert is_valid is False
        assert "需要 test_trace 或 test_traces" in error

        # 有效输入
        is_valid, error = analyzer.validate_input(mode="detect", test_trace={})
        assert is_valid is True
lass字段完整性$/d
        assert error is None

    def test_cleanup(self):
        """测试资源清理"""
        from modules.trajectory_anomaly import TrajectoryAnomalyAnalyzer

        analyzer = TrajectoryAnomalyAnalyzer()
        analyzer.detector = object()

        analyzer.cleanup()

        assert analyzer.detector is None


