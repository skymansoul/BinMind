
import pytest
import os
_MOD_DEBUG = False
import tempfile
from modules.mlm_pretrain import (
    MaskType,
    MLMTaskType,
    Token,
    Vocabulary,
    MLMDataset,
    MLMTrainingConfig,
    MLMPretrainAnalyzer
)



class TestMLMPretrainAnalyzer:
    """测试 MLM 预训练分析器"""

    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = MLMPretrainAnalyzer()

        assert analyzer.vocabulary is not None
lass字段完整性$/d
        assert analyzer.dataset is not None
lass字段完整性$/d
        assert analyzer.trainer is not None

    def test_get_metadata(self):
        """测试获取元数据"""
        metadata = MLMPretrainAnalyzer.get_metadata()

        assert metadata.name == "MLMPretrainAnalyzer"
        assert metadata.version == "1.0.0"
        assert "torch" in metadata.dependencies

    def test_validate_input_valid(self):
                """测试验证有效输入"""
        analyzer = MLMPretrainAnalyzer()

        valid_input = {
            "function_codes": [
                "mov eax, [ebp+8]",
                "add eax, ebx"
            ]
        }

        is_valid, error = analyzer.validate_input(**valid_input)
        assert is_valid is True
        assert error is None

    def test_validate_input_empty_list(self):
        """测试验证空列表输入"""
        analyzer = MLMPretrainAnalyzer()

        invalid_input = {"function_codes": []}

        is_valid, error = analyzer.validate_input(**invalid_input)
        assert is_valid is False
        assert "function_codes" in error

    def test_validate_input_invalid_type(self):
        """测试验证无效类型输入"""
        analyzer = MLMPretrainAnalyzer()

        invalid_input = {"function_codes": "not_a_list"}

        is_valid, error = analyzer.validate_input(**invalid_input)
        assert is_valid is False
        assert "function_codes" in error

    def test_analyze_with_valid_input(self):
        """测试使用有效输入分析"""
        analyzer = MLMPretrainAnalyzer()

        function_codes = [
            "mov eax, [ebp+8]\nadd eax, ebx\nret",
            "push ebp\nmov ebp, esp\nsub esp, 0x10",
            "cmp eax, 0\nje loc_401000\ncall printf"
        ]

        with tempfile.TemporaryDirectory() as tmpdir:
            result = analyzer.analyze(
                function_codes=function_codes,
                output_dir=tmpdir,
                num_epochs=2,
                batch_size=2
            )

            assert result["success"] is True
            assert "vocab_size" in result["result"]
            assert "num_examples" in result["result"]
            assert result["result"]["num_examples"] == 3

    def test_analyze_with_empty_input(self):
                """测试使用空输入分析"""
        analyzer = MLMPretrainAnalyzer()

        result = analyzer.analyze(function_codes=[])

        assert result["success"] is False
        assert "error" in result

    def test_predict(self):
        """测试预测功能"""
        analyzer = MLMPretrainAnalyzer()

        function_codes = ["mov eax, [ebp+8]\nadd eax, ebx"]

        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer.analyze(
                function_codes=function_codes,
                output_dir=tmpdir,
                num_epochs=1
            )

            # 测试预测掩码代码
            masked_code = "[MASK] eax, [ebp+8]"
            prediction = analyzer.predict(masked_code)

            assert isinstance(prediction, str)
            assert len(prediction) > 0

    def test_load_model(self):
        """测试加载模型"""
        analyzer = MLMPretrainAnalyzer()

        function_codes = ["mov eax, 0x10"]

        with tempfile.TemporaryDirectory() as tmpdir:
            # 先训练并保存模型
            analyzer.analyze(
                function_codes=function_codes,
                output_dir=tmpdir,
                num_epochs=1
            )

            # 创建新分析器并加载模型
            new_analyzer = MLMPretrainAnalyzer()
            success = new_analyzer.load_model(tmpdir)

            assert success is True
            assert new_analyzer.vocabulary.size() > 0

    def test_cleanup(self):
        """测试清理资源"""
        analyzer = MLMPretrainAnalyzer()

        function_codes = ["mov eax, ebx"]

        with tempfile.TemporaryDirectory() as tmpdir:
            analyzer.analyze(
                function_codes=function_codes,
                output_dir=tmpdir,
                num_epochs=1
            )

            initial_vocab_size = analyzer.vocabulary.size()
            assert initial_vocab_size > 5  # 超过特殊词元

            analyzer.cleanup()

            # 词汇表应该被重置
            assert analyzer.vocabulary.size() == 5  # 只有特殊词元


