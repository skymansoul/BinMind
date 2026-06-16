"""
掩码语言模型预训练模块测试
"""

import pytest
import os
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


class TestMaskType:
    """测试掩码类型枚举"""
    
    def test_mask_type_values(self):
        """测试掩码类型值"""
        assert MaskType.INSTRUCTION.value == "instruction"
        assert MaskType.FUNCTION_NAME.value == "function_name"
        assert MaskType.DATA_REFERENCE.value == "data_reference"
        assert MaskType.OPERAND.value == "operand"
        assert MaskType.ALL.value == "all"


class TestMLMTaskType:
    """测试 MLM 任务类型枚举"""
    
    def test_task_type_values(self):
        """测试任务类型值"""
        assert MLMTaskType.MASKED_LANGUAGE_MODELING.value == "masked_language_modeling"
        assert MLMTaskType.NEXT_INSTRUCTION_PREDICTION.value == "next_instruction_prediction"
        assert MLMTaskType.FUNCTION_CLASSIFICATION.value == "function_classification"
        assert MLMTaskType.CALL_SITE_RESOLUTION.value == "call_site_resolution"


class TestToken:
    """测试词元数据类"""
    
    def test_token_creation(self):
        """测试词元创建"""
        token = Token(value="mov", token_type="instruction", position=0)
        
        assert token.value == "mov"
        assert token.token_type == "instruction"
        assert token.position == 0
        assert token.is_masked is False
        assert token.original_value is None
    
    def test_token_masked(self):
        """测试掩码词元"""
        token = Token(
            value="[MASK]",
            token_type="instruction",
            position=1,
            is_masked=True,
            original_value="mov"
        )
        
        assert token.is_masked is True
        assert token.original_value == "mov"


class TestVocabulary:
    """测试词汇表类"""
    
    def test_vocabulary_initialization(self):
        """测试词汇表初始化"""
        vocab = Vocabulary()
        
        assert vocab.size() == 5  # [PAD], [CLS], [SEP], [MASK], [UNK]
        assert "[CLS]" in vocab.token_to_id
        assert "[MASK]" in vocab.token_to_id
    
    def test_add_token(self):
        """测试添加词元"""
        vocab = Vocabulary()
        initial_size = vocab.size()
        
        idx = vocab.add_token("mov")
        
        assert idx == initial_size
        assert vocab.size() == initial_size + 1
        assert vocab.get_id("mov") == idx
    
    def test_get_id(self):
        """测试获取词元 ID"""
        vocab = Vocabulary()
        
        # 添加词元
        vocab.add_token("mov")
        vocab.add_token("eax")
        
        assert vocab.get_id("mov") == 5
        assert vocab.get_id("eax") == 6
        assert vocab.get_id("unknown_token") == vocab.get_id("[UNK]")
    
    def test_get_token(self):
        """测试获取词元"""
        vocab = Vocabulary()
        
        vocab.add_token("mov")
        
        assert vocab.get_token(5) == "mov"
        assert vocab.get_token(999) == "[UNK]"
    
    def test_vocabulary_save_load(self):
        """测试词汇表保存和加载"""
        vocab = Vocabulary()
        vocab.add_token("mov")
        vocab.add_token("eax")
        
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, "vocab.json")
            vocab.save(path)
            
            loaded_vocab = Vocabulary.load(path)
            
            assert loaded_vocab.size() == vocab.size()
            assert loaded_vocab.get_id("mov") == vocab.get_id("mov")


class TestMLMDataset:
    """测试 MLM 数据集类"""
    
    def test_dataset_initialization(self):
        """测试数据集初始化"""
        vocab = Vocabulary()
        config = MLMTrainingConfig()
        dataset = MLMDataset(vocab, config)
        
        assert len(dataset) == 0
    
    def test_add_decompiled_function(self):
        """测试添加反编译函数"""
        vocab = Vocabulary()
        config = MLMTrainingConfig()
        dataset = MLMDataset(vocab, config)
        
        function_code = "mov eax, [ebp+8]\nadd eax, ebx\nret"
        dataset.add_decompiled_function(function_code, "test_func")
        
        assert len(dataset) == 1
    
    def test_tokenize_function(self):
        """测试分词函数"""
        vocab = Vocabulary()
        config = MLMTrainingConfig()
        dataset = MLMDataset(vocab, config)
        
        function_code = "mov eax, 0x10"
        tokens = dataset._tokenize_function(function_code, "test_func")
        
        assert len(tokens) > 0
        assert tokens[0].value == "[CLS]"
        assert tokens[-1].value == "[SEP]"


class TestMLMPretrainAnalyzer:
    """测试 MLM 预训练分析器"""
    
    def test_analyzer_initialization(self):
        """测试分析器初始化"""
        analyzer = MLMPretrainAnalyzer()
        
        assert analyzer.vocabulary is not None
        assert analyzer.dataset is not None
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
