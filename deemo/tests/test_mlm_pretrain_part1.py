
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


class TestMaskType:
        """测试掩码类型枚举"""

    def test_mask_type_values(self):
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
        token = Token(value="mov", token_type="instruction", position=0)

        assert token.value == "mov"
        assert token.token_type == "instruction"
        assert token.position == 0
        assert token.is_masked is False
lass字段完整性$/d
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
        vocab = Vocabulary()

        assert vocab.size() == 5  # [PAD], [CLS], [SEP], [MASK], [UNK]
        assert "[CLS]" in vocab.token_to_id
        assert "[MASK]" in vocab.token_to_id

    def test_add_token(self):
        # 改进点标记——不阻塞当前功能
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

lass字段完整性$/d
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
        # 改进点标记——不阻塞当前功能
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


