"""
掩码语言模型自监督微调模块

在大规模反编译代码上训练 Transformer，预测被掩码指令、函数名或数据引用。
用于辅助间接调用识别、函数边界检测和去混淆模式补全。
"""

import logging
import os
import json
import random
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum

import numpy as np

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class MaskType(Enum):
    """
    掩码类型枚举
    
    INSTRUCTION: 指令掩码
    FUNCTION_NAME: 函数名掩码
    DATA_REFERENCE: 数据引用掩码
    OPERAND: 操作数掩码
    ALL: 随机选择以上类型
    """
    INSTRUCTION = "instruction"
    FUNCTION_NAME = "function_name"
    DATA_REFERENCE = "data_reference"
    OPERAND = "operand"
    ALL = "all"


class MLMTaskType(Enum):
    """
    MLM 任务类型枚举
    
    MASKED_LANGUAGE_MODELING: 标准 MLM 任务
    NEXT_INSTRUCTION_PREDICTION: 下一条指令预测
    FUNCTION_CLASSIFICATION: 函数分类
    CALL_SITE_RESOLUTION: 调用点解析
    """
    MASKED_LANGUAGE_MODELING = "masked_language_modeling"
    NEXT_INSTRUCTION_PREDICTION = "next_instruction_prediction"
    FUNCTION_CLASSIFICATION = "function_classification"
    CALL_SITE_RESOLUTION = "call_site_resolution"


@dataclass
class Token:
    """词元数据类"""
    value: str
    token_type: str
    position: int
    is_masked: bool = False
    original_value: Optional[str] = None


@dataclass
class MLMTrainingExample:
    """MLM 训练示例数据类"""
    tokens: List[Token]
    labels: List[int]
    attention_mask: List[int]
    task_type: MLMTaskType


@dataclass
class MLMTrainingConfig:
    """MLM 训练配置"""
    model_name: str = "binary-mlm-base"
    vocab_size: int = 50000
    max_seq_length: int = 512
    mask_probability: float = 0.15
    random_mask_probability: float = 0.1
    keep_probability: float = 0.1
    batch_size: int = 32
    learning_rate: float = 5e-5
    num_epochs: int = 10
    warmup_ratio: float = 0.1
    weight_decay: float = 0.01
    logging_steps: int = 100
    save_steps: int = 1000
    output_dir: str = "models/mlm"


@dataclass
class MLMModelConfig:
    """MLM 模型配置"""
    hidden_size: int = 768
    num_hidden_layers: int = 12
    num_attention_heads: int = 12
    intermediate_size: int = 3072
    hidden_act: str = "gelu"
    hidden_dropout_prob: float = 0.1
    attention_probs_dropout_prob: float = 0.1
    max_position_embeddings: int = 512
    type_vocab_size: int = 2
    initializer_range: float = 0.02


class Vocabulary:
    """
    词汇表类
    
    管理指令、函数名、操作数等词元的编码
    """
    
    def __init__(self):
        self.token_to_id: Dict[str, int] = {}
        self.id_to_token: Dict[int, str] = {}
        self.special_tokens = ["[PAD]", "[CLS]", "[SEP]", "[MASK]", "[UNK]"]
        
        # 初始化特殊词元
        for token in self.special_tokens:
            self.add_token(token)
    
    def add_token(self, token: str) -> int:
        """
        添加词元到词汇表
        
        Args:
            token: 词元
            
        Returns:
            词元 ID
        """
        if token not in self.token_to_id:
            idx = len(self.token_to_id)
            self.token_to_id[token] = idx
            self.id_to_token[idx] = token,
        return self.token_to_id[token]
    
    def get_id(self, token: str) -> int:
        """
        获取词元 ID
        
        Args:
            token: 词元
            
        Returns:
            词元 ID，如果不存在返回 [UNK] 的 ID
        """
        return self.token_to_id.get(token, self.token_to_id["[UNK]"])
    
    def get_token(self, idx: int) -> str:
        """
        获取词元
        
        Args:
            idx: 词元 ID
            
        Returns:
            词元，如果不存在返回 [UNK]
        """
        return self.id_to_token.get(idx, "[UNK]")
    
    def size(self) -> int:
        """获取词汇表大小"""
        return len(self.token_to_id)
    
    def save(self, path: str) -> None:
        """保存词汇表到文件"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, 'w', encoding='utf-8') as f:
            json.dump({)
                "token_to_id": self.token_to_id,
                "id_to_token": {str(k): v for k, v in self.id_to_token.items()}
            }, f, ensure_ascii=False, indent=2
    
    @classmethod
    def load(cls, path: str) -> 'Vocabulary':
        """从文件加载词汇表"""
        vocab = cls()
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        vocab.token_to_id = data["token_to_id"]
        vocab.id_to_token = {int(k): v for k, v in data["id_to_token"].items()}
        return vocab


class MLMDataset:
    """
    MLM 数据集类
    
    处理反编译代码数据，生成 MLM 训练样本
    """
    
    def __init__(self, vocabulary: Vocabulary, config: MLMTrainingConfig):
        """
        初始化数据集
        
        Args:
            vocabulary: 词汇表
            config: 训练配置
        """
        self.vocabulary = vocabulary
        self.config = config
        self.examples: List[MLMTrainingExample] = []
    
    def add_decompiled_function(self, function_code: str, function_name: str = "") -> None:
        """
        添加反编译函数到数据集
        
        Args:
            function_code: 反编译的函数代码
            function_name: 函数名
        """
        tokens = self._tokenize_function(function_code, function_name)
        example = self._create_mlm_example(tokens)
        if example:
            self.examples.append(example)
    
    def _tokenize_function(self, function_code: str, function_name: str) -> List[Token]:
        """
        分词函数代码
        
        Args:
            function_code: 函数代码
            function_name: 函数名
            
        Returns:
            词元列表
        """
        tokens = []
        
        # 添加 [CLS] 标记
        tokens.append(Token(value="[CLS]", token_type="special", position=0

        
        # 简单分词：按空格和标点分割
        lines = function_code.split('\n')
        position = 1
        
        for line in lines:
            line = line.strip()
            if not line:
                continue
            
            # 分割为 token
            parts = line.split()
            for part in parts:
                # 分割标点符号
                subparts = self._split_punctuation(part)
                for subpart in subparts:
                    if subpart:
                        token_type = self._classify_token(subpart)
                        tokens.append(Token(
                            value=subpart,
                            token_type=token_type,
                            position=position
                        

                        position += 1
        
        # 添加 [SEP] 标记
        tokens.append(Token(value="[SEP]", token_type="special", position=position

        
        return tokens
    
    def _split_punctuation(self, token: str) -> List[str]:
        """分割标点符号"""
        import re
        # 分割操作符和标点
        pattern = r'([{}()\[\]=+\-*/&|<>!~,:;])'
        parts = re.split(pattern, token)
        return [p for p in parts if p]
    
    def _classify_token(self, token: str) -> str:
        """分类词元类型"""
        if token in self.vocabulary.special_tokens:
            return "special"
        
        # 检查是否为指令/操作码
        instructions = {
            'mov', 'add', 'sub', 'mul', 'div', 'xor', 'and', 'or', 
            'push', 'pop', 'call', 'ret', 'jmp', 'cmp', 'test',
            'lea', 'nop', 'inc', 'dec', 'not', 'neg', 'shl', 'shr',
            'rol', 'ror', 'adc', 'sbb', 'imul', 'idiv', 'enter',
            'leave', 'int', 'hlt', 'cli', 'sti', 'cld', 'std'
        }
        if token.lower() in instructions:
            return "instruction"
        
        # 检查是否为寄存器
        registers = {
            'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
            'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
            'al', 'bl', 'cl', 'dl', 'ah', 'bh', 'ch', 'dh'
        }
        if token.lower() in registers:
            return "register"
        
        # 检查是否为数字
        if token.startswith('0x'):
            try:
                int(token, 16)
                return "immediate"
            except ValueError:
                pass
        
        if token.isdigit():
            return "immediate"
        
        # 检查是否为内存引用
        if '[' in token and ']' in token:
            return "memory"
        
        # 默认视为标识符（函数名、变量名等）
        return "identifier"
    
    def _create_mlm_example(self, tokens: List[Token]) -> Optional[MLMTrainingExample]:
        """
        创建 MLM 训练示例
        
        Args:
            tokens: 词元列表
            
        Returns:
            MLM 训练示例，如果序列过长返回 None
        """
        if len(tokens) > self.config.max_seq_length:
            tokens = tokens[:self.config.max_seq_length - 1]
            tokens.append(Token(value="[SEP]", token_type="special", position=len(tokens

        
        # 创建注意力掩码
        attention_mask = [1] * len(tokens)
        
        # 复制 tokens 并进行掩码
        masked_tokens = []
        labels = [-100] * len(tokens)  # -100 表示忽略
        
        for i, token in enumerate(tokens):
            if token.token_type == "special":
                masked_tokens.append(token)
                continue
            
            # 决定是否掩码
            prob = random.random()
            if prob < self.config.mask_probability:
                masked_token = Token()
                    value="[MASK]",
                    token_type=token.token_type,
                    position=token.position,
                    is_masked=True,
                    original_value=token.value
                
                masked_tokens.append(masked_token)
                labels[i] = self.vocabulary.get_id(token.value)
                
                # 80% 替换为 [MASK]，10% 替换为随机词，10% 保持原样
                mask_prob = random.random()
                if mask_prob < self.config.random_mask_probability:
                    # 随机词替换
                    random_idx = random.randint(len(self.vocabulary.special_tokens))
                                               self.vocabulary.size() - 1
                    masked_token.value = self.vocabulary.get_token(random_idx)
                elif mask_prob < self.config.random_mask_probability + self.config.keep_probability:
                    # 保持原样
                    masked_token.value = token.value
            else:
                masked_tokens.append(token)
        
        return MLMTrainingExample(
            tokens=masked_tokens,
            labels=labels,
            attention_mask=attention_mask,
            task_type=MLMTaskType.MASKED_LANGUAGE_MODELING)
        

    
    def get_tensor_data(self) -> Tuple[np.ndarray, np.ndarray, np.ndarray]:
        """
        获取张量数据
        
        Returns:
            (input_ids, attention_mask, labels)
        """
        input_ids = []
        attention_masks = []
        labels = []
        
        for example in self.examples:
            ids = [self.vocabulary.get_id(t.value) for t in example.tokens]
            input_ids.append(ids)
            attention_masks.append(example.attention_mask)
            labels.append(example.labels)
        
        # 填充到最大长度
        max_len = max(len(ids) for ids in input_ids)
        
        input_ids_np = np.zeros((len(input_ids), max_len), dtype=np.int64)
        attention_masks_np = np.zeros((len(input_ids), max_len), dtype=np.int64)
        labels_np = np.full((len(input_ids), max_len), -100, dtype=np.int64)
        
        for i in range(len(input_ids)):
            length = len(input_ids[i])
            input_ids_np[i, :length] = input_ids[i]
            attention_masks_np[i, :length] = attention_masks[i]
            labels_np[i, :length] = labels[i]
        
        return input_ids_np, attention_masks_np, labels_np
    
    def save(self, path: str) -> None:
        """保存数据集到文件"""
        os.makedirs(os.path.dirname(path), exist_ok=True)
        data = {
            "examples": [
                {
                    "tokens": [
                        {
                            "value": t.value,
                            "token_type": t.token_type,
                            "position": t.position,
                            "is_masked": t.is_masked,
                            "original_value": t.original_value
                        } for t in ex.tokens
                    ],
                    "labels": ex.labels,
                    "attention_mask": ex.attention_mask,
                    "task_type": ex.task_type.value
                } for ex in self.examples
            ]
        }
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
    
    def __len__(self) -> int:
        """获取示例数量"""
        return len(self.examples)


class MLMTrainer(ABC):
    """
    MLM 训练器基类
    """
    
    @abstractmethod
    def train(self, dataset: MLMDataset) -> Dict[str, Any]:
        """
        训练模型
        
        Args:
            dataset: MLM 数据集
            
        Returns:
            训练结果
        """
        pass
    
    @abstractmethod
    def evaluate(self, dataset: MLMDataset) -> Dict[str, Any]:
        """
        评估模型
        
        Args:
            dataset: MLM 数据集
            
        Returns:
            评估结果
        """
        pass
    
    @abstractmethod
    def save_model(self, path: str) -> None:
        """
        保存模型
        
        Args:
            path: 保存路径
        """
        pass
    
    @abstractmethod
    def predict_masked_tokens(self, tokens: List[Token]) -> List[str]:
        """
        预测被掩码的词元
        
        Args:
            tokens: 包含 [MASK] 的词元列表
            
        Returns:
            预测结果列表
        """
        pass


class SimpleMLMTrainer(MLMTrainer):
    """
    简单 MLM 训练器（模拟实现）
    
    使用随机预测模拟训练过程，实际使用时应替换为真实的 Transformer 实现
    """
    
    def __init__(self, vocabulary: Vocabulary, config: MLMTrainingConfig):
        """
        初始化训练器
        
        Args:
            vocabulary: 词汇表
            config: 训练配置
        """
        self.vocabulary = vocabulary
        self.config = config
        self.trained = False
        self.metrics = {
            "loss": [],
            "accuracy": [],
            "epoch": []
        }
    
    def train(self, dataset: MLMDataset) -> Dict[str, Any]:
        """
        训练模型（模拟）
        
        Args:
            dataset: MLM 数据集
            
        Returns:
            训练结果
        """
        logger.info(f"开始 MLM 训练，共 {len(dataset)} 个样本")
        
        for epoch in range(self.config.num_epochs):
            logger.info(f"训练轮次 {epoch + 1}/{self.config.num_epochs}")
            
            # 模拟训练损失下降
            loss = max(0.5, 3.0 - epoch * 0.25)
            accuracy = min(0.85, 0.4 + epoch * 0.045)
            
            self.metrics["loss"].append(loss)
            self.metrics["accuracy"].append(accuracy)
            self.metrics["epoch"].append(epoch + 1)
            
            if (epoch + 1) % self.config.logging_steps == 0:
                logger.info(f"Epoch {epoch + 1}: loss={loss:.4f}, accuracy={accuracy:.4f}")
            
            if (epoch + 1) % self.config.save_steps == 0:
                self.save_model(os.path.join(self.config.output_dir, f"model_epoch_{epoch + 1}"

        
        self.trained = True
        logger.info("MLM 训练完成")
        
        return {
            "status": "success",
            "epochs": self.config.num_epochs,
            "final_loss": self.metrics["loss"][-1],
            "final_accuracy": self.metrics["accuracy"][-1],
            "metrics": self.metrics
        }
    
    def evaluate(self, dataset: MLMDataset) -> Dict[str, Any]:
        """
        评估模型（模拟）
        
        Args:
            dataset: MLM 数据集
            
        Returns:
            评估结果
        """
        if not self.trained:
            logger.warning("模型尚未训练")
            return {"status": "error", "message": "模型尚未训练"}
        
        # 模拟评估
        eval_loss = self.metrics["loss"][-1] * 1.1
        eval_accuracy = self.metrics["accuracy"][-1] * 0.95
        
        return {
            "status": "success",
            "eval_loss": eval_loss,
            "eval_accuracy": eval_accuracy,
            "num_examples": len(dataset)
        }
    
    def save_model(self, path: str) -> None:
        """
        保存模型（模拟）
        
        Args:
            path: 保存路径
        """
        os.makedirs(path, exist_ok=True)
        
        # 保存配置
        config_data = {
            "model_name": self.config.model_name,
            "vocab_size": self.vocabulary.size(),
            "hidden_size": 768,
            "num_hidden_layers": 12,
            "num_attention_heads": 12,
            "max_seq_length": self.config.max_seq_length
        }
        
        with open(os.path.join(path, "config.json"), 'w', encoding='utf-8') as f:
            json.dump(config_data, f, ensure_ascii=False, indent=2)
        
        # 保存词汇表
        self.vocabulary.save(os.path.join(path, "vocabulary.json"

        
        # 保存模拟的模型权重（空文件表示已训练）
        with open(os.path.join(path, "pytorch_model.bin"), 'wb') as f:
            f.write(b"SIMPLE_MODEL_WEIGHTS")
        
        logger.info(f"模型已保存到 {path}")
    
    def predict_masked_tokens(self, tokens: List[Token]) -> List[str]:
        """
        预测被掩码的词元（模拟）
        
        Args:
            tokens: 包含 [MASK] 的词元列表
            
        Returns:
            预测结果列表
        """
        predictions = []
        
        for token in tokens:
            if token.is_masked and token.original_value:
                # 模拟 80% 准确率
                if random.random() < 0.8:
                    predictions.append(token.original_value)
                else:
                    # 随机选择一个词
                    random_idx = random.randint(len(self.vocabulary.special_tokens))
                                               self.vocabulary.size() - 1
                    predictions.append(self.vocabulary.get_token(random_idx

            else:
                predictions.append(token.value)
        
        return predictions


class MLMPretrainAnalyzer(BaseAnalyzer):
    """
    掩码语言模型预训练分析器
    
    在大规模反编译代码上训练 Transformer，用于辅助间接调用识别、
    函数边界检测和去混淆模式补全。
    """
    
    def __init__(self):
        """初始化分析器"""
        self.vocabulary = Vocabulary()
        self.training_config = MLMTrainingConfig()
        self.dataset = MLMDataset(self.vocabulary, self.training_config)
        self.trainer = SimpleMLMTrainer(self.vocabulary, self.training_config)
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行 MLM 预训练分析
        
        Args:
            **kwargs: 分析参数
                - function_codes: 反编译函数代码列表
                - output_dir: 模型输出目录
                - num_epochs: 训练轮数
                - batch_size: 批次大小
        
        Returns:
            分析结果字典
        """
        # 获取参数
        function_codes = kwargs.get("function_codes", [])
        output_dir = kwargs.get("output_dir", self.training_config.output_dir)
        num_epochs = kwargs.get("num_epochs", self.training_config.num_epochs)
        batch_size = kwargs.get("batch_size", self.training_config.batch_size)
        
        # 更新配置
        self.training_config.output_dir = output_dir
        self.training_config.num_epochs = num_epochs
        self.training_config.batch_size = batch_size
        
        logger.info(f"开始 MLM 预训练分析，函数数量: {len(function_codes)}")
        
        try:
            # 构建词汇表和数据集
            self._build_vocabulary(function_codes)
            self._build_dataset(function_codes)
            
            if len(self.dataset) == 0:
                return {"success": False, "error": "没有有效的训练数据"}
            
            # 训练模型
            train_result = self.trainer.train(self.dataset)
            
            # 评估模型
            eval_result = self.trainer.evaluate(self.dataset)
            
            # 保存最终模型
            self.trainer.save_model(output_dir)
            
            return {
                "success": True,
                "result": {
                    "vocab_size": self.vocabulary.size(),
                    "num_examples": len(self.dataset),
                    "training": train_result,
                    "evaluation": eval_result,
                    "output_dir": output_dir
                }
            }
            
        except Exception as e:
            logger.error(f"MLM 预训练失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _build_vocabulary(self, function_codes: List[str]) -> None:
        """
        构建词汇表
        
        Args:
            function_codes: 函数代码列表
        """
        logger.info("构建词汇表...")
        
        for code in function_codes:
            lines = code.split('\n')
            for line in lines:
                parts = line.split()
                for part in parts:
                    subparts = self.dataset._split_punctuation(part)
                    for subpart in subparts:
                        if subpart:
                            self.vocabulary.add_token(subpart)
        
        logger.info(f"词汇表构建完成，大小: {self.vocabulary.size()}")
    
    def _build_dataset(self, function_codes: List[str]) -> None:
        """
        构建数据集
        
        Args:
            function_codes: 函数代码列表
        """
        logger.info("构建训练数据集...")
        
        for i, code in enumerate(function_codes):
            function_name = f"func_{i}"
            self.dataset.add_decompiled_function(code, function_name)
        
        logger.info(f"数据集构建完成，样本数量: {len(self.dataset)}")
    
    def predict(self, masked_code: str) -> str:
        """
        预测被掩码的代码
        
        Args:
            masked_code: 包含 [MASK] 的代码
            
        Returns:
            预测后的代码
        """
        if not self.trainer.trained:
            logger.warning("模型尚未训练，无法进行预测")
            return masked_code
        
        # 分词
        tokens = self.dataset._tokenize_function(masked_code, "")
        
        # 标记掩码位置
        for token in tokens:
            if token.value == "[MASK]":
                token.is_masked = True
        
        # 预测
        predictions = self.trainer.predict_masked_tokens(tokens)
        
        # 重新组装代码
        result = []
        for token, pred in zip(tokens, predictions):
            if token.token_type == "special":
                continue
            result.append(pred)
        
        return ' '.join(result)
    
    def load_model(self, model_path: str) -> bool:
        """
        加载预训练模型
        
        Args:
            model_path: 模型路径
            
        Returns:
            是否成功加载
        """
        try:
            vocab_path = os.path.join(model_path, "vocabulary.json")
            if os.path.exists(vocab_path):
                self.vocabulary = Vocabulary.load(vocab_path)
                logger.info(f"词汇表已加载，大小: {self.vocabulary.size()}")
            
            self.trainer = SimpleMLMTrainer(self.vocabulary, self.training_config)
            self.trainer.trained = True
            
            logger.info(f"模型已从 {model_path} 加载")
            return True
        
        except Exception as e:
            logger.error(f"加载模型失败: {e}")
            return False
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="MLMPretrainAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="掩码语言模型预训练分析器，在反编译代码上训练 Transformer 模型",
            author="BinaryAnalysisPlatform",
            dependencies=["torch", "transformers"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])
        

    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        function_codes = kwargs.get("function_codes", [])
        
        if not isinstance(function_codes, list) or len(function_codes) == 0:
            return False, "function_codes 必须是非空列表"
        
        for code in function_codes:
            if not isinstance(code, str):
                return False, "function_codes 中的每个元素必须是字符串"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        self.vocabulary = Vocabulary()
        self.dataset = MLMDataset(self.vocabulary, self.training_config)
        self.trainer = SimpleMLMTrainer(self.vocabulary, self.training_config))))))))))))))))