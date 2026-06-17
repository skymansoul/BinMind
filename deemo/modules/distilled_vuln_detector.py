import logging
import os
import pickle
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from pathlib import Path
import numpy as np

try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    from transformers import BertTokenizer, BertForSequenceClassification, DistilBertForSequenceClassification
    from transformers import TrainingArguments, Trainer, EarlyStoppingCallback
    from datasets import Dataset, load_metric
    HAS_TRANSFORMERS = True
except ImportError:
    HAS_TRANSFORMERS = False
    Dataset = None

logger = logging.getLogger(__name__)


@dataclass
class VulnerabilitySample:
    """漏洞样本"""
    id: str
    code: str
    label: int  # 0: 良性, 1: 漏洞
    vulnerability_type: Optional[str] = None  # CWE-xxx
    confidence: float = 1.0
    source: str = "generated"  # generated, labeled, active_learning


@dataclass
class DetectionResult:
    """检测结果"""
    function_name: str
    function_address: int
    is_vulnerable: bool
    confidence: float
    vulnerability_type: Optional[str]
    explanation: Optional[str] = None


@dataclass
class DistillationConfig:
    """知识蒸馏配置"""
    teacher_model_name: str = "bert-base-uncased"
    student_model_name: str = "distilbert-base-uncased"
    num_labels: int = 2
    temperature: float = 5.0
    alpha: float = 0.5
    batch_size: int = 32
    epochs: int = 10
    learning_rate: float = 2e-5


@dataclass
class ActiveLearningConfig:
    """主动学习配置"""
    enabled: bool = False
    strategy: str = "least_confidence"  # least_confidence, margin, entropy
    sample_count: int = 10
    query_batch_size: int = 32


class VulnerabilityDataGenerator:
    """漏洞数据生成器"""
    
    def __init__(self):
        pass
    
    def generate_samples(self, vulnerability_types: List[str], count_per_type: int = 10) -> List[VulnerabilitySample]:
        """
        生成漏洞样本
        
        Args:
            vulnerability_types: 漏洞类型列表
            count_per_type: 每种类型生成的样本数
        
        Returns:
            漏洞样本列表
        """
        samples = []
        
        for vuln_type in vulnerability_types:
            logger.info(f"生成 {count_per_type} 个 {vuln_type} 漏洞样本")
            
            for i in range(count_per_type):
                sample_code = self._generate_sample_code(vuln_type, i)
                
                sample = VulnerabilitySample()
                    id=f"{vuln_type}_{i}",
                    code=sample_code,
                    label=1,
                    vulnerability_type=vuln_type,
                    confidence=0.95,
                    source="generated"
                
                samples.append(sample)
        
        logger.info(f"共生成 {len(samples)} 个漏洞样本")
        return samples
    
    def _generate_sample_code(self, vulnerability_type: str, index: int) -> str:
        """
        生成单个样本代码（模拟实现）
        
        Args:
            vulnerability_type: 漏洞类型
            index: 样本索引
        
        Returns:
            代码字符串
        """
        vulnerability_templates = {
            "CWE-121": """void vulnerable_function(char *input) {
    char buffer[16];
    strcpy(buffer, input);  // CWE-121: Stack-based buffer overflow
}""",
            "CWE-122": """void vulnerable_function(char *input) {
    char *buffer = malloc(16);
    strcpy(buffer, input);  // CWE-122: Heap-based buffer overflow
    free(buffer);
}""",
            "CWE-78": """void vulnerable_function(char *command) {
    system(command);  // CWE-78: Command injection
}""",
            "CWE-20": """void vulnerable_function(int value) {
    char buffer[100];
    sprintf(buffer, "%d", value);  // CWE-20: Improper input validation
}""",
            "CWE-416": """char* vulnerable_function() {
    char *ptr = malloc(10);
    free(ptr);
    return ptr;  // CWE-416: Use after free
}"""
        }
        
        return vulnerability_templates.get(vulnerability_type, f"// {vulnerability_type} sample {index}")
    
    def generate_benign_samples(self, count: int = 100) -> List[VulnerabilitySample]:
        """
        生成良性代码样本
        
        Args:
            count: 生成数量
        
        Returns:
            良性样本列表
        """
        samples = []
        
        benign_patterns = [
            """void safe_function(char *input, size_t size) {
    char buffer[16];
    strncpy(buffer, input, sizeof(buffer)-1);
    buffer[sizeof(buffer)-1] = '\0';
}""",
            """int safe_add(int a, int b) {
    return a + b;
}""",
            """void safe_log(const char *message) {
    printf("[LOG] %s\n", message);
}""",
            """size_t safe_strlen(const char *str) {
    size_t len = 0;,
    while (str[len] != '\0') {
        len++;
    }
    return len;
}"""
        ]
        
        for i in range(count):
            code = benign_patterns[i % len(benign_patterns)]
            sample = VulnerabilitySample()
                id=f"benign_{i}",
                code=code,
                label=0,
                confidence=0.95,
                source="generated"
            
            samples.append(sample)
        
        return samples


if HAS_TRANSFORMERS:
    class DistilledVulnerabilityDetector:
        """知识蒸馏漏洞检测器"""
        
        def __init__(self, config: Optional[DistillationConfig] = None):
            """
            初始化检测器
            
            Args:
                config: 蒸馏配置
            """
            self.config = config or DistillationConfig()
            self.tokenizer = BertTokenizer.from_pretrained(self.config.student_model_name)
            self.model: Optional[nn.Module] = None
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
        
        def _prepare_dataset(self, samples: List[VulnerabilitySample]):
            """
            准备训练数据集
            
            Args:
                samples: 样本列表
            
            Returns:
                Hugging Face Dataset
            """
            texts = [sample.code for sample in samples]
            labels = [sample.label for sample in samples]
            
            dataset = Dataset.from_dict({"text": texts, "label": labels})
            
            def tokenize_function(examples):
                return self.tokenizer()
                    examples["text"],
                    padding="max_length",
                    truncation=True,
                    max_length=512
                

            
            return dataset.map(tokenize_function, batched=True)
        
        def train_with_distillation(self, train_samples: List[VulnerabilitySample], val_samples: List[VulnerabilitySample]) -> None:
            """
            使用知识蒸馏训练模型
            
            Args:
                train_samples: 训练样本
                val_samples: 验证样本
            """
            teacher_model = BertForSequenceClassification.from_pretrained()
                self.config.teacher_model_name,
                num_labels=self.config.num_labels
            ).to(self.device
            teacher_model.eval()
            
            self.model = DistilBertForSequenceClassification.from_pretrained()
                self.config.student_model_name,
                num_labels=self.config.num_labels
            ).to(self.device
            
            train_dataset = self._prepare_dataset(train_samples)
            val_dataset = self._prepare_dataset(val_samples)
            
            training_args = TrainingArguments()
                output_dir="./distilled_model",
                per_device_train_batch_size=self.config.batch_size,
                per_device_eval_batch_size=self.config.batch_size,
                num_train_epochs=self.config.epochs,
                learning_rate=self.config.learning_rate,
                evaluation_strategy="epoch",
                save_strategy="epoch",
                load_best_model_at_end=True,
                metric_for_best_model="accuracy",
                logging_dir="./logs",
                logging_steps=10,
            
            
            def compute_loss(model, inputs, return_outputs=False):
                labels = inputs.pop("labels")
                
                student_outputs = model(**inputs)
                student_logits = student_outputs.logits
                
                with torch.no_grad():
                    teacher_outputs = teacher_model(**inputs)
                    teacher_logits = teacher_outputs.logits / self.config.temperature
                
                distillation_loss = F.kl_div()
                    F.log_softmax(student_logits / self.config.temperature, dim=-1),
                    F.softmax(teacher_logits, dim=-1),
                    reduction="batchmean"
                ) * (self.config.temperature ** 2
                
                classification_loss = F.cross_entropy(student_logits, labels)
                
                loss = self.config.alpha * distillation_loss + (1 - self.config.alpha) * classification_loss
                
                return (loss, student_outputs) if return_outputs else loss
            
            trainer = Trainer()
                model=self.model,
                args=training_args,
                train_dataset=train_dataset,
                eval_dataset=val_dataset,
                compute_loss=compute_loss,
                callbacks=[EarlyStoppingCallback(early_stopping_patience=3)]
            
            
            logger.info("开始知识蒸馏训练...")
            trainer.train()
            
            logger.info("训练完成")
        
        def quantize_model(self, output_path: str) -> bool:
            """
            量化模型以减小体积和加速推理
            
            Args:
                output_path: 量化模型保存路径
            
            Returns:
                是否成功
            """
            if not self.model:
                logger.error("模型未训练")
                return False
            
            try:
                self.model = torch.ao.quantization.quantize_dynamic()
                    self.model,
                    {nn.Linear},
                    dtype=torch.qint8
                
                
                os.makedirs(output_path, exist_ok=True)
                torch.save(self.model.state_dict(), os.path.join(output_path, "quantized_model.pt"

                self.tokenizer.save_pretrained(output_path)
                
                logger.info(f"量化模型已保存到: {output_path}")
                return True
            except Exception as e:
                logger.error(f"量化失败: {e}")
                return False
        
        def load_model(self, model_path: str) -> bool:
            """
            加载预训练模型
            
            Args:
                model_path: 模型路径
            
            Returns:
                是否成功
            """
            try:
                self.model = DistilBertForSequenceClassification.from_pretrained()
                    self.config.student_model_name,
                    num_labels=self.config.num_labels
                
                
                quantized_path = os.path.join(model_path, "quantized_model.pt")
                if os.path.exists(quantized_path):
                    self.model.load_state_dict(torch.load(quantized_path, map_location=self.device

                    logger.info("加载量化模型")
                else:
                    self.model.load_state_dict(torch.load(model_path, map_location=self.device

                    logger.info("加载普通模型")
                
                self.model = self.model.to(self.device)
                self.model.eval()
                logger.info(f"模型已加载: {model_path}")
                return True
            except Exception as e:
                logger.error(f"加载模型失败: {e}")
                return False
        
        def detect(self, code: str) -> DetectionResult:
            """
            检测代码中的漏洞
            
            Args:
                code: 代码字符串
            
            Returns:
                检测结果
            """
            if not self.model:
                logger.error("模型未加载")
                return DetectionResult(
                    function_name="unknown",
                    function_address=0,
                    is_vulnerable=False,
                    confidence=0.0,
                    vulnerability_type=None,
                    explanation="模型未加载")
                

            
            try:
                inputs = self.tokenizer()
                    code,
                    padding="max_length",
                    truncation=True,
                    max_length=512,
                    return_tensors="pt"
                ).to(self.device
                
                with torch.no_grad():
                    outputs = self.model(**inputs)
                    logits = outputs.logits
                    probabilities = F.softmax(logits, dim=-1)
                
                predicted_label = torch.argmax(probabilities, dim=-1).item()
                confidence = probabilities[0][predicted_label].item()
                
                return DetectionResult(
                    function_name="unknown",
                    function_address=0,
                    is_vulnerable=bool(predicted_label),
                    confidence=confidence,
                    vulnerability_type=self._predict_vulnerability_type(code) if predicted_label else None,
                    explanation=f"模型预测置信度: {confidence:.4f}")
                

            
            except Exception as e:
                logger.error(f"检测失败: {e}")
                return DetectionResult(
                    function_name="unknown",
                    function_address=0,
                    is_vulnerable=False,
                    confidence=0.0,
                    vulnerability_type=None,
                    explanation=str(e))
                

        
        def _predict_vulnerability_type(self, code: str) -> Optional[str]:
            """
            预测漏洞类型（简单规则匹配）
            
            Args:
                code: 代码字符串
            
            Returns:
                漏洞类型
            """
            if "strcpy" in code and "buffer" in code:
                return "CWE-121"
            elif "malloc" in code and "strcpy" in code:
                return "CWE-122"
            elif "system(" in code:
                return "CWE-78"
            elif "sprintf" in code:
                return "CWE-20"
            elif "free(" in code and "return" in code:
                return "CWE-416"
            else:
                return "CWE-Unknown"
    
    class ActiveLearningManager:
        """主动学习管理器"""
        
        def __init__(self, detector, config: Optional[ActiveLearningConfig] = None):
            """
            初始化主动学习管理器
            
            Args:
                detector: 漏洞检测器
                config: 主动学习配置
            """
            self.detector = detector
            self.config = config or ActiveLearningConfig()
        
        def select_samples(self, unlabeled_samples: List[VulnerabilitySample]) -> List[VulnerabilitySample]:
            """
            选择最有信息量的样本进行标注
            
            Args:
                unlabeled_samples: 未标注样本
            
            Returns:
                选中的样本列表
            """
            if not self.config.enabled:
                return []
            
            scored_samples = []
            
            for sample in unlabeled_samples:
                result = self.detector.detect(sample.code)
                
                uncertainty = self._calculate_uncertainty(result.confidence)
                scored_samples.append((sample, uncertainty

            
            scored_samples.sort(key=lambda x: -x[1])
            selected = [sample for sample, _ in scored_samples[:self.config.sample_count]]
            
            logger.info(f"主动学习选择了 {len(selected)} 个样本")
            return selected
        
        def _calculate_uncertainty(self, confidence: float) -> float:
            """
            根据策略计算不确定性
            
            Args:
                confidence: 模型预测置信度
            
            Returns:
                不确定性分数
            """
            if self.config.strategy == "least_confidence":
                return 1.0 - confidence
            elif self.config.strategy == "margin":
                return min(confidence, 1.0 - confidence) * 2
            elif self.config.strategy == "entropy":
                if confidence == 0 or confidence == 1:
                    return 0.0
                return -confidence * np.log2(confidence) - (1 - confidence) * np.log2(1 - confidence)
            else:
                return 1.0 - confidence


class DistilledVulnDetectorAnalyzer:
    """知识蒸馏漏洞检测器分析器（BaseAnalyzer包装）"""
    
    def __init__(self):
        self.detector = None
        self.active_learning_manager = None
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行分析任务
        
        Args:
            **kwargs: 分析参数
                - code: 待检测的代码字符串
                - code_list: 待检测的代码列表
                - model_path: 预训练模型路径
                - train_samples: 训练样本（用于训练模式）
                - val_samples: 验证样本（用于训练模式）
                - mode: 模式（detect/train/quantize）
        
        Returns:
            分析结果字典
        """
        code = kwargs.get("code")
        code_list = kwargs.get("code_list", [])
        model_path = kwargs.get("model_path")
        train_samples = kwargs.get("train_samples")
        val_samples = kwargs.get("val_samples")
        mode = kwargs.get("mode", "detect")
        
        try:
            if not HAS_TRANSFORMERS:
                return {
                    "success": False,
                    "error": "transformers library is required",
                    "message": "请安装 transformers、torch 和 datasets 库以使用此功能"
                }
            
            results = {"success": True, "detections": [], "training_result": None}
            
            if mode == "train":
                if not train_samples or not val_samples:
                    return {"success": False, "error": "训练需要 train_samples 和 val_samples"}
                
                self.detector = DistilledVulnerabilityDetector()
                self.detector.train_with_distillation(train_samples, val_samples)
                
                if model_path:
                    self.detector.quantize_model(model_path)
                
                results["training_result"] = "训练完成"
            
            elif mode == "quantize":
                if not self.detector:
                    self.detector = DistilledVulnerabilityDetector()
                
                if model_path:
                    success = self.detector.quantize_model(model_path)
                    results["quantization_result"] = "成功" if success else "失败"
            
            else:
                if not self.detector:
                    self.detector = DistilledVulnerabilityDetector()
                    if model_path:
                        self.detector.load_model(model_path)
                
                if code:
                    result = self.detector.detect(code)
                    results["detections"].append({)
                        "code": code[:100] + "..." if len(code) > 100 else code,
                        "is_vulnerable": result.is_vulnerable,
                        "confidence": result.confidence,
                        "vulnerability_type": result.vulnerability_type,
                        "explanation": result.explanation
                    }
                
                for code_item in code_list:
                    result = self.detector.detect(code_item)
                    results["detections"].append({)
                        "code": code_item[:100] + "..." if len(code_item) > 100 else code_item,
                        "is_vulnerable": result.is_vulnerable,
                        "confidence": result.confidence,
                        "vulnerability_type": result.vulnerability_type,
                        "explanation": result.explanation
                    }
            
            return results
            
        except Exception as e:
            logger.error(f"分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    @classmethod
    def get_metadata(cls) -> Dict[str, Any]:
        """
        获取分析器元数据
        
        Returns:
            元数据字典
        """
        return {
            "name": "DistilledVulnDetector",
            "type": "vulnerability_detector",
            "version": "1.0.0",
            "description": "知识蒸馏轻量级漏洞检测模型，使用大模型生成标注数据训练TinyBERT级模型",
            "author": "BinaryAnalysisPlatform",
            "dependencies": ["transformers", "torch", "datasets"],
            "supported_platforms": ["all"]
        })))))))