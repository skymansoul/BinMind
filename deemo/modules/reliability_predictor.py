import logging
import os
import time
import json
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional, Tuple, Union
from enum import Enum
from abc import ABC, abstractmethod

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class ReliabilityLevel(Enum):
    """可靠性等级枚举"""
    CRITICAL = "critical"      # 极不可靠
    LOW = "low"                # 低可靠性
    MEDIUM = "medium"          # 中等可靠性
    HIGH = "high"              # 高可靠性
    CRITICAL_SUCCESS = "critical_success"  # 极高可靠性


class FeatureType(Enum):
    """特征类型枚举"""
    VULNERABILITY_TYPE = "vulnerability_type"
    TARGET_ARCHITECTURE = "target_architecture"
    MITIGATION_STATUS = "mitigation_status"
    PAYLOAD_COMPLEXITY = "payload_complexity"
    ENVIRONMENT_STABILITY = "environment_stability"
    MEMORY_LAYOUT_VARIABILITY = "memory_layout_variability"
    TIMING_SENSITIVITY = "timing_sensitivity"
    DEPENDENCY_COUNT = "dependency_count"


@dataclass
class FeatureVector:
    """特征向量"""
    vulnerability_type: str
    architecture: str
    mitigations: List[str]
    payload_size: int
    gadget_count: int
    has_info_leak: bool
    requires_memory_layout: bool
    timing_constraints: bool
    dependency_count: int
    os_version: str
    target_binary_size: int
    entropy_score: float = 0.0
    code_density: float = 0.0


@dataclass
class ReliabilityPrediction:
    """可靠性预测结果"""
    score: float
    level: ReliabilityLevel
    confidence: float
    factors: List[Dict[str, Any]]
    recommendations: List[str]
    estimated_success_rate: float
    expected_failures: List[str]
    runtime_estimate: float


class PredictionModel(ABC):
    """预测模型基类"""
    
    @abstractmethod
    def predict(self, features: FeatureVector) -> ReliabilityPrediction:
        """执行预测"""
        pass
    
    @abstractmethod
    def train(self, training_data: List[Tuple[FeatureVector, float]]) -> None:
        """训练模型"""
        pass


class RuleBasedModel(PredictionModel):
    """基于规则的预测模型"""
    
    def __init__(self):
        self.rules = self._load_rules()
    
    def _load_rules(self) -> List[Dict[str, Any]]:
        """加载规则集"""
        return [
            {
                "name": "ASLR规避要求",
                "condition": lambda f: "ASLR" in f.mitigations and not f.has_info_leak,
                "impact": -0.3,
                "reason": "存在ASLR但无信息泄露漏洞，无法获取地址"
            },
            {
                "name": "NX规避要求",
                "condition": lambda f: "NX" in f.mitigations and f.gadget_count == 0,
                "impact": -0.4,
                "reason": "存在NX但无可用ROP gadget"
            },
            {
                "name": "复杂payload惩罚",
                "condition": lambda f: f.payload_size > 1024,
                "impact": -0.1,
                "reason": "payload过大增加失败概率"
            },
            {
                "name": "内存布局依赖惩罚",
                "condition": lambda f: f.requires_memory_layout,
                "impact": -0.2,
                "reason": "依赖特定内存布局降低可靠性"
            },
            {
                "name": "时序依赖惩罚",
                "condition": lambda f: f.timing_constraints,
                "impact": -0.15,
                "reason": "时序约束增加失败概率"
            },
            {
                "name": "信息泄露加分",
                "condition": lambda f: f.has_info_leak,
                "impact": 0.2,
                "reason": "存在信息泄露可帮助绕过ASLR"
            },
            {
                "name": "简单payload加分",
                "condition": lambda f: f.payload_size < 256,
                "impact": 0.1,
                "reason": "payload较小更可靠"
            },
            {
                "name": "丰富gadget加分",
                "condition": lambda f: f.gadget_count > 10,
                "impact": 0.15,
                "reason": "充足的gadget提高ROP链成功率"
            },
            {
                "name": "CFG规避惩罚",
                "condition": lambda f: "CFG" in f.mitigations,
                "impact": -0.25,
                "reason": "CFG防护增加利用难度"
            },
            {
                "name": "CET规避惩罚",
                "condition": lambda f: "CET" in f.mitigations,
                "impact": -0.35,
                "reason": "CET防护大幅增加ROP难度"
            },
            {
                "name": "低依赖加分",
                "condition": lambda f: f.dependency_count <= 2,
                "impact": 0.1,
                "reason": "依赖项少更可靠"
            },
        ]
    
    def predict(self, features: FeatureVector) -> ReliabilityPrediction:
        """执行基于规则的预测"""
        base_score = 0.7  # 基础分数
        factors = []
        recommendations = []
        expected_failures = []
        
        for rule in self.rules:
            if rule["condition"](features):
                base_score += rule["impact"]
                factors.append({
                    "name": rule["name"],
                    "impact": rule["impact"],
                    "reason": rule["reason"]
                })
                
                if rule["impact"] < 0:
                    expected_failures.append(rule["reason"])
                    recommendations.append(f"考虑绕过或禁用: {rule['name']}")
        
        # 根据漏洞类型调整
        vuln_type_scores = {
            "buffer_overflow": 0.0,
            "heap_overflow": -0.1,
            "use_after_free": -0.15,
            "format_string": 0.1,
            "integer_overflow": -0.05,
            "info_leak": 0.15,
        }
        base_score += vuln_type_scores.get(features.vulnerability_type, 0)
        
        # 根据架构调整
        arch_scores = {
            "x86": 0.1,
            "x86_64": -0.05,
            "arm": -0.1,
            "arm64": -0.15,
            "mips": -0.2,
        }
        base_score += arch_scores.get(features.architecture, 0)
        
        # 限制分数范围
        score = max(0.0, min(1.0, base_score))
        
        # 确定可靠性等级
        if score >= 0.9:
            level = ReliabilityLevel.CRITICAL_SUCCESS
        elif score >= 0.7:
            level = ReliabilityLevel.HIGH
        elif score >= 0.5:
            level = ReliabilityLevel.MEDIUM
        elif score >= 0.3:
            level = ReliabilityLevel.LOW
        else:
            level = ReliabilityLevel.CRITICAL
        
        # 计算置信度
        confidence = min(0.95, 0.6 + len(factors) * 0.05)
        
        # 计算预计成功率
        estimated_success_rate = score * 0.8 + confidence * 0.2
        
        # 预估运行时间
        runtime_estimate = max(0.1, features.payload_size / 1000.0 + len(factors) * 0.05)
        
        return ReliabilityPrediction(
            score=score,
            level=level,
            confidence=confidence,
            factors=factors,
            recommendations=recommendations,
            estimated_success_rate=estimated_success_rate,
            expected_failures=expected_failures,
            runtime_estimate=runtime_estimate
        )
    
    def train(self, training_data: List[Tuple[FeatureVector, float]]) -> None:
        """基于规则的模型不需要训练"""
        pass


class MachineLearningModel(PredictionModel):
    """机器学习预测模型"""
    
    def __init__(self):
        self.weights = self._initialize_weights()
        self.bias = 0.5
    
    def _initialize_weights(self) -> Dict[str, float]:
        """初始化模型权重"""
        return {
            "vulnerability_type_buffer_overflow": 0.0,
            "vulnerability_type_heap_overflow": -0.1,
            "vulnerability_type_use_after_free": -0.15,
            "vulnerability_type_format_string": 0.1,
            "vulnerability_type_info_leak": 0.15,
            "architecture_x86": 0.1,
            "architecture_x86_64": -0.05,
            "architecture_arm": -0.1,
            "architecture_arm64": -0.15,
            "mitigation_aslr": -0.2,
            "mitigation_nx": -0.15,
            "mitigation_cfg": -0.25,
            "mitigation_cet": -0.35,
            "has_info_leak": 0.2,
            "requires_memory_layout": -0.2,
            "timing_constraints": -0.15,
            "payload_size_normalized": -0.1,
            "gadget_count_normalized": 0.15,
            "dependency_count_normalized": -0.1,
        }
    
    def _extract_features(self, feature_vector: FeatureVector) -> Dict[str, float]:
        """从特征向量提取特征"""
        features = {}
        
        # 漏洞类型
        key = f"vulnerability_type_{feature_vector.vulnerability_type}"
        features[key] = 1.0
        
        # 架构
        key = f"architecture_{feature_vector.architecture}"
        features[key] = 1.0
        
        # 缓解措施
        if "ASLR" in feature_vector.mitigations:
            features["mitigation_aslr"] = 1.0
        if "NX" in feature_vector.mitigations:
            features["mitigation_nx"] = 1.0
        if "CFG" in feature_vector.mitigations:
            features["mitigation_cfg"] = 1.0
        if "CET" in feature_vector.mitigations:
            features["mitigation_cet"] = 1.0
        
        # 布尔特征
        features["has_info_leak"] = 1.0 if feature_vector.has_info_leak else 0.0
        features["requires_memory_layout"] = 1.0 if feature_vector.requires_memory_layout else 0.0
        features["timing_constraints"] = 1.0 if feature_vector.timing_constraints else 0.0
        
        # 归一化特征
        features["payload_size_normalized"] = min(feature_vector.payload_size / 1024.0, 1.0)
        features["gadget_count_normalized"] = min(feature_vector.gadget_count / 50.0, 1.0)
        features["dependency_count_normalized"] = min(feature_vector.dependency_count / 10.0, 1.0)
        
        return features
    
    def predict(self, features: FeatureVector) -> ReliabilityPrediction:
        """执行机器学习预测"""
        extracted_features = self._extract_features(features)
        
        # 计算加权分数
        score = self.bias
        active_factors = []
        
        for feature_name, value in extracted_features.items():
            weight = self.weights.get(feature_name, 0.0)
            contribution = value * weight
            score += contribution
            
            if abs(contribution) > 0.01:
                active_factors.append({
                    "name": feature_name.replace("_", " "),
                    "impact": contribution,
                    "reason": f"特征值: {value:.2f}, 权重: {weight:.2f}"
                })
        
        # 使用sigmoid激活函数
        score = 1.0 / (1.0 + 2.71828 ** (-10 * (score - 0.5)))
        
        # 确定可靠性等级
        if score >= 0.9:
            level = ReliabilityLevel.CRITICAL_SUCCESS
        elif score >= 0.7:
            level = ReliabilityLevel.HIGH
        elif score >= 0.5:
            level = ReliabilityLevel.MEDIUM
        elif score >= 0.3:
            level = ReliabilityLevel.LOW
        else:
            level = ReliabilityLevel.CRITICAL
        
        # 计算置信度
        confidence = min(0.95, 0.5 + sum(1 for f in active_factors if abs(f["impact"]) > 0.05) * 0.05)
        
        # 生成建议
        recommendations = []
        expected_failures = []
        
        for factor in active_factors:
            if factor["impact"] < -0.1:
                expected_failures.append(factor["name"])
                recommendations.append(f"优化 {factor['name']} 可提高可靠性")
        
        return ReliabilityPrediction(
            score=score,
            level=level,
            confidence=confidence,
            factors=active_factors,
            recommendations=recommendations,
            estimated_success_rate=score * confidence,
            expected_failures=expected_failures,
            runtime_estimate=0.5
        )
    
    def train(self, training_data: List[Tuple[FeatureVector, float]]) -> None:
        """训练模型"""
        if not training_data:
            return
        
        learning_rate = 0.01
        iterations = 100
        
        for _ in range(iterations):
            total_error = 0.0
            
            for features, target in training_data:
                extracted_features = self._extract_features(features)
                
                # 前向传播
                score = self.bias
                for feature_name, value in extracted_features.items():
                    score += self.weights.get(feature_name, 0.0) * value
                
                prediction = 1.0 / (1.0 + 2.71828 ** (-10 * (score - 0.5)))
                
                # 计算误差
                error = prediction - target
                total_error += abs(error)
                
                # 反向传播
                gradient = error * prediction * (1 - prediction) * 10
                
                self.bias -= learning_rate * gradient
                
                for feature_name, value in extracted_features.items():
                    self.weights[feature_name] = self.weights.get(feature_name, 0.0) - learning_rate * gradient * value


class ReliabilityPredictor(BaseAnalyzer):
    """
    利用可靠性预测模型
    
    功能：
    1. 基于漏洞特征预测利用成功率
    2. 分析影响可靠性的关键因素
    3. 提供改进建议
    4. 支持基于规则和机器学习两种预测模式
    
    输入特征：
    - 漏洞类型
    - 目标架构
    - 缓解措施状态
    - Payload复杂度
    - 环境稳定性
    - 内存布局依赖
    - 时序敏感性
    - 依赖项数量
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self.config = config or {}
        self.model_type = self.config.get('model_type', 'rule_based')
        self.models: Dict[str, PredictionModel] = {
            'rule_based': RuleBasedModel(),
            'ml': MachineLearningModel()
        }
        self.current_model = self.models[self.model_type]
        self._predictions: List[ReliabilityPrediction] = []
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ReliabilityPredictor",
            type=AnalyzerType.OTHER,
            version="1.0.0",
            description="利用可靠性预测模型，基于漏洞特征预测利用成功率并提供改进建议",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["x86", "x86_64", "arm", "arm64", "mips"],
            config_schema={
                "model_type": {"type": "string", "default": "rule_based"},
                "confidence_threshold": {"type": "number", "default": 0.7}
            }
        )
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        required_params = [
            'vulnerability_type',
            'architecture',
            'mitigations',
            'payload_size',
            'gadget_count'
        ]
        
        for param in required_params:
            if param not in kwargs:
                return False, f"缺少必需参数: {param}"
        
        if not isinstance(kwargs['mitigations'], list):
            return False, "mitigations 必须是列表类型"
        
        if kwargs['payload_size'] < 0:
            return False, "payload_size 不能为负数"
        
        if kwargs['gadget_count'] < 0:
            return False, "gadget_count 不能为负数"
        
        valid_vuln_types = [
            'buffer_overflow', 'heap_overflow', 'use_after_free',
            'format_string', 'integer_overflow', 'info_leak', 'other'
        ]
        if kwargs['vulnerability_type'] not in valid_vuln_types:
            return False, f"无效的漏洞类型: {kwargs['vulnerability_type']}"
        
        return True, None
    
    def _build_feature_vector(self, **kwargs) -> FeatureVector:
        """构建特征向量"""
        return FeatureVector(
            vulnerability_type=kwargs['vulnerability_type'],
            architecture=kwargs['architecture'],
            mitigations=kwargs['mitigations'],
            payload_size=kwargs['payload_size'],
            gadget_count=kwargs['gadget_count'],
            has_info_leak=kwargs.get('has_info_leak', False),
            requires_memory_layout=kwargs.get('requires_memory_layout', False),
            timing_constraints=kwargs.get('timing_constraints', False),
            dependency_count=kwargs.get('dependency_count', 0),
            os_version=kwargs.get('os_version', 'unknown'),
            target_binary_size=kwargs.get('target_binary_size', 0),
            entropy_score=kwargs.get('entropy_score', 0.0),
            code_density=kwargs.get('code_density', 0.0)
        )
    
    def predict(self, **kwargs) -> ReliabilityPrediction:
        """
        执行可靠性预测
        
        Args:
            vulnerability_type: 漏洞类型
            architecture: 目标架构
            mitigations: 缓解措施列表
            payload_size: payload大小
            gadget_count: gadget数量
            has_info_leak: 是否存在信息泄露
            requires_memory_layout: 是否依赖特定内存布局
            timing_constraints: 是否有时序约束
            dependency_count: 依赖项数量
            os_version: 操作系统版本
            target_binary_size: 目标二进制大小
        
        Returns:
            可靠性预测结果
        """
        valid, error = self.validate_input(**kwargs)
        if not valid:
            raise ValueError(error)
        
        feature_vector = self._build_feature_vector(**kwargs)
        prediction = self.current_model.predict(feature_vector)
        
        self._predictions.append(prediction)
        
        return prediction
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行可靠性分析
        
        Args:
            同 predict 方法
        
        Returns:
            分析结果字典
        """
        valid, error = self.validate_input(**kwargs)
        if not valid:
            return {"success": False, "error": error}
        
        try:
            prediction = self.predict(**kwargs)
            
            return {
                "success": True,
                "score": prediction.score,
                "level": prediction.level.value,
                "confidence": prediction.confidence,
                "estimated_success_rate": prediction.estimated_success_rate,
                "runtime_estimate": prediction.runtime_estimate,
                "factors": prediction.factors,
                "recommendations": prediction.recommendations,
                "expected_failures": prediction.expected_failures,
                "model_type": self.model_type,
                "feature_summary": {
                    "vulnerability_type": kwargs['vulnerability_type'],
                    "architecture": kwargs['architecture'],
                    "mitigations_count": len(kwargs['mitigations']),
                    "payload_size": kwargs['payload_size'],
                    "gadget_count": kwargs['gadget_count']
                }
            }
        
        except Exception as e:
            logger.error(f"可靠性预测失败: {e}")
            return {"success": False, "error": str(e)}
    
    def set_model(self, model_type: str) -> bool:
        """
        设置预测模型类型
        
        Args:
            model_type: 模型类型 ('rule_based' 或 'ml')
        
        Returns:
            是否成功设置
        """
        if model_type not in self.models:
            return False
        
        self.model_type = model_type
        self.current_model = self.models[model_type]
        return True
    
    def train_model(self, training_data: List[Dict[str, Any]]) -> bool:
        """
        训练机器学习模型
        
        Args:
            training_data: 训练数据列表，每个元素包含特征和目标值
        
        Returns:
            是否成功训练
        """
        if self.model_type != 'ml':
            logger.warning("只有机器学习模型支持训练")
            return False
        
        try:
            converted_data = []
            for item in training_data:
                features = self._build_feature_vector(**item['features'])
                converted_data.append((features, item['target']))
            
            self.current_model.train(converted_data)
            return True
        
        except Exception as e:
            logger.error(f"训练失败: {e}")
            return False
    
    def get_prediction_history(self) -> List[ReliabilityPrediction]:
        """获取预测历史"""
        return self._predictions
    
    def export_model(self, filepath: str) -> bool:
        """
        导出模型参数
        
        Args:
            filepath: 输出文件路径
        
        Returns:
            是否成功导出
        """
        if self.model_type == 'ml' and hasattr(self.current_model, 'weights'):
            model_data = {
                'model_type': self.model_type,
                'weights': self.current_model.weights,
                'bias': self.current_model.bias
            }
            
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(model_data, f, indent=2)
                return True
            except Exception as e:
                logger.error(f"导出失败: {e}")
                return False
        
        return False
    
    def import_model(self, filepath: str) -> bool:
        """
        导入模型参数
        
        Args:
            filepath: 输入文件路径
        
        Returns:
            是否成功导入
        """
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                model_data = json.load(f)
            
            if model_data.get('model_type') == 'ml':
                self.set_model('ml')
                self.current_model.weights = model_data.get('weights', {})
                self.current_model.bias = model_data.get('bias', 0.5)
                return True
            
            return False
        
        except Exception as e:
            logger.error(f"导入失败: {e}")
            return False
    
    def cleanup(self) -> None:
        """清理资源"""
        self._predictions.clear()


def predict_reliability(**kwargs) -> Dict[str, Any]:
    """
    预测利用可靠性的便捷函数
    
    Args:
        同 ReliabilityPredictor.predict 方法
    
    Returns:
        预测结果
    """
    predictor = ReliabilityPredictor()
    return predictor.analyze(**kwargs)