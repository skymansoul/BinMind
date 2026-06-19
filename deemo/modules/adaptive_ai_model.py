"""
自适应AI模型选择模块

功能：
1. 根据任务复杂度动态选择轻量/强模型
2. 控制成本与时延
3. 支持模型性能监控和反馈
4. 实现模型选择策略

核心组件：
- ModelType: 模型类型枚举
- TaskComplexity: 任务复杂度评估
- ModelSelector: 模型选择器
- CostManager: 成本管理器
"""

import os
import time
import json
import logging
import threading
from typing import Dict, Any, Optional, List, Callable, Type
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod

logger = logging.getLogger(__name__)


class ModelType(Enum):
    """模型类型枚举"""
    LIGHT = "light"
    STANDARD = "standard"
    STRONG = "strong"
    CUSTOM = "custom"


class TaskType(Enum):
    """任务类型枚举"""
    DECOMPILATION = "decompilation"
    VULNERABILITY_ANALYSIS = "vulnerability_analysis"
    CODE_GENERATION = "code_generation"
    NATURAL_LANGUAGE = "natural_language"
    PATTERN_RECOGNITION = "pattern_recognition"


@dataclass
class ModelConfig:
    """模型配置"""
    name: str
    model_type: ModelType
    task_types: List[TaskType]
    max_tokens: int
    cost_per_token: float
    avg_latency_ms: int
    capabilities: List[str]
    api_endpoint: Optional[str] = None
    api_key: Optional[str] = None


@dataclass
class TaskFeatures:
    """任务特征"""
    task_type: TaskType
    input_size: int
    output_size_estimate: int
    complexity_score: float
    urgency: float = 1.0
    accuracy_requirement: float = 0.8


@dataclass
class ModelSelectionResult:
    """模型选择结果"""
    model_name: str
    model_type: ModelType
    estimated_cost: float
    estimated_latency_ms: int
    confidence: float
    reason: str


class ComplexityEstimator(ABC):
    """复杂度评估器基类"""
    
    @abstractmethod
    def estimate(self, **kwargs) -> float:
        """评估任务复杂度"""
        pass


class FunctionComplexityEstimator(ComplexityEstimator):
    """函数复杂度评估器"""
    
    def estimate(self, func_size: int = 0, instruction_count: int = 0, basic_block_count: int = 0, **kwargs) -> float:
        """
        评估函数分析任务的复杂度
        
        Args:
            func_size: 函数大小（字节）
            instruction_count: 指令数量
            basic_block_count: 基本块数量
            
        Returns:
            复杂度分数 (0-1)
        """
        score = 0.0
        
        if func_size > 0:
            score += min(func_size / 10000, 0.3)
        
        if instruction_count > 0:
            score += min(instruction_count / 500, 0.3)
        
        if basic_block_count > 0:
            score += min(basic_block_count / 50, 0.4)
        
        return min(score, 1.0)


class AnalysisComplexityEstimator(ComplexityEstimator):
    """分析复杂度评估器"""
    
    def estimate(self, binary_size: int = 0, function_count: int = 0, analysis_depth: int = 1, **kwargs) -> float:
        """
        评估分析任务的复杂度
        
        Args:
            binary_size: 二进制文件大小
            function_count: 函数数量
            analysis_depth: 分析深度
            
        Returns:
            复杂度分数 (0-1)
        """
        score = 0.0
        
        if binary_size > 0:
            score += min(binary_size / (100 * 1024 * 1024), 0.3)
        
        if function_count > 0:
            score += min(function_count / 1000, 0.3)
        
        if analysis_depth > 0:
            score += min(analysis_depth / 10, 0.4)
        
        return min(score, 1.0)


class ModelSelector(ABC):
    """模型选择器基类"""
    
    @abstractmethod
    def select_model(self, task_features: TaskFeatures) -> ModelSelectionResult:
        """选择模型"""
        pass


class CostBasedModelSelector(ModelSelector):
    """基于成本的模型选择器"""
    
    def __init__(self, models: List[ModelConfig]):
        self._models = models
        self._cost_threshold = 1.0
        self._latency_threshold_ms = 3000

    def select_model(self, task_features: TaskFeatures) -> ModelSelectionResult:
        """
        根据成本和延迟选择模型
        
        Args:
            task_features: 任务特征
            
        Returns:
            模型选择结果
        """
        candidates = self._filter_models(task_features)
        
        if not candidates:
            return ModelSelectionResult(
                model_name="unknown",
                model_type=ModelType.LIGHT,
                estimated_cost=0.0,
                estimated_latency_ms=0,
                confidence=0.0,
                reason="No suitable model found")
            

        
        best_model = self._find_best_model(candidates, task_features)
        return self._create_result(best_model, task_features)

    def _filter_models(self, task_features: TaskFeatures) -> List[ModelConfig]:
        """过滤适用的模型"""
        return [
            m for m in self._models
            if task_features.task_type in m.task_types
        ]

    def _find_best_model(self, candidates: List[ModelConfig], task_features: TaskFeatures) -> ModelConfig:
        """找到最优模型"""
        scores = []
        
        for model in candidates:
            cost_score = self._calculate_cost_score(model, task_features)
            latency_score = self._calculate_latency_score(model)
            capability_score = self._calculate_capability_score(model, task_features)
            
            urgency_weight = task_features.urgency
            accuracy_weight = task_features.accuracy_requirement
            
            total_score = (
                cost_score * (1 - accuracy_weight) +
                latency_score * urgency_weight +
                capability_score * accuracy_weight
            
            
            scores.append((model, total_score

        
        scores.sort(key=lambda x: x[1], reverse=True)
        return scores[0][0]

    def _calculate_cost_score(self, model: ModelConfig, task_features: TaskFeatures) -> float:
        """计算成本分数"""
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        estimated_cost = estimated_tokens * model.cost_per_token
        
        if estimated_cost <= self._cost_threshold:
            return 1.0
        elif estimated_cost <= self._cost_threshold * 2:
            return 0.5
        else:
            return 0.1

    def _calculate_latency_score(self, model: ModelConfig) -> float:
        """计算延迟分数"""
        if model.avg_latency_ms <= self._latency_threshold_ms:
            return 1.0
        elif model.avg_latency_ms <= self._latency_threshold_ms * 2:
            return 0.5
        else:
            return 0.1

    def _calculate_capability_score(self, model: ModelConfig, task_features: TaskFeatures) -> float:
        """计算能力分数"""
        complexity = task_features.complexity_score
        
        if model.model_type == ModelType.STRONG:
            return min(1.0, complexity + 0.2)
        elif model.model_type == ModelType.STANDARD:
            return min(1.0, complexity)
        else:
            return min(0.8, complexity * 0.8)

    def _create_result(self, model: ModelConfig, task_features: TaskFeatures) -> ModelSelectionResult:
        """创建选择结果"""
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        
        return ModelSelectionResult(
            model_name=model.name,
            model_type=model.model_type,
            estimated_cost=estimated_tokens * model.cost_per_token,
            estimated_latency_ms=model.avg_latency_ms,
            confidence=self._calculate_confidence(model, task_features),
            reason=self._generate_reason(model, task_features))
        


    def _calculate_confidence(self, model: ModelConfig, task_features: TaskFeatures) -> float:
        """计算置信度"""
        complexity = task_features.complexity_score
        
        if model.model_type == ModelType.STRONG:
            return min(1.0, 0.7 + complexity * 0.3)
        elif model.model_type == ModelType.STANDARD:
            return min(0.9, 0.5 + complexity * 0.4)
        else:
            return min(0.7, 0.4 + complexity * 0.3)

    def _generate_reason(self, model: ModelConfig, task_features: TaskFeatures) -> str:
        """生成选择理由"""
        reasons = []
        
        if task_features.complexity_score > 0.7:
            reasons.append("高复杂度任务需要强模型")
        elif task_features.complexity_score < 0.3:
            reasons.append("低复杂度任务使用轻量模型")
        else:
            reasons.append("中等复杂度任务使用标准模型")
        
        if task_features.urgency > 1.5:
            reasons.append("高紧急度优先选择低延迟模型")
        
        if task_features.accuracy_requirement > 0.9:
            reasons.append("高精度要求选择强模型")
        
        return "; ".join(reasons)


class PerformanceBasedModelSelector(ModelSelector):
    """基于性能的模型选择器"""
    
    def __init__(self, models: List[ModelConfig]):
        self._models = models
        self._performance_history: Dict[str, List[float]] = {}
        self._lock = threading.RLock()

    def select_model(self, task_features: TaskFeatures) -> ModelSelectionResult:
        """根据历史性能选择模型"""
        candidates = self._filter_models(task_features)
        
        if not candidates:
            return ModelSelectionResult(
                model_name="unknown",
                model_type=ModelType.LIGHT,
                estimated_cost=0.0,
                estimated_latency_ms=0,
                confidence=0.0,
                reason="No suitable model found")
            

        
        best_model = self._find_best_by_performance(candidates, task_features)
        return self._create_result(best_model, task_features)

    def _filter_models(self, task_features: TaskFeatures) -> List[ModelConfig]:
        """过滤适用的模型"""
        return [
            m for m in self._models
            if task_features.task_type in m.task_types
        ]

    def _find_best_by_performance(self, candidates: List[ModelConfig], task_features: TaskFeatures) -> ModelConfig:
        """根据历史性能找到最优模型"""
        best_score = float('-inf')
        best_model = candidates[0]
        
        for model in candidates:
            avg_performance = self._get_average_performance(model.name)
            complexity_factor = self._get_complexity_factor(model, task_features)
            
            score = avg_performance * complexity_factor
            
            if score > best_score:
                best_score = score
                best_model = model
        
        return best_model

    def _get_average_performance(self, model_name: str) -> float:
        """获取模型平均性能"""
        with self._lock:
            history = self._performance_history.get(model_name, [])
            if not history:
                return 0.5
            return sum(history) / len(history)

    def _get_complexity_factor(self, model: ModelConfig, task_features: TaskFeatures) -> float:
        """获取复杂度因子"""
        complexity = task_features.complexity_score
        
        if model.model_type == ModelType.STRONG:
            return 1.0 if complexity > 0.5 else 0.8
        elif model.model_type == ModelType.STANDARD:
            return 1.0 if 0.2 < complexity <= 0.7 else 0.7
        else:
            return 1.0 if complexity <= 0.3 else 0.5

    def record_performance(self, model_name: str, score: float) -> None:
        """记录模型性能"""
        with self._lock:
            if model_name not in self._performance_history:
                self._performance_history[model_name] = []
            self._performance_history[model_name].append(score)
            
            if len(self._performance_history[model_name]) > 100:
                self._performance_history[model_name] = self._performance_history[model_name][-50:]

    def _create_result(self, model: ModelConfig, task_features: TaskFeatures) -> ModelSelectionResult:
        """创建选择结果"""
        estimated_tokens = task_features.input_size + task_features.output_size_estimate
        
        return ModelSelectionResult(
            model_name=model.name,
            model_type=model.model_type,
            estimated_cost=estimated_tokens * model.cost_per_token,
            estimated_latency_ms=model.avg_latency_ms,
            confidence=self._get_average_performance(model.name),
            reason=f"基于历史性能选择")
        



class AdaptiveModelSelector:
    """
    自适应模型选择器
    - 综合考虑成本、性能和任务特征
    - 支持动态调整策略
    """
    
    def __init__(self):
        self._models: List[ModelConfig] = []
        self._selectors: Dict[str, ModelSelector] = {}
        self._active_selector = "cost_based"
        self._load_default_models()

    def _load_default_models(self) -> None:
        """加载默认模型配置"""
        default_models = [
            ModelConfig()
                name="gpt-4o-mini",
                model_type=ModelType.LIGHT,
                task_types=[TaskType.DECOMPILATION, TaskType.NATURAL_LANGUAGE],
                max_tokens=128000,
                cost_per_token=0.000001,
                avg_latency_ms=500,
                capabilities=["fast", "cost-effective"]
            ),
            ModelConfig()
                name="gpt-4o",
                model_type=ModelType.STANDARD,
                task_types=[TaskType.DECOMPILATION, TaskType.VULNERABILITY_ANALYSIS, 
                           TaskType.CODE_GENERATION, TaskType.NATURAL_LANGUAGE],
                max_tokens=128000,
                cost_per_token=0.000005,
                avg_latency_ms=1500,
                capabilities=["balanced", "versatile"]
            ),
            ModelConfig()
                name="gpt-4-turbo",
                model_type=ModelType.STRONG,
                task_types=[TaskType.VULNERABILITY_ANALYSIS, TaskType.CODE_GENERATION,
                           TaskType.PATTERN_RECOGNITION],
                max_tokens=128000,
                cost_per_token=0.00001,
                avg_latency_ms=3000,
                capabilities=["powerful", "accurate"]
            
        ]
        self._models = default_models
        
        self._selectors["cost_based"] = CostBasedModelSelector(default_models)
        self._selectors["performance_based"] = PerformanceBasedModelSelector(default_models)

    def add_model(self, config: ModelConfig) -> None:
        """添加模型配置"""
        self._models.append(config)
        for selector in self._selectors.values():
            if hasattr(selector, '_models'):
                selector._models.append(config)

    def set_selector(self, selector_name: str) -> bool:
        """设置活动选择器"""
        if selector_name in self._selectors:
            self._active_selector = selector_name,
            return True
        return False

    def select_model(self, task_type: TaskType, **kwargs) -> ModelSelectionResult:
        """
        选择模型
        
        Args:
            task_type: 任务类型
            **kwargs: 任务特征参数
            
        Returns:
            模型选择结果
        """
        features = self._build_task_features(task_type, kwargs)
        selector = self._selectors[self._active_selector]
        return selector.select_model(features)

    def _build_task_features(self, task_type: TaskType, kwargs: Dict[str, Any]) -> TaskFeatures:
        """构建任务特征"""
        complexity_estimator = self._get_estimator(task_type)
        complexity_score = complexity_estimator.estimate(**kwargs)
        
        return TaskFeatures(
            task_type=task_type,
            input_size=kwargs.get('input_size', 1000),
            output_size_estimate=kwargs.get('output_size', 2000),
            complexity_score=complexity_score,
            urgency=kwargs.get('urgency', 1.0),
            accuracy_requirement=kwargs.get('accuracy_requirement', 0.8))
        


    def _get_estimator(self, task_type: TaskType) -> ComplexityEstimator:
        """获取复杂度评估器"""
        if task_type in [TaskType.DECOMPILATION, TaskType.VULNERABILITY_ANALYSIS]:
            return FunctionComplexityEstimator()
        return AnalysisComplexityEstimator()

    def record_performance(self, model_name: str, score: float) -> None:
        """记录模型性能"""
        if "performance_based" in self._selectors:
            self._selectors["performance_based"].record_performance(model_name, score)

    def get_models(self) -> List[ModelConfig]:
        """获取所有模型配置"""
        return self._models


class CostManager:
    """
    成本管理器
    - 跟踪API调用成本
    - 实施预算控制
    - 生成成本报告
    """
    
    def __init__(self, daily_budget: float = 100.0):
        self._daily_budget = daily_budget
        self._today_cost = 0.0
        self._today_start = time.time()
        self._cost_history: List[Dict[str, Any]] = []
        self._lock = threading.RLock()

    def add_cost(self, model_name: str, tokens: int, cost_per_token: float) -> None:
        """添加成本记录"""
        cost = tokens * cost_per_token
        
        with self._lock:
            self._today_cost += cost
            
            self._cost_history.append({)
                "timestamp": time.time(),
                "model_name": model_name,
                "tokens": tokens,
                "cost": cost
            }
            
            if len(self._cost_history) > 1000:
                self._cost_history = self._cost_history[-500:]
            
            self._check_daily_reset()

    def _check_daily_reset(self) -> None:
        """检查是否需要重置每日成本"""
        now = time.time()
        if now - self._today_start > 24 * 60 * 60:
            self._today_cost = 0.0
            self._today_start = now

    def get_today_cost(self) -> float:
        """获取今日成本"""
        with self._lock:
            self._check_daily_reset()
            return self._today_cost

    def get_remaining_budget(self) -> float:
        """获取剩余预算"""
        return max(0.0, self._daily_budget - self.get_today_cost(


    def is_within_budget(self, estimated_cost: float) -> bool:
        """检查是否在预算内"""
        return self.get_today_cost( + estimated_cost <= self._daily_budget)

    def get_cost_report(self, days: int = 7) -> Dict[str, Any]:
        """生成成本报告"""
        with self._lock:
            cutoff_time = time.time() - days * 24 * 60 * 60
            recent_records = [
                r for r in self._cost_history
                if r["timestamp"] >= cutoff_time
            ]
            
            total_cost = sum(r["cost"] for r in recent_records)
            model_costs: Dict[str, float] = {}
            
            for record in recent_records:
                model_costs[record["model_name"]] = (
                    model_costs.get(record["model_name"], 0) + record["cost"]
                
            
            return {
                "total_cost": total_cost,
                "period_days": days,
                "model_breakdown": model_costs,
                "record_count": len(recent_records)
            }

    def set_daily_budget(self, budget: float) -> None:
        """设置每日预算"""
        with self._lock:
            self._daily_budget = budget


# 全局自适应模型选择器实例
_global_model_selector: Optional[AdaptiveModelSelector] = None
_global_cost_manager: Optional[CostManager] = None


def get_model_selector() -> AdaptiveModelSelector:
    """获取全局模型选择器"""
    global _global_model_selector
    if _global_model_selector is None:
        _global_model_selector = AdaptiveModelSelector()
    return _global_model_selector


def get_cost_manager() -> CostManager:
    """获取全局成本管理器"""
    global _global_cost_manager
    if _global_cost_manager is None:
        _global_cost_manager = CostManager()
    return _global_cost_manager


def select_ai_model(task_type: str, **kwargs) -> ModelSelectionResult:
    """便捷函数：选择AI模型"""
    selector = get_model_selector()
    task_type_enum = TaskType[task_type.upper()]
    return selector.select