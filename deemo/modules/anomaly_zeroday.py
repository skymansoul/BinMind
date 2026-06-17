"""
异常检测驱动零日发现模块

学习"正常"二进制行为（系统调用序列、数据流图拓扑），对目标进行异常评分。
高偏离度函数标记为潜在后门或漏洞区域。
"""

import logging
import os
import json
import pickle
import hashlib
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Union
from enum import Enum
from collections import defaultdict

import numpy as np

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

logger = logging.getLogger(__name__)


class AnomalyScoreLevel(Enum):
    """
    异常评分等级枚举
    
    NORMAL: 正常（0-0.2）
    SUSPICIOUS: 可疑（0.2-0.5）
    ANOMALOUS: 异常（0.5-0.8）
    CRITICAL: 严重异常（0.8-1.0）
    """
    NORMAL = "normal"
    SUSPICIOUS = "suspicious"
    ANOMALOUS = "anomalous"
    CRITICAL = "critical"


class FeatureType(Enum):
    """
    特征类型枚举
    
    SYSTEM_CALL_SEQUENCE: 系统调用序列
    DATA_FLOW_TOPOLOGY: 数据流图拓扑
    CONTROL_FLOW_GRAPH: 控制流图特征
    INSTRUCTION_PATTERNS: 指令模式
    STRING_ANALYSIS: 字符串分析
    IMPORT_TABLE: 导入表特征
    EXPORT_TABLE: 导出表特征
    SECTION_ANALYSIS: 节区分析
    """
    SYSTEM_CALL_SEQUENCE = "system_call_sequence"
    DATA_FLOW_TOPOLOGY = "data_flow_topology"
    CONTROL_FLOW_GRAPH = "control_flow_graph"
    INSTRUCTION_PATTERNS = "instruction_patterns"
    STRING_ANALYSIS = "string_analysis"
    IMPORT_TABLE = "import_table"
    EXPORT_TABLE = "export_table"
    SECTION_ANALYSIS = "section_analysis"


@dataclass
class FunctionFeatures:
    """函数特征数据类"""
    function_name: str
    function_address: int
    features: Dict[str, Any] = field(default_factory=dict)
    anomaly_score: float = 0.0
    score_level: AnomalyScoreLevel = AnomalyScoreLevel.NORMAL
    suspicious_reasons: List[str] = field(default_factory=list)


@dataclass
class AnomalyReport:
    """异常检测报告数据类"""
    binary_path: str
    binary_hash: str
    total_functions: int
    anomalous_functions: List[FunctionFeatures]
    overall_anomaly_score: float
    score_level: AnomalyScoreLevel
    timestamp: str = ""


@dataclass
class NormalModel:
    """正常行为模型数据类"""
    model_id: str
    feature_type: FeatureType
    statistics: Dict[str, Any] = field(default_factory=dict)
    thresholds: Dict[str, float] = field(default_factory=dict)
    trained_samples: int = 0
    creation_time: str = ""


class FeatureExtractor(ABC):
    """
    特征提取器基类
    """
    
    @abstractmethod
    def extract(self, binary_data: bytes) -> Dict[str, Any]:
        """
        提取特征
        
        Args:
            binary_data: 二进制数据
            
        Returns:
            特征字典
        """
        pass
    
    @abstractmethod
    def get_feature_type(self) -> FeatureType:
        """获取特征类型"""
        pass


class SystemCallFeatureExtractor(FeatureExtractor):
    """
    系统调用特征提取器
    """
    
    def extract(self, binary_data: bytes) -> Dict[str, Any]:
        """
        提取系统调用特征（模拟实现）
        
        Args:
            binary_data: 二进制数据
            
        Returns:
            特征字典
        """
        features = {
            "syscall_count": self._count_syscalls(binary_data),
            "syscall_entropy": self._calculate_entropy(binary_data),
            "suspicious_syscalls": self._detect_suspicious_syscalls(binary_data),
            "syscall_diversity": self._calculate_diversity(binary_data)
        }
        return features
    
    def get_feature_type(self) -> FeatureType:
        return FeatureType.SYSTEM_CALL_SEQUENCE
    
    def _count_syscalls(self, data: bytes) -> int:
        """模拟统计系统调用数量"""
        # 简单模拟：统计特定字节模式作为系统调用指令
        patterns = [b'\xcd\x80', b'\x0f\x05']  # int 0x80, syscall
        count = sum(data.count(pattern) for pattern in patterns)
        return count
    
    def _calculate_entropy(self, data: bytes) -> float:
        """计算熵值"""
        if len(data) == 0:
            return 0.0
        
        byte_counts = defaultdict(int)
        for byte in data:
            byte_counts[byte] += 1
        
        entropy = 0.0
        total = len(data)
        for count in byte_counts.values():
            prob = count / total
            entropy -= prob * (prob ** 0.5)  # 简化的熵计算
        
        return min(1.0, entropy * 10)
    
    def _detect_suspicious_syscalls(self, data: bytes) -> List[str]:
        """检测可疑系统调用"""
        suspicious = []
        
        # 检查常见的可疑系统调用相关模式
        if b'shutdown' in data.lower():
            suspicious.append("shutdown syscall")
        if b'reboot' in data.lower():
            suspicious.append("reboot syscall")
        if b'unlink' in data.lower():
            suspicious.append("unlink syscall")
        if b'chmod' in data.lower():
            suspicious.append("chmod syscall")
        if b'execve' in data.lower():
            suspicious.append("execve syscall")
        
        return suspicious
    
    def _calculate_diversity(self, data: bytes) -> float:
        """计算多样性"""
        unique_bytes = len(set(data

        return unique_bytes / 256.0


class ControlFlowFeatureExtractor(FeatureExtractor):
    """
    控制流特征提取器
    """
    
    def extract(self, binary_data: bytes) -> Dict[str, Any]:
        """
        提取控制流特征（模拟实现）
        
        Args:
            binary_data: 二进制数据
            
        Returns:
            特征字典
        """
        features = {
            "basic_block_count": self._estimate_basic_blocks(binary_data),
            "branch_density": self._calculate_branch_density(binary_data),
            "indirect_jump_ratio": self._calculate_indirect_jump_ratio(binary_data),
            "cyclomatic_complexity": self._estimate_complexity(binary_data)
        }
        return features
    
    def get_feature_type(self) -> FeatureType:
        return FeatureType.CONTROL_FLOW_GRAPH
    
    def _estimate_basic_blocks(self, data: bytes) -> int:
        """估计基本块数量"""
        # 简单模拟：统计跳转指令
        jump_patterns = [b'\xe9', b'\xeb', b'\xff\x25', b'\xff\x15']  # jmp, jmp short, indirect jmp
        count = sum(data.count(pattern) for pattern in jump_patterns)
        return max(1, count)
    
    def _calculate_branch_density(self, data: bytes) -> float:
        """计算分支密度"""
        branch_instructions = [b'\x74', b'\x75', b'\x7c', b'\x7d', b'\xe9', b'\xeb']
        count = sum(data.count(pattern) for pattern in branch_instructions)
        return min(1.0, count / len(data) * 100)
    
    def _calculate_indirect_jump_ratio(self, data: bytes) -> float:
        """计算间接跳转比例"""
        direct_jumps = data.count(b'\xe9') + data.count(b'\xeb')
        indirect_jumps = data.count(b'\xff\x25') + data.count(b'\xff\x15')
        
        total = direct_jumps + indirect_jumps,
        if total == 0:
            return 0.0
        
        return indirect_jumps / total
    
    def _estimate_complexity(self, data: bytes) -> float:
        """估计圈复杂度"""
        branch_count = data.count(b'\x74') + data.count(b'\x75') + data.count(b'\xe9') + data.count(b'\xeb')
        return min(100, branch_count * 2)


class StringFeatureExtractor(FeatureExtractor):
    """
    字符串特征提取器
    """
    
    def extract(self, binary_data: bytes) -> Dict[str, Any]:
        """
        提取字符串特征（模拟实现）
        
        Args:
            binary_data: 二进制数据
            
        Returns:
            特征字典
        """
        features = {
            "string_count": self._count_strings(binary_data),
            "avg_string_length": self._calculate_avg_length(binary_data),
            "suspicious_strings": self._detect_suspicious_strings(binary_data),
            "url_count": self._count_urls(binary_data),
            "email_count": self._count_emails(binary_data)
        }
        return features
    
    def get_feature_type(self) -> FeatureType:
        return FeatureType.STRING_ANALYSIS
    
    def _count_strings(self, data: bytes) -> int:
        """统计可打印字符串数量"""
        import re
        strings = re.findall(b'[ -~]{4,}', data)
        return len(strings)
    
    def _calculate_avg_length(self, data: bytes) -> float:
        """计算平均字符串长度"""
        import re
        strings = re.findall(b'[ -~]{4,}', data)
        if not strings:
            return 0.0
        return sum(len(s) for s in strings) / len(strings)
    
    def _detect_suspicious_strings(self, data: bytes) -> List[str]:
        """检测可疑字符串"""
        suspicious_patterns = [
            b'root', b'admin', b'password', b'backdoor',
            b'shell', b'exploit', b'payload', b'ROP',
            b'jmp esp', b'call esp', b'/bin/sh', b'cmd.exe'
        ]
        
        found = []
        for pattern in suspicious_patterns:
            if pattern in data.lower():
                found.append(pattern.decode('utf-8', errors='ignore'

        
        return found
    
    def _count_urls(self, data: bytes) -> int:
        """统计 URL 数量"""
        import re
        urls = re.findall(rb'https?://[^\s]+', data)
        return len(urls)
    
    def _count_emails(self, data: bytes) -> int:
        """统计邮箱数量"""
        import re
        emails = re.findall(rb'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', data)
        return len(emails)


class AnomalyDetector(ABC):
    """
    异常检测器基类
    """
    
    @abstractmethod
    def train(self, features_list: List[Dict[str, Any]]) -> None:
        """
        训练模型
        
        Args:
            features_list: 特征列表
        """
        pass
    
    @abstractmethod
    def detect(self, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        检测异常
        
        Args:
            features: 特征字典
            
        Returns:
            (异常分数, 可疑原因列表)
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
    
    @classmethod
    @abstractmethod
    def load_model(cls, path: str) -> 'AnomalyDetector':
        """
        加载模型
        
        Args:
            path: 模型路径
            
        Returns:
            异常检测器实例
        """
        pass


class ZScoreAnomalyDetector(AnomalyDetector):
    """
    Z-score 异常检测器
    
    使用统计方法检测偏离正常分布的特征
    """
    
    def __init__(self):
        self.mean: Dict[str, float] = {}
        self.std: Dict[str, float] = {}
        self.threshold: float = 3.0  # 默认阈值
    
    def train(self, features_list: List[Dict[str, Any]]) -> None:
        """
        训练模型
        
        Args:
            features_list: 特征列表
        """
        if not features_list:
            return
        
        # 获取所有特征键
        all_keys = set()
        for features in features_list:
            all_keys.update(features.keys(

        
        for key in all_keys:
            values = [f.get(key, 0.0) for f in features_list]
            if len(values) > 0:
                self.mean[key] = np.mean(values)
                self.std[key] = np.std(values) if len(values) > 1 else 1.0
        
        logger.info(f"Z-score 检测器训练完成，特征数量: {len(self.mean)}")
    
    def detect(self, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        检测异常
        
        Args:
            features: 特征字典
            
        Returns:
            (异常分数, 可疑原因列表)
        """
        if not self.mean:
            return 0.0, ["模型未训练"]
        
        scores = []
        reasons = []
        
        for key, value in features.items():
            if key in self.mean:
                mean = self.mean[key]
                std = max(self.std[key], 1e-6)
                
                # 计算 Z-score
                z_score = abs(value - mean) / std
                
                if z_score > self.threshold:
                    scores.append(z_score / self.threshold)
                    reasons.append(f"{key}: 偏离正常范围 (Z={z_score:.2f})")
        
        # 计算综合异常分数
        if scores:
            anomaly_score = min(1.0, sum(scores) / len(scores

        else:
            anomaly_score = 0.0
        
        return anomaly_score, reasons
    
    def save_model(self, path: str) -> None:
        """
        保存模型
        
        Args:
            path: 保存路径
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        model_data = {
            "mean": self.mean,
            "std": self.std,
            "threshold": self.threshold
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Z-score 模型已保存到 {path}")
    
    @classmethod
    def load_model(cls, path: str) -> 'ZScoreAnomalyDetector':
        """
        加载模型
        
        Args:
            path: 模型路径
            
        Returns:
            异常检测器实例
        """
        detector = cls()
        
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        detector.mean = model_data["mean"]
        detector.std = model_data["std"]
        detector.threshold = model_data["threshold"]
        
        logger.info(f"Z-score 模型已从 {path} 加载")
        return detector


class IsolationForestAnomalyDetector(AnomalyDetector):
    """
    Isolation Forest 异常检测器（模拟实现）
    
    使用隔离森林算法检测异常点
    """
    
    def __init__(self):
        self.trained = False
        self.feature_importance: Dict[str, float] = {}
    
    def train(self, features_list: List[Dict[str, Any]]) -> None:
        """
        训练模型（模拟）
        
        Args:
            features_list: 特征列表
        """
        if not features_list:
            return
        
        # 模拟特征重要性计算
        all_keys = set()
        for features in features_list:
            all_keys.update(features.keys(

        
        # 为每个特征分配随机重要性分数
        for key in all_keys:
            self.feature_importance[key] = np.random.uniform(0.1, 1.0)
        
        self.trained = True
        logger.info(f"Isolation Forest 检测器训练完成")
    
    def detect(self, features: Dict[str, Any]) -> Tuple[float, List[str]]:
        """
        检测异常（模拟）
        
        Args:
            features: 特征字典
            
        Returns:
            (异常分数, 可疑原因列表)
        """
        if not self.trained:
            return 0.0, ["模型未训练"]
        
        scores = []
        reasons = []
        
        for key, value in features.items():
            importance = self.feature_importance.get(key, 0.5)
            
            # 模拟异常检测：值越极端，分数越高
            normalized_value = min(1.0, abs(value) / 100)
            score_contribution = normalized_value * importance
            scores.append(score_contribution)
            
            if normalized_value > 0.5:
                reasons.append(f"{key}: 异常值 ({value})")
        
        if scores:
            anomaly_score = min(1.0, sum(scores) / len(scores

        else:
            anomaly_score = 0.0
        
        return anomaly_score, reasons
    
    def save_model(self, path: str) -> None:
        """
        保存模型
        
        Args:
            path: 保存路径
        """
        os.makedirs(os.path.dirname(path), exist_ok=True)
        
        model_data = {
            "feature_importance": self.feature_importance,
            "trained": self.trained
        }
        
        with open(path, 'wb') as f:
            pickle.dump(model_data, f)
        
        logger.info(f"Isolation Forest 模型已保存到 {path}")
    
    @classmethod
    def load_model(cls, path: str) -> 'IsolationForestAnomalyDetector':
        """
        加载模型
        
        Args:
            path: 模型路径
            
        Returns:
            异常检测器实例
        """
        detector = cls()
        
        with open(path, 'rb') as f:
            model_data = pickle.load(f)
        
        detector.feature_importance = model_data["feature_importance"]
        detector.trained = model_data["trained"]
        
        logger.info(f"Isolation Forest 模型已从 {path} 加载")
        return detector


class AnomalyZerodayAnalyzer(BaseAnalyzer):
    """
    异常检测驱动零日发现分析器
    
    学习正常二进制行为模式，对目标进行异常评分，标记潜在后门或漏洞区域。
    """
    
    def __init__(self):
        """初始化分析器"""
        self.extractors: List[FeatureExtractor] = [
            SystemCallFeatureExtractor(),
            ControlFlowFeatureExtractor(),
            StringFeatureExtractor()
        ]
        self.detectors: Dict[str, AnomalyDetector] = {
            "zscore": ZScoreAnomalyDetector(),
            "isolation_forest": IsolationForestAnomalyDetector()
        }
        self.trained = False
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行异常检测分析
        
        Args:
            **kwargs: 分析参数
                - binary_path: 二进制文件路径
                - binary_data: 二进制数据（可选）
                - model_path: 预训练模型路径（可选）
                - detector_type: 检测器类型（zscore/isolation_forest）
        
        Returns:
            分析结果字典
        """
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        model_path = kwargs.get("model_path")
        detector_type = kwargs.get("detector_type", "zscore")
        
        logger.info(f"开始异常检测分析: {binary_path}")
        
        try:
            # 加载二进制数据
            if binary_data is None and binary_path:
                if os.path.exists(binary_path):
                    with open(binary_path, 'rb') as f:
                        binary_data = f.read()
                else:
                    return {"success": False, "error": f"文件不存在: {binary_path}"}
            
            if binary_data is None:
                return {"success": False, "error": "缺少二进制数据"}
            
            # 加载预训练模型（如果提供）
            if model_path and os.path.exists(model_path):
                self._load_models(model_path)
            
            # 提取特征
            all_features = self._extract_all_features(binary_data)
            
            # 使用所有检测器进行检测
            results = []
            for name, detector in self.detectors.items():
                score, reasons = detector.detect(all_features)
                results.append({)
                    "detector": name,
                    "anomaly_score": score,
                    "score_level": self._get_score_level(score).value,
                    "reasons": reasons
                }
            
            # 综合评分
            avg_score = sum(r["anomaly_score"] for r in results) / len(results)
            score_level = self._get_score_level(avg_score)
            
            # 生成报告
            report = AnomalyReport()
                binary_path=binary_path or "memory",
                binary_hash=self._calculate_hash(binary_data),
                total_functions=1,
                anomalous_functions=[
                    FunctionFeatures()
                        function_name="main",
                        function_address=0,
                        features=all_features,
                        anomaly_score=avg_score,
                        score_level=score_level,
                        suspicious_reasons=[r["reasons"] for r in results if r["reasons"]]
                    
                ],
                overall_anomaly_score=avg_score,
                score_level=score_level
            
            
            return {
                "success": True,
                "result": {
                    "binary_hash": report.binary_hash,
                    "overall_anomaly_score": avg_score,
                    "score_level": score_level.value,
                    "detector_results": results,
                    "features": all_features,
                    "report": {
                        "total_functions": report.total_functions,
                        "anomalous_functions": len([f for f in report.anomalous_functions )
                                                    if f.score_level != AnomalyScoreLevel.NORMAL]),
                        "summary": self._generate_summary(report)
                    }
                }
            }
            
        except Exception as e:
            logger.error(f"异常检测分析失败: {e}")
            return {"success": False, "error": str(e)}
    
    def _extract_all_features(self, binary_data: bytes) -> Dict[str, Any]:
        """
        提取所有特征
        
        Args:
            binary_data: 二进制数据
            
        Returns:
            合并后的特征字典
        """
        all_features = {}
        
        for extractor in self.extractors:
            features = extractor.extract(binary_data)
            prefix = extractor.get_feature_type().value,
            for key, value in features.items():
                all_features[f"{prefix}_{key}"] = value
        
        return all_features
    
    def _get_score_level(self, score: float) -> AnomalyScoreLevel:
        """
        获取评分等级
        
        Args:
            score: 异常分数
            
        Returns:
            评分等级
        """
        if score < 0.2:
            return AnomalyScoreLevel.NORMAL
        elif score < 0.5:
            return AnomalyScoreLevel.SUSPICIOUS
        elif score < 0.8:
            return AnomalyScoreLevel.ANOMALOUS
        else:
            return AnomalyScoreLevel.CRITICAL
    
    def _calculate_hash(self, data: bytes) -> str:
        """
        计算数据哈希
        
        Args:
            data: 数据
            
        Returns:
            SHA256 哈希值
        """
        return hashlib.sha256(data).hexdigest()
    
    def _generate_summary(self, report: AnomalyReport) -> str:
        """
        生成摘要
        
        Args:
            report: 异常报告
            
        Returns:
            摘要字符串
        """
        level = report.score_level,
        if level == AnomalyScoreLevel.NORMAL:
            return "未检测到异常行为"
        elif level == AnomalyScoreLevel.SUSPICIOUS:
            return "检测到可疑行为，建议进一步分析"
        elif level == AnomalyScoreLevel.ANOMALOUS:
            return "检测到异常行为，可能存在安全风险"
        else:
            return "检测到严重异常，可能存在后门或漏洞"
    
    def train_normal_model(self, binary_paths: List[str], output_dir: str = "models/anomaly") -> bool:
        """
        训练正常行为模型
        
        Args:
            binary_paths: 正常二进制文件路径列表
            output_dir: 模型输出目录
            
        Returns:
            是否成功训练
        """
        logger.info(f"开始训练正常行为模型，样本数量: {len(binary_paths)}")
        
        try:
            # 收集所有特征
            all_features_list = []
            
            for path in binary_paths:
                if os.path.exists(path):
                    with open(path, 'rb') as f:
                        data = f.read()
                    features = self._extract_all_features(data)
                    all_features_list.append(features)
            
            if not all_features_list:
                logger.error("没有有效的训练数据")
                return False
            
            # 训练所有检测器
            for name, detector in self.detectors.items():
                detector.train(all_features_list)
                
                # 保存模型
                model_path = os.path.join(output_dir, f"{name}_model.pkl")
                detector.save_model(model_path)
            
            self.trained = True
            logger.info("正常行为模型训练完成")
            return True
            
        except Exception as e:
            logger.error(f"训练失败: {e}")
            return False
    
    def _load_models(self, model_dir: str) -> None:
        """
        加载预训练模型
        
        Args:
            model_dir: 模型目录
        """
        for name, detector in self.detectors.items():
            model_path = os.path.join(model_dir, f"{name}_model.pkl")
            if os.path.exists(model_path):
                try:
                    if name == "zscore":
                        self.detectors[name] = ZScoreAnomalyDetector.load_model(model_path)
                    elif name == "isolation_forest":
                        self.detectors[name] = IsolationForestAnomalyDetector.load_model(model_path)
                except Exception as e:
                    logger.warning(f"加载 {name} 模型失败: {e}")
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="AnomalyZerodayAnalyzer",
            type=AnalyzerType.VULNERABILITY_DETECTOR,
            version="1.0.0",
            description="异常检测驱动零日发现分析器，学习正常行为模式并检测异常",
            author="BinaryAnalysisPlatform",
            dependencies=["numpy", "scikit-learn"],
            supported_platforms=["x86", "x86_64", "arm", "arm64"])
        

    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        binary_path = kwargs.get("binary_path")
        binary_data = kwargs.get("binary_data")
        
        if not binary_path and binary_data is None:
            return False, "必须提供 binary_path 或 binary_data"
        
        if binary_path and not os.path.exists(binary_path):
            return False, f"文件不存在: {binary_path}"
        
        if binary_data is not None and not isinstance(binary_data, bytes):
            return False, "binary_data 必须是 bytes 类型"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        self.detectors = {
            "zscore": ZScoreAnomalyDetector(),
            "isolation_forest": IsolationForestAnomalyDetector()
        }
        self.trained = False)))))))))))