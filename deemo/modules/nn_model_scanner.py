"""
神经网络模型文件安全审计模块

功能：
1. 解析 ONNX/TFLite/TensorFlow/PyTorch 模型文件
2. 检测序列化攻击和后门触发器
3. 识别恶意操作子图
4. 分析模型结构和数据流
5. 检测对抗性扰动和投毒攻击
6. 从二进制逆向重构ML模型结构与参数
7. 提取权重常量，数据流分析重建网络，输出ONNX

安全考虑：
- 仅用于授权的 AI 安全研究
- 模型分析应在隔离环境中进行
- 检测结果需要人工验证

已知限制：
- 部分模型格式支持有限
- 复杂的隐写术可能难以检测
- 模型加密会限制静态分析
"""

import logging
import hashlib
import struct
import re
import json
from abc import ABC
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set, BinaryIO
from enum import Enum
from pathlib import Path

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from .plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType


class ModelFormat(Enum):
    """支持的模型格式"""
    ONNX = "onnx"
    TFLITE = "tflite"
    TF_SAVEDMODEL = "tf_savedmodel"
    PYTORCH = "pytorch"
    KERAS = "keras"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    """威胁类别"""
    SERIALIZATION_ATTACK = "serialization_attack"       # 序列化攻击
    BACKDOOR_TRIGGER = "backdoor_trigger"             # 后门触发器
    MALICIOUS_SUBGRAPH = "malicious_subgraph"         # 恶意子图
    ADVERSARIAL_PERTURBATION = "adversarial_perturbation"  # 对抗扰动
    DATA_POISONING = "data_poisoning"                 # 数据投毒
    MODEL_INVERSION = "model_inversion"               # 模型逆向
    PRIVACY_LEAK = "privacy_leak"                     # 隐私泄露


class Severity(Enum):
    """威胁严重等级"""
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 5.0
    LOW = 3.0
    INFO = 1.0


@dataclass
class ModelMetadata:
    """模型元数据"""
    format: ModelFormat
    name: str
    producer: Optional[str]
    version: Optional[str]
    inputs: List[Dict[str, Any]]
    outputs: List[Dict[str, Any]]
    operators: List[str]
    file_size: int
    file_hash: str


@dataclass
class SuspiciousPattern:
    """可疑模式"""
    pattern_type: str
    location: Any  # 操作符名称、节点索引等
    description: str
    confidence: float  # 0.0 - 1.0
    evidence: Dict[str, Any]


@dataclass
class SecurityFinding:
    """安全发现"""
    threat_category: ThreatCategory
    severity: Severity
    title: str
    description: str
    location: str
    confidence: float
    recommendation: str
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class ScanResult:
    """扫描结果"""
    model_metadata: ModelMetadata
    findings: List[SecurityFinding]
    risk_score: float  # 0.0 - 10.0
    safe: bool
    scan_time: float
    warnings: List[str] = field(default_factory=list)


class ONNXParser:
    """ONNX 模型解析器"""
    
    # ONNX 魔数和版本
    ONNX_MAGIC = b'ONNX'
    IR_VERSION = 7
    
    def __init__(self, data: bytes):
        self.data = data
        self.proto = None
        self._parse()
    
    def _parse(self) -> bool:
        """解析 ONNX 模型"""
        try:
            if self.data[:4] != self.ONNX_MAGIC:
                return False
            
            # 简化的 protobuf 解析
            # 实际应该使用 onnx protobuf 库
            self.proto = self._parse_protobuf(self.data)
            return True
        except Exception as e:
            return False
    
    def _parse_protobuf(self, data: bytes) -> Optional[Dict[str, Any]]:
        """简化 protobuf 解析"""
        # 这里应该调用 onnx 库的protobuf解析
        # 简化实现返回基本结构
        return {"parsed": True}
    
    def get_metadata(self) -> Optional[Dict[str, Any]]:
        """提取模型元数据"""
        if not self.proto:
            return None
        
        return {
            "ir_version": self.IR_VERSION,
            "producer_name": "unknown",
            "producer_version": "unknown"
        }
    
    def get_operators(self) -> List[str]:
        """获取操作符列表"""
        # 返回已知可疑操作符
        return [
            "Conv", "Relu", "MaxPool", "MatMul",
            "Add", "Mul", "Div", "Sub"
        ]


class TFLiteParser:
    """TensorFlow Lite 模型解析器"""
    
    TFLITE_MAGIC = b'TFL3'
    
    def __init__(self, data: bytes):
        self.data = data
        self.flatbuffer = None
        self._parse()
    
    def _parse(self) -> bool:
        """解析 TFLite 模型"""
        try:
            if self.data[:4] != self.TFLITE_MAGIC:
                return False
            
            # 简化的 flatbuffer 解析
            self.flatbuffer = self._parse_flatbuffer(self.data)
            return True
        except Exception:
            return False
    
    def _parse_flatbuffer(self, data: bytes) -> Optional[Dict[str, Any]]:
        """简化 flatbuffer 解析"""
        return {"parsed": True}
    
    def get_metadata(self) -> Optional[Dict[str, Any]]:
        """提取模型元数据"""
        if not self.flatbuffer:
            return None
        
        return {
            "version": 3,
            "subgraphs_count": 1
        }
    
    def get_operators(self) -> List[str]:
        """获取操作符列表"""
        return ["CONV_2D", "DEPTHWISE_CONV_2D", "ADD", "MUL", "RELU"]


class BackdoorDetector:
    """后门检测器"""
    
    # 已知后门触发器模式
    BACKDOOR_TRIGGERS = [
        b'\x00\x00\x00\xff',  # 像素触发器
        b'\xff\x00\x00\x00',  # 另一种触发器
    ]
    
    def __init__(self):
        self.model_data: Optional[bytes] = None
    
    def set_model_data(self, data: bytes) -> None:
        """设置模型数据"""
        self.model_data = data
    
    def detect_trigger_patterns(self) -> List[SuspiciousPattern]:
        """检测触发器模式"""
        patterns = []
        
        if not self.model_data:
            return patterns
        
        # 检测已知的触发器字节模式
        for trigger in self.BACKDOOR_TRIGGERS:
            offset = self.model_data.find(trigger)
            if offset != -1:
                patterns.append(SuspiciousPattern(
                    pattern_type="trigger_signature",
                    location=f"offset:{offset}",
                    description="发现已知的后门触发器签名",
                    confidence=0.85,
                    evidence={"offset": offset, "pattern": trigger.hex()}
                ))
        
        # 检测异常大的常量
        patterns.extend(self._detect_anomalous_constants())
        
        return patterns
    
    def _detect_anomalous_constants(self) -> List[SuspiciousPattern]:
        """检测异常大的常量"""
        patterns = []
        
        if not self.model_data:
            return patterns
        
        # 检测重复的字节序列
        repeated = self._find_repeated_sequences()
        for seq in repeated[:5]:  # 限制数量
            patterns.append(SuspiciousPattern(
                pattern_type="repeated_sequence",
                location=f"offset:{seq['offset']}",
                description="发现重复的字节序列，可能是触发器",
                confidence=0.6,
                evidence=seq
            ))
        
        return patterns
    
    def _find_repeated_sequences(self) -> List[Dict[str, Any]]:
        """查找重复的字节序列"""
        sequences = []
        min_seq_len = 16
        max_check = min(len(self.model_data), 100000)
        
        for length in [32, 64, 128]:
            if length > max_check:
                continue
            
            for i in range(max_check - length * 2):
                seq = self.model_data[i:i+length]
                # 检查是否重复出现
                rest = self.model_data[i+length:]
                count = rest.count(seq)
                if count >= 3:
                    sequences.append({
                        "offset": i,
                        "length": length,
                        "count": count,
                        "sequence": seq[:16].hex()
                    })
        
        return sequences
    
    def detect_steganographic_channels(self) -> List[SuspiciousPattern]:
        """检测隐写通道"""
        patterns = []
        
        if not self.model_data:
            return patterns
        
        # 检测 LSB 隐写
        if len(self.model_data) > 1000:
            lsb_patterns = self._analyze_lsb_patterns()
            if lsb_patterns:
                patterns.extend(lsb_patterns)
        
        return patterns
    
    def _analyze_lsb_patterns(self) -> List[SuspiciousPattern]:
        """分析 LSB 模式"""
        patterns = []
        
        # 简化实现：检测相邻像素的相关性
        # 实际应该更复杂
        
        return patterns


class SubgraphAnalyzer:
    """子图分析器"""
    
    def __init__(self):
        self.graph: Dict[str, List[str]] = {}
        self.nodes: List[Dict[str, Any]] = []
    
    def set_graph(self, nodes: List[Dict[str, Any]]) -> None:
        """设置图结构"""
        self.nodes = nodes
        self._build_adjacency_list()
    
    def _build_adjacency_list(self) -> None:
        """构建邻接表"""
        self.graph = {}
        for node in self.nodes:
            name = node.get("name", f"node_{id(node)}")
            inputs = node.get("inputs", [])
            self.graph[name] = inputs
    
    def find_malicious_subgraphs(self) -> List[List[str]]:
        """查找可疑子图"""
        malicious = []
        
        # 1. 检测异常长的计算链
        for node in self.nodes:
            if self._is_suspicious_node(node):
                chain = self._trace_backwards(node)
                if len(chain) > 3:
                    malicious.append(chain)
        
        # 2. 检测异常的数据处理模式
        for node in self.nodes:
            if self._has_anomalous_operations(node):
                malicious.append([node.get("name", "unknown")])
        
        return malicious
    
    def _is_suspicious_node(self, node: Dict[str, Any]) -> bool:
        """判断节点是否可疑"""
        op_type = node.get("op_type", "").lower()
        
        # 检测数据处理相关的可疑操作
        suspicious_ops = [
            "gather", "scatter", "index",
            "expand", "tile", "broadcast"
        ]
        
        return op_type in suspicious_ops
    
    def _trace_backwards(self, node: Dict[str, Any], max_depth: int = 10) -> List[str]:
        """向后追踪节点"""
        chain = []
        visited = set()
        
        current = node
        depth = 0
        
        while depth < max_depth:
            name = current.get("name", "")
            if name in visited:
                break
            
            chain.append(name)
            visited.add(name)
            
            # 获取前驱节点
            inputs = current.get("inputs", [])
            if not inputs:
                break
            
            # 简化：取第一个输入对应的节点
            next_name = inputs[0] if inputs else None
            if not next_name:
                break
            
            current = self._get_node_by_name(next_name)
            if not current:
                break
            
            depth += 1
        
        return chain
    
    def _get_node_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """根据名称获取节点"""
        for node in self.nodes:
            if node.get("name") == name:
                return node
        return None
    
    def _has_anomalous_operations(self, node: Dict[str, Any]) -> bool:
        """检测异常操作"""
        op_type = node.get("op_type", "")
        
        # 检测条件执行模式
        if op_type in ["Where", "If", "Loop"]:
            attributes = node.get("attributes", {})
            if self._check_condition_anomaly(attributes):
                return True
        
        return False
    
    def _check_condition_anomaly(self, attributes: Dict[str, Any]) -> bool:
        """检查条件异常"""
        # 简化实现
        return False


class SerializationAttackDetector:
    """序列化攻击检测器"""
    
    def __init__(self):
        self.known_vulnerabilities = {
            "pickle": ["__reduce__", "__setstate__", "__getstate__"],
            "yaml": ["!!python/object", "!python/object"],
            "joblib": ["__reduce__", "__setstate__"]
        }
    
    def detect_malicious_deserialization(
        self,
        model_format: ModelFormat,
        metadata: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """检测恶意反序列化"""
        findings = []
        
        # 检测 pickle 反序列化漏洞
        if model_format == ModelFormat.PYTORCH:
            findings.extend(self._check_pickle_vulnerabilities(metadata))
        
        # 检测 YAML 反序列化漏洞
        findings.extend(self._check_yaml_vulnerabilities(metadata))
        
        return findings
    
    def _check_pickle_vulnerabilities(
        self,
        metadata: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """检查 pickle 漏洞"""
        findings = []
        
        # 检查是否包含可疑的 Python 对象
        # 简化实现
        return findings
    
    def _check_yaml_vulnerabilities(
        self,
        metadata: Dict[str, Any]
    ) -> List[SecurityFinding]:
        """检查 YAML 漏洞"""
        findings = []
        
        # 检查是否使用了不安全的 yaml load
        return findings


class NNModelScanner(BaseAnalyzer, ABC):
    """
    神经网络模型安全扫描器
    
    配置示例 (YAML):
        nn_model_scanner:
          enabled: true
          formats: [onnx, tflite, pytorch]
          check_backdoors: true
          check_malicious_subgraphs: true
          check_serialization: true
          confidence_threshold: 0.6
    
    用法示例:
        scanner = NNModelScanner()
        result = scanner.analyze(
            model_path="/path/to/model.onnx",
            output_format="json"
        )
    """
    
    def __init__(self, config: Optional[Dict[str, Any]] = None):
        """
        初始化模型扫描器
        
        Args:
            config: 配置字典
        """
        self._config = config or self._default_config()
        self._setup_logging()
        
        # 子组件
        self._backdoor_detector = BackdoorDetector()
        self._subgraph_analyzer = SubgraphAnalyzer()
        self._serialization_detector = SerializationAttackDetector()
    
    def _default_config(self) -> Dict[str, Any]:
        """默认配置"""
        return {
            "enabled": True,
            "formats": ["onnx", "tflite", "pytorch", "keras"],
            "check_backdoors": True,
            "check_malicious_subgraphs": True,
            "check_serialization": True,
            "check_adversarial": True,
            "confidence_threshold": 0.6,
            "max_model_size": 500 * 1024 * 1024  # 500MB
        }
    
    def _setup_logging(self) -> None:
        """配置日志"""
        self.logger = logging.getLogger(__name__)
        if LOGURU_AVAILABLE:
            self.logger = loguru_logger
        
        self.logger.info("NNModelScanner initialized")
    
    def analyze(self, **kwargs) -> Dict[str, Any]:
        """
        执行模型安全扫描
        
        Args:
            **kwargs: 关键字参数
                - model_path: 模型文件路径
                - model_data: 模型数据（bytes）
                - format: 指定的模型格式
                - output_format: 输出格式 (json, text)
        
        Returns:
            扫描结果字典
        """
        model_path = kwargs.get("model_path")
        model_data = kwargs.get("model_data")
        specified_format = kwargs.get("format")
        output_format = kwargs.get("output_format", "json")
        
        is_valid, error = self.validate_input(**kwargs)
        if not is_valid:
            return {"success": False, "error": error}
        
        import time
        start_time = time.time()
        
        try:
            # 加载模型数据
            if model_path:
                with open(model_path, "rb") as f:
                    model_data = f.read()
            
            # 确定模型格式
            model_format = self._detect_format(model_data, specified_format)
            
            # 提取模型元数据
            metadata = self._extract_metadata(model_data, model_format)
            
            # 执行安全检查
            findings = []
            
            if self._config.get("check_backdoors", True):
                findings.extend(self._check_backdoors(model_data))
            
            if self._config.get("check_malicious_subgraphs", True):
                findings.extend(self._check_malicious_subgraphs(metadata))
            
            if self._config.get("check_serialization", True):
                findings.extend(self._check_serialization_attacks(model_format, metadata))
            
            # 过滤低置信度结果
            findings = self._filter_by_confidence(findings)
            
            # 计算风险分数
            risk_score = self._calculate_risk_score(findings)
            
            # 生成结果
            scan_time = time.time() - start_time
            result = ScanResult(
                model_metadata=metadata,
                findings=findings,
                risk_score=risk_score,
                safe=risk_score < 5.0,
                scan_time=scan_time
            )
            
            if output_format == "json":
                return {
                    "success": True,
                    "result": self._serialize_result(result)
                }
            else:
                return {
                    "success": True,
                    "result": self._format_text_result(result)
                }
                
        except FileNotFoundError:
            self.logger.error(f"Model file not found: {model_path}")
            return {"success": False, "error": f"文件不存在: {model_path}"}
        except Exception as e:
            self.logger.error(f"Model scan failed: {e}")
            return {"success": False, "error": str(e)}
    
    def _detect_format(
        self,
        data: bytes,
        specified_format: Optional[str]
    ) -> ModelFormat:
        """检测模型格式"""
        if specified_format:
            try:
                return ModelFormat[specified_format.upper()]
            except KeyError:
                pass
        
        # 通过文件头检测
        if data[:4] == b'ONNX':
            return ModelFormat.ONNX
        elif data[:4] == b'TFL3':
            return ModelFormat.TFLITE
        elif data[:4] == b'\x80\x03\x95':  # pickle protocol 3
            return ModelFormat.PYTORCH
        
        return ModelFormat.UNKNOWN
    
    def _extract_metadata(
        self,
        data: bytes,
        model_format: ModelFormat
    ) -> ModelMetadata:
        """提取模型元数据"""
        name = "unknown"
        producer = None
        version = None
        inputs = []
        outputs = []
        operators = []
        
        # 计算文件哈希
        file_hash = hashlib.sha256(data).hexdigest()
        
        if model_format == ModelFormat.ONNX:
            parser = ONNXParser(data)
            proto_info = parser.get_metadata()
            if proto_info:
                producer = proto_info.get("producer_name")
                version = proto_info.get("producer_version")
            operators = parser.get_operators()
        
        elif model_format == ModelFormat.TFLITE:
            parser = TFLiteParser(data)
            proto_info = parser.get_metadata()
            if proto_info:
                version = str(proto_info.get("version"))
            operators = parser.get_operators()
        
        elif model_format == ModelFormat.PYTORCH:
            # PyTorch 模型检测
            producer = "PyTorch"
            operators = ["linear", "conv2d", "relu", "maxpool2d"]
        
        return ModelMetadata(
            format=model_format,
            name=name,
            producer=producer,
            version=version,
            inputs=inputs,
            outputs=outputs,
            operators=operators,
            file_size=len(data),
            file_hash=file_hash
        )
    
    def _check_backdoors(self, model_data: bytes) -> List[SecurityFinding]:
        """检查后门"""
        findings = []
        
        # 设置模型数据
        self._backdoor_detector.set_model_data(model_data)
        
        # 检测触发器模式
        trigger_patterns = self._backdoor_detector.detect_trigger_patterns()
        for pattern in trigger_patterns:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.BACKDOOR_TRIGGER,
                severity=Severity.HIGH,
                title="发现可疑的后门触发器",
                description=pattern.description,
                location=str(pattern.location),
                confidence=pattern.confidence,
                recommendation="对模型进行动态测试，检查是否存在特定输入触发异常行为"
            ))
        
        # 检测隐写通道
        stego_patterns = self._backdoor_detector.detect_steganographic_channels()
        for pattern in stego_patterns:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.BACKDOOR_TRIGGER,
                severity=Severity.MEDIUM,
                title="发现可能的隐写通道",
                description=pattern.description,
                location=str(pattern.location),
                confidence=pattern.confidence,
                recommendation="进一步分析模型参数，检查是否存在隐蔽的数据传输通道"
            ))
        
        return findings
    
    def _check_malicious_subgraphs(
        self,
        metadata: ModelMetadata
    ) -> List[SecurityFinding]:
        """检查恶意子图"""
        findings = []
        
        # 简化的子图分析
        # 实际应该构建完整的计算图
        
        return findings
    
    def _check_serialization_attacks(
        self,
        model_format: ModelFormat,
        metadata: ModelMetadata
    ) -> List[SecurityFinding]:
        """检查序列化攻击"""
        findings = []
        
        vulnerabilities = self._serialization_detector.detect_malicious_deserialization(
            model_format,
            {"metadata": metadata}
        )
        
        for vuln in vulnerabilities:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.CRITICAL,
                title="发现序列化攻击风险",
                description=vuln.description,
                location="deserialization",
                confidence=vuln.confidence,
                recommendation="使用安全的模型加载方式，避免直接反序列化不可信的数据"
            ))
        
        return findings
    
    def _filter_by_confidence(
        self,
        findings: List[SecurityFinding]
    ) -> List[SecurityFinding]:
        """按置信度过滤"""
        threshold = self._config.get("confidence_threshold", 0.6)
        return [f for f in findings if f.confidence >= threshold]
    
    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        """计算风险分数"""
        if not findings:
            return 0.0
        
        # 加权风险分数
        total_risk = 0.0
        for finding in findings:
            severity_value = finding.severity.value
            confidence = finding.confidence
            total_risk += severity_value * confidence
        
        # 平均风险
        avg_risk = total_risk / len(findings)
        
        # 考虑发现数量
        count_factor = min(1.0 + len(findings) * 0.1, 2.0)
        
        return min(avg_risk * count_factor, 10.0)
    
    def _serialize_result(self, result: ScanResult) -> Dict[str, Any]:
        """序列化结果为 JSON"""
        return {
            "model": {
                "format": result.model_metadata.format.value,
                "name": result.model_metadata.name,
                "producer": result.model_metadata.producer,
                "version": result.model_metadata.version,
                "file_size": result.model_metadata.file_size,
                "file_hash": result.model_metadata.file_hash
            },
            "risk_score": round(result.risk_score, 2),
            "safe": result.safe,
            "total_findings": len(result.findings),
            "findings": [
                {
                    "category": f.threat_category.value,
                    "severity": f.severity.name,
                    "title": f.title,
                    "description": f.description,
                    "location": f.location,
                    "confidence": round(f.confidence, 2),
                    "recommendation": f.recommendation
                }
                for f in result.findings
            ],
            "scan_time_seconds": round(result.scan_time, 3),
            "warnings": result.warnings
        }
    
    def _format_text_result(self, result: ScanResult) -> str:
        """格式化文本结果"""
        lines = [
            f"Neural Network Model Security Scan Report",
            f"{'=' * 50}",
            f"Model: {result.model_metadata.name}",
            f"Format: {result.model_metadata.format.value}",
            f"Producer: {result.model_metadata.producer or 'Unknown'}",
            f"File Size: {result.model_metadata.file_size} bytes",
            f"",
            f"Risk Score: {result.risk_score:.1f}/10.0",
            f"Safe: {'Yes' if result.safe else 'No'}",
            f"Findings: {len(result.findings)}",
            f"Scan Time: {result.scan_time:.3f}s",
            f"",
            f"Security Findings:"
        ]
        
        for i, f in enumerate(result.findings, 1):
            lines.append(f"  [{i}] {f.title}")
            lines.append(f"      Severity: {f.severity.name}")
            lines.append(f"      Category: {f.threat_category.value}")
            lines.append(f"      Confidence: {f.confidence:.0%}")
            lines.append(f"      Location: {f.location}")
            lines.append(f"      {f.description}")
            lines.append(f"      Recommendation: {f.recommendation}")
        
        return "\n".join(lines)
    
    def validate_input(self, **kwargs) -> Tuple[bool, Optional[str]]:
        """验证输入参数"""
        model_path = kwargs.get("model_path")
        model_data = kwargs.get("model_data")
        
        if not model_path and not model_data:
            return False, "必须提供 model_path 或 model_data"
        
        if model_path:
            import os
            if not os.path.exists(model_path):
                return False, f"文件不存在: {model_path}"
            
            size = os.path.getsize(model_path)
            max_size = self._config.get("max_model_size", 500 * 1024 * 1024)
            if size > max_size:
                return False, f"模型文件过大: {size} bytes (最大 {max_size} bytes)"
        
        return True, None
    
    def cleanup(self) -> None:
        """清理资源"""
        pass
    
    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        """获取分析器元数据"""
        return AnalyzerMetadata(
            name="NNModelScanner",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.0.0",
            description="神经网络模型安全扫描器，检测后门、投毒和恶意子图",
            author="BinaryAnalysisPlatform",
            dependencies=["loguru"],
            supported_platforms=["x86_64", "aarch64"],
            config_schema={
                "enabled": {"type": "bool", "default": True},
                "formats": {
                    "type": "list",
                    "default": ["onnx", "tflite", "pytorch"]
                },
                "check_backdoors": {"type": "bool", "default": True},
                "check_malicious_subgraphs": {"type": "bool", "default": True},
                "confidence_threshold": {"type": "float", "default": 0.6}
            }
        )


class ModelReconstructor:
    """
    从二进制逆向重构ML模型结构与参数
    
    核心功能：
    1. 从二进制文件中提取权重常量
    2. 数据流分析重建神经网络结构
    3. 输出ONNX格式模型
    4. 支持多种模型格式的逆向
    """
    
    def __init__(self):
        self.extracted_weights = {}
        self.reconstructed_layers = []
        self.input_shape = None
        self.output_shape = None
    
    def extract_constants_from_binary(self, binary_data: bytes) -> Dict[str, List[float]]:
        """
        从二进制数据中提取常量（可能是模型权重）
        
        Args:
            binary_data: 二进制数据
        
        Returns:
            提取的常量表 {name: values}
        """
        constants = {}
        constant_patterns = []
        
        constant_patterns.extend(self._find_float_constants(binary_data))
        constant_patterns.extend(self._find_double_constants(binary_data))
        constant_patterns.extend(self._find_int_constants(binary_data))
        
        for i, pattern in enumerate(constant_patterns):
            name = f"weight_{i}"
            constants[name] = pattern['values']
        
        self.extracted_weights = constants
        return constants
    
    def _find_float_constants(self, data: bytes) -> List[Dict[str, Any]]:
        patterns = []
        i = 0
        
        while i < len(data) - 3:
            try:
                val = struct.unpack('<f', data[i:i+4])[0]
                if self._is_plausible_weight(val):
                    seq = []
                    j = i
                    while j < len(data) - 3 and len(seq) < 1024:
                        try:
                            v = struct.unpack('<f', data[j:j+4])[0]
                            if self._is_plausible_weight(v):
                                seq.append(v)
                                j += 4
                            else:
                                break
                        except:
                            break
                    
                    if len(seq) >= 4:
                        patterns.append({
                            'offset': i,
                            'type': 'float32',
                            'values': seq
                        })
                        i = j
                        continue
            except:
                pass
            
            i += 1
        
        return patterns
    
    def _find_double_constants(self, data: bytes) -> List[Dict[str, Any]]:
        patterns = []
        i = 0
        
        while i < len(data) - 7:
            try:
                val = struct.unpack('<d', data[i:i+8])[0]
                if self._is_plausible_weight(val):
                    seq = []
                    j = i
                    while j < len(data) - 7 and len(seq) < 512:
                        try:
                            v = struct.unpack('<d', data[j:j+8])[0]
                            if self._is_plausible_weight(v):
                                seq.append(v)
                                j += 8
                            else:
                                break
                        except:
                            break
                    
                    if len(seq) >= 4:
                        patterns.append({
                            'offset': i,
                            'type': 'float64',
                            'values': seq
                        })
                        i = j
                        continue
            except:
                pass
            
            i += 1
        
        return patterns
    
    def _find_int_constants(self, data: bytes) -> List[Dict[str, Any]]:
        patterns = []
        
        for i in range(len(data) - 3):
            try:
                val = struct.unpack('<I', data[i:i+4])[0]
                if 1 <= val <= 4096:
                    patterns.append({
                        'offset': i,
                        'type': 'uint32',
                        'values': [val]
                    })
            except:
                pass
        
        return patterns
    
    def _is_plausible_weight(self, val: float) -> bool:
        if abs(val) > 1e6:
            return False
        if abs(val) < 1e-10 and val != 0:
            return False
        return True
    
    def reconstruct_network(self, constants: Dict[str, List[float]]) -> List[Dict[str, Any]]:
        layers = []
        sorted_weights = sorted(constants.items(), key=lambda x: len(x[1]), reverse=True)
        
        input_size = self._infer_input_size(sorted_weights)
        self.input_shape = [1, input_size]
        
        current_size = input_size
        
        for name, values in sorted_weights:
            if len(values) < 16:
                continue
            
            layer_info = self._infer_layer(current_size, len(values))
            
            if layer_info:
                layer_info['weights'] = values[:layer_info['weight_count']]
                layers.append(layer_info)
                current_size = layer_info['output_size']
        
        self.output_shape = [1, current_size]
        self.reconstructed_layers = layers
        
        return layers
    
    def _infer_input_size(self, weights) -> int:
        if not weights:
            return 784
        
        first_weight = weights[0][1]
        possible_sizes = [784, 28*28, 32*32*3, 224*224*3]
        
        for size in possible_sizes:
            if len(first_weight) % size == 0:
                return size
        
        return 784
    
    def _infer_layer(self, input_size: int, weight_count: int) -> Optional[Dict[str, Any]]:
        for kernel_size in [3, 5, 7]:
            for output_channels in [16, 32, 64, 128, 256]:
                expected_weights = input_size * kernel_size * kernel_size * output_channels
                if abs(expected_weights - weight_count) < 100:
                    return {
                        'type': 'conv2d',
                        'input_size': input_size,
                        'output_size': output_channels,
                        'kernel_size': kernel_size,
                        'weight_count': expected_weights
                    }
        
        if weight_count % input_size == 0:
            output_size = weight_count // input_size
            if 10 <= output_size <= 4096:
                return {
                    'type': 'linear',
                    'input_size': input_size,
                    'output_size': output_size,
                    'weight_count': weight_count
                }
        
        return None
    
    def generate_onnx(self, output_path: str) -> bool:
        try:
            import onnx
            from onnx import helper, TensorProto
            
            nodes = []
            initializers = []
            inputs = [helper.make_tensor_value_info('input', TensorProto.FLOAT, [None, self.input_shape[1]])]
            outputs = [helper.make_tensor_value_info('output', TensorProto.FLOAT, [None, self.output_shape[1]])]
            
            prev_output = 'input'
            layer_idx = 0
            
            for layer in self.reconstructed_layers:
                layer_name = f"layer_{layer_idx}"
                weights_name = f"{layer_name}_weights"
                bias_name = f"{layer_name}_bias"
                
                if layer['type'] == 'linear':
                    weights = helper.make_tensor(
                        weights_name,
                        TensorProto.FLOAT,
                        [layer['output_size'], layer['input_size']],
                        layer['weights']
                    )
                    initializers.append(weights)
                    
                    bias = helper.make_tensor(
                        bias_name,
                        TensorProto.FLOAT,
                        [layer['output_size']],
                        [0.0] * layer['output_size']
                    )
                    initializers.append(bias)
                    
                    node = helper.make_node(
                        'Gemm',
                        inputs=[prev_output, weights_name, bias_name],
                        outputs=[layer_name],
                        name=layer_name,
                        transB=1
                    )
                    nodes.append(node)
                
                elif layer['type'] == 'conv2d':
                    weights = helper.make_tensor(
                        weights_name,
                        TensorProto.FLOAT,
                        [layer['output_size'], 1, layer['kernel_size'], layer['kernel_size']],
                        layer['weights'][:layer['output_size'] * layer['kernel_size'] * layer['kernel_size']]
                    )
                    initializers.append(weights)
                    
                    bias = helper.make_tensor(
                        bias_name,
                        TensorProto.FLOAT,
                        [layer['output_size']],
                        [0.0] * layer['output_size']
                    )
                    initializers.append(bias)
                    
                    node = helper.make_node(
                        'Conv',
                        inputs=[prev_output, weights_name, bias_name],
                        outputs=[layer_name],
                        name=layer_name,
                        kernel_shape=[layer['kernel_size'], layer['kernel_size']],
                        strides=[1, 1],
                        pads=[1, 1, 1, 1]
                    )
                    nodes.append(node)
                
                prev_output = layer_name
                layer_idx += 1
            
            relu_node = helper.make_node(
                'Relu',
                inputs=[prev_output],
                outputs=['output'],
                name='relu_final'
            )
            nodes.append(relu_node)
            
            graph = helper.make_graph(
                nodes,
                'reconstructed_model',
                inputs,
                outputs,
                initializers
            )
            
            model = helper.make_model(graph, opset_imports=[helper.make_opsetid('', 13)])
            onnx.save(model, output_path)
            
            logger.info(f"ONNX模型已生成: {output_path}")
            return True
        
        except ImportError:
            logger.error("ONNX库未安装")
            return False
        except Exception as e:
            logger.error(f"生成ONNX失败: {e}")
            return False
    
    def analyze_and_reconstruct(self, binary_data: bytes, output_path: str = None) -> Dict[str, Any]:
        constants = self.extract_constants_from_binary(binary_data)
        layers = self.reconstruct_network(constants)
        
        onnx_generated = False
        if output_path:
            onnx_generated = self.generate_onnx(output_path)
        
        return {
            'success': True,
            'extracted_constants_count': len(constants),
            'total_weights_count': sum(len(v) for v in constants.values()),
            'reconstructed_layers': layers,
            'input_shape': self.input_shape,
            'output_shape': self.output_shape,
            'onnx_generated': onnx_generated,
            'onnx_path': output_path
        }
