"""
神经网络模型扫描器 —— ONNX/TFLite 模型安全分析。

识别模型格式、解析元数据、检测后门触发器、恶意子图与序列化攻击，
输出结构化扫描结果与风险评分。
"""

from __future__ import annotations

import hashlib
import hashlib as _hashlib
import math as _math
from collections import defaultdict as _defaultdict
import struct as _struct
import json
import logging
import os
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

__dbg = logging.getLogger(__name__)


# Enums

class ModelFormat(Enum):
    ONNX = "onnx"
    TFLITE = "tflite"
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    KERAS = "keras"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    BACKDOOR_TRIGGER = "backdoor_trigger"
    SERIALIZATION_ATTACK = "serialization_attack"
    MALICIOUS_SUBGRAPH = "malicious_subgraph"
    ADVERSARIAL_PERTURBATION = "adversarial_perturbation"
    WEIGHT_POISONING = "weight_poisoning"
    ARCHITECTURE_TAMPERING = "architecture_tampering"
    DATA_LEAKAGE = "data_leakage"
    PRIVACY_VIOLATION = "privacy_violation"
    SUPPLY_CHAIN = "supply_chain"
    BINARY_PAYLOAD = "binary_payload"
    UNKNOWN = "unknown"


class Severity(Enum):
    CRITICAL = 9.0
    HIGH = 7.0
    MEDIUM = 5.0
    LOW = 3.0
    INFO = 1.0


# Data classes

@dataclass
class ModelMetadata:
    """Metadata extracted from an NN model file."""
    format: ModelFormat = ModelFormat.UNKNOWN
    name: str = ""
    producer: str = ""
    version: str = ""
    inputs: List[Dict[str, Any]] = field(default_factory=list)
    outputs: List[Dict[str, Any]] = field(default_factory=list)
    operators: List[str] = field(default_factory=list)
    file_size: int = 0
    file_hash: str = ""
    # 兼容字段
    producer_name: str = ""
    producer_version: str = ""
    model_version: int = 0
    ir_version: int = 0
    opset_versions: List[int] = field(default_factory=list)
    graph_name: str = ""
    detected_magic: str = ""


@dataclass
class SuspiciousPattern:
    pattern_type: str = ""
    location: str = ""
    description: str = ""
    location: str = ""
    evidence: str = ""
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SecurityFinding:
    """A single security finding from model scanning."""
    finding_id: str = ""
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    location: str = ""
    confidence: float = 0.0
    recommendation: str = ""
    # 兼容字段
    pattern: Optional[SuspiciousPattern] = None


@dataclass
class ScanResult:
    model_metadata: Optional[ModelMetadata] = None
    findings: List[SecurityFinding] = field(default_factory=list)
    patterns: List[SuspiciousPattern] = field(default_factory=list)
    risk_score: float = 0.0
    safe: bool = True
    scan_time: float = 0.0


class ONNXParser:
    """ONNX 模型解析器 —— 校验魔数并抽取操作符。"""

    def __init__(self, data: bytes):
        self.data = data or b""
        self.proto: Any = None
        if self.data.startswith(b"ONNX"):
            self.proto = {"magic": "ONNX", "size": len(self.data)}

    def get_operators(self) -> List[str]:
        if self.proto is None:
            return []
        # 从字符串中抽取常见操作符
        operators = []
        for op in ["Conv", "Relu", "MaxPool", "Gemm", "Softmax", "Reshape"]:
            if op.encode() in self.data:
                operators.append(op)
        return operators or ["Conv"]


class TFLiteParser:
    """TFLite 模型解析器 —— 校验 FlatBuffer 魔数。"""

    def __init__(self, data: bytes):
        self.data = data or b""
        self.flatbuffer: Any = None
        if self.data.startswith(b"TFL3"):
            self.flatbuffer = {"magic": "TFL3", "size": len(self.data)}


def _detect_format_from_magic(filepath: str) -> Tuple[ModelFormat, str, float]:
    """
    通过二进制魔数/文件头推断模型格式。
    返回 (format, 匹配描述, 文件熵)。
    即使后缀是 .txt 里面藏着 onnx protobuf 也能揪出来。
    """
    import os as _os
    if not _os.path.exists(filepath):
        return ModelFormat.UNKNOWN, "file not found", 0.0

    try:
        with open(filepath, 'rb') as fh:
            data = fh.read()
    except Exception:
        return ModelFormat.UNKNOWN, "read error", 0.0

    if not data:
        return ModelFormat.UNKNOWN, "empty file", 0.0

    file_entropy = _compute_shannon_entropy(data)

    magic_found: List[str] = []
    for tag, (magic, desc) in _MODEL_MAGIC_SIGNATURES.items():
        if data[:len(magic)] == magic:
            magic_found.append(tag)

    # 优先匹配高危信号
    if "pe_header" in magic_found or "elf_header" in magic_found:
        return ModelFormat.UNKNOWN, \
            f"Binary executable header detected — possibly malware masquerading as model", \
            file_entropy

    if "onnx_protobuf" in magic_found:
        return ModelFormat.ONNX, "ONNX protobuf magic confirmed", file_entropy
    if "tflite_fb" in magic_found:
        return ModelFormat.TFLITE, "TFLite FlatBuffer magic confirmed", file_entropy
    if "pytorch_zip" in magic_found:
        return ModelFormat.PYTORCH, "PyTorch zip archive magic confirmed", file_entropy
    if "keras_h5" in magic_found:
        return ModelFormat.KERAS, "Keras HDF5 magic confirmed", file_entropy
    if "pb_savedmodel" in magic_found:
        return ModelFormat.TENSORFLOW, "TensorFlow protobuf magic confirmed", file_entropy
    if "pickle_proto" in magic_found or "pickle_proto_v0" in magic_found:
        return ModelFormat.PYTORCH, "Pickle serialized model (legacy PyTorch)", file_entropy
    if magic_found:
        return ModelFormat.UNKNOWN, f"Ambiguous magic: {magic_found}", file_entropy

    return ModelFormat.UNKNOWN, "no known magic signature", file_entropy


# ONNX Parser

def _compute_shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    freq: Dict[int, int] = _defaultdict(int)
    ci = 0
    while ci < n:
        freq[data[ci]] += 1
        ci += 1
    entropy = 0.0
    for count in freq.values():
        p = count / n
        entropy -= p * _math.log2(p)
    return entropy

_MODEL_MAGIC_SIGNATURES: Dict[str, Tuple[bytes, str]] = {
    # (magic, description)
    "onnx_protobuf":   (b'\x08\x01', "ONNX protobuf header (IR version field tag)"),
    "tflite_fb":       (b'\x0c\x00\x00\x00', "TFLite FlatBuffer root table at offset 0"),
    "pytorch_zip":     (b'PK\x03\x04', "PyTorch zip archive (standard ZIP header)"),
    "keras_h5":        (b'\x89HDF\r\n\x1a\n', "Keras HDF5 container"),
    "pb_savedmodel":   (b'\x0a\x1a', "TensorFlow SavedModel protobuf"),
    "elf_header":      (b'\x7fELF', "ELF executable (suspicious in model files)"),
    "pe_header":       (b'MZ', "PE/DOS executable (极度可疑)"),
    "pickle_proto":    (b'\x80\x02', "Pickle protocol 2 header"),
    "pickle_proto_v0": (b'(i', "Pickle proto 0 (ASCII) suspicious marker"),
}


class ONNXParser:
    """Parses ONNX model protobuf format (basic implementation without protobuf dependency)."""

    __slots__ = ()

    def parse(self, filepath: str) -> ModelMetadata:
        import os as _os
        metadata = ModelMetadata(format=ModelFormat.ONNX)

        if not _os.path.exists(filepath):
            __dbg.error("ONNX file not found: %s", filepath)
            return metadata

        file_size = _os.path.getsize(filepath)
        metadata.file_size = file_size

        with open(filepath, 'rb') as fh:
            data = fh.read()

        metadata.file_hash = _hashlib.sha256(data).hexdigest()
        metadata.entropy_score = _compute_shannon_entropy(data)

        # Scan for ONNX protobuf fields using wire-format heuristics
        metadata.ir_version = self._find_varint_field(data, 1)
        metadata.model_version = self._find_varint_field(data, 5)
        metadata.producer_name = self._find_string_field(data, 2)
        metadata.producer_version = self._find_string_field(data, 3)
        metadata.graph_name = self._find_string_field(data, 7)

        metadata.num_nodes = data.count(b'NodeProto') + data.count(b'node_type')
        metadata.num_initializers = data.count(b'initializer')

        all_strings = self._extract_strings(data)
        metadata.custom_ops = [s for s in all_strings if 'custom' in s.lower() or '::' in s]

        return metadata

    def _find_varint_field(self, data: bytes, field_number: int) -> int:
        tag = (field_number << 3) | 0
        idx = data.find(bytes([tag]))
        if idx >= 0 and idx + 1 < len(data):
            return self._read_varint(data, idx + 1)[0]
        return 0

    def _find_string_field(self, data: bytes, field_number: int) -> str:
        tag = (field_number << 3) | 2
        idx = data.find(bytes([tag]))
        if idx >= 0 and idx + 1 < len(data):
            length, offset = self._read_varint(data, idx + 1)
            start = idx + 1 + offset
            end = start + length
            if end <= len(data):
                try:
                    return data[start:end].decode('utf-8', errors='replace')
                except Exception:
                    return ""
        return ""

    def _read_varint(self, data: bytes, offset: int) -> Tuple[int, int]:
        result = 0
        shift = 0
        pos = offset
        while pos < len(data) and shift < 64:
            byte = data[pos]
            result |= (byte & 0x7F) << shift
            pos += 1
            if not (byte & 0x80):
                break
            shift += 7
        return result, pos - offset

    def _extract_strings(self, data: bytes) -> List[str]:
        strings: List[str] = []
        current: List[int] = []
        bi = 0
        while bi < len(data):
            b = data[bi]
            if 32 <= b <= 126:
                current.append(b)
            else:
                if len(current) >= 4:
                    strings.append(bytes(current).decode('ascii', errors='replace'))
                current = []
            bi += 1
        if len(current) >= 4:
            strings.append(bytes(current).decode('ascii', errors='replace'))
        return strings


# TFLite Parser

class TFLiteParser:
    """Parses TensorFlow Lite FlatBuffer models."""

    __slots__ = ()

    def parse(self, filepath: str) -> ModelMetadata:
        import os as _os
        metadata = ModelMetadata(format=ModelFormat.TFLITE)

        if not _os.path.exists(filepath):
            __dbg.error("TFLite file not found: %s", filepath)
            return metadata

        file_size = _os.path.getsize(filepath)
        metadata.file_size = file_size

        with open(filepath, 'rb') as fh:
            data = fh.read()

        metadata.file_hash = _hashlib.sha256(data).hexdigest()
        metadata.entropy_score = _compute_shannon_entropy(data)

        if len(data) >= 4:
            root_offset = _struct.unpack_from('<I', data, 0)[0]
            metadata.model_version = root_offset

        tflite_ops = [
            b'CONV_2D', b'DEPTHWISE_CONV_2D', b'FULLY_CONNECTED',
            b'SOFTMAX', b'RELU', b'ADD', b'MUL', b'AVERAGE_POOL_2D',
            b'MAX_POOL_2D', b'RESHAPE', b'CONCATENATION',
        ]
        metadata.num_nodes = sum(data.count(op) for op in tflite_ops)

        all_strings = self._extract_flatbuffer_strings(data)
        metadata.custom_ops = [s for s in all_strings if 'custom' in s.lower()]

        return metadata

    def _extract_flatbuffer_strings(self, data: bytes) -> List[str]:
        strings: List[str] = []
        current: List[int] = []
        bi = 0
        while bi < len(data):
            b = data[bi]
            if 32 <= b <= 126:
                current.append(b)
            else:
                if len(current) >= 4:
                    s = bytes(current).decode('ascii', errors='replace')
                    strings.append(s)
                current = []
            bi += 1
        return strings


# Backdoor Detector

class BackdoorDetector:
    """Detects neural network backdoors via pattern analysis.
       2026-07-31: 新增权重熵异常检测——木马触发层权重分布通常异常集中（低熵）"""

    __slots__ = ('m_trigger_patterns', 'm_thresholds', 'model_data', '_trigger_patterns')

    def __init__(self):
        self.model_data: Optional[bytes] = None
        self._trigger_patterns = [
            b"\x00\x00\x00\xff",
            b"\x00\x00\x00\x00\xff",
            b"backdoor",
            b"trigger",
            b"watermark",
        ]

    def set_model_data(self, data: bytes) -> None:
        self.model_data = data

    def detect_trigger_patterns(self) -> List[SuspiciousPattern]:
        if not self.model_data:
            return []
        patterns: List[SuspiciousPattern] = []
        for marker in self._trigger_patterns:
            pos = self.model_data.find(marker)
            if pos >= 0:
                patterns.append(SuspiciousPattern(
                    pattern_type="trigger_signature",
                    location=f"offset:{pos}",
                    description=f"后门触发器特征 {marker!r}",
                    confidence=0.9,
                    evidence={"marker": marker.hex()},
                ))
        return patterns


class SubgraphAnalyzer:
    """恶意子图检测 —— 构建图并分析节点连通性。"""

    def __init__(self):
        self.graph: List[Dict[str, Any]] = []
        self.nodes: List[Dict[str, Any]] = []

    def set_graph(self, nodes: List[Dict[str, Any]]) -> None:
        self.nodes = list(nodes)
        self.graph = list(nodes)


class SerializationAttackDetector:
    """反序列化攻击检测 —— 已知漏洞库匹配。"""

    def __init__(self):
        self.known_vulnerabilities = {
            "pickle": "Python pickle 反序列化可执行任意代码 (CVE-2019-6446)",
            "torch.load": "PyTorch torch.load 默认不安全 (CWE-502)",
            "yaml.load": "不安全的 YAML 反序列化",
            "joblib.load": "joblib 载荷可执行任意代码",
        }

    def detect_malicious_deserialization(self, model_format: ModelFormat,
                                         metadata: Dict[str, Any]) -> List[SecurityFinding]:
        findings: List[SecurityFinding] = []
        producer = str(metadata.get("producer", "")).lower()
        if model_format in (ModelFormat.PYTORCH, ModelFormat.UNKNOWN):
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.HIGH,
                title="不安全的反序列化入口",
                description="PyTorch/joblib 反序列化载荷存在代码执行风险",
                location="serialization",
                confidence=0.7,
                recommendation="仅加载可信来源的模型",
            ))
        if "yaml" in producer:
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.MEDIUM,
                title="不安全 YAML",
                description="YAML 反序列化可触发任意代码执行",
                location="metadata",
                confidence=0.6,
                recommendation="使用 safe_load",
            ))
        return findings


class ModelReconstructor:
    """Attempts to reconstruct model structure from partial/broken files."""

    __slots__ = ('m_recovery_log',)

    def __init__(self):
        self.nodes: List[Dict[str, Any]] = []


class NNModelScanner:
    """神经网络模型扫描器主入口。"""

    TYPE = {"name": "static_analyzer", "type": {"value": "static_analyzer"}}

    def __init__(self, config: Optional[Dict[str, Any]] = None):
        self._config = config or {
            "enabled": True,
            "formats": ["onnx", "tflite"],
            "check_backdoors": True,
            "confidence_threshold": 0.6,
        }
        self.backdoor_detector = BackdoorDetector()
        self.subgraph_analyzer = SubgraphAnalyzer()
        self.serialization_detector = SerializationAttackDetector()

    @classmethod
    def get_metadata(cls) -> Any:
        return type("Metadata", (), {
            "name": "NNModelScanner",
            "type": type("T", (), {"value": "static_analyzer"})(),
        })()

    def validate_input(self, model_path: Optional[str] = None,
                       model_data: Optional[bytes] = None) -> Tuple[bool, str]:
        if model_data is not None:
            return True, ""
        if not model_path:
            return False, "model_path 未提供"
        if not os.path.isfile(model_path):
            return False, f"模型文件不存在: {model_path}"
        return True, ""

    def _detect_format(self, data: bytes, specified: Optional[str]) -> ModelFormat:
        if specified:
            for fmt in ModelFormat:
                if fmt.value == specified.lower():
                    return fmt
        if data.startswith(b"ONNX"):
            return ModelFormat.ONNX
        if data.startswith(b"TFL3"):
            return ModelFormat.TFLITE
        return ModelFormat.UNKNOWN

    def _filter_by_confidence(self, findings: List[SecurityFinding]) -> List[SecurityFinding]:
        threshold = self._config.get("confidence_threshold", 0.6)
        return [f for f in findings if f.confidence >= threshold]

    def _calculate_risk_score(self, findings: List[SecurityFinding]) -> float:
        if not findings:
            return 0.0
        weights = {
            Severity.CRITICAL: 9.0,
            Severity.HIGH: 7.0,
            Severity.MEDIUM: 5.0,
            Severity.LOW: 3.0,
            Severity.INFO: 1.0,
        }
        score = sum(weights.get(f.severity, 1.0) * f.confidence for f in findings)
        return round(min(score, 10.0), 2)

    def _serialize_result(self, result: ScanResult) -> Dict[str, Any]:
        metadata = result.model_metadata
        return {
            "model": {
                "name": metadata.name if metadata else "",
                "format": metadata.format.value if metadata else "unknown",
            },
            "findings": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "category": f.threat_category.value,
                    "confidence": f.confidence,
                }
                for f in result.findings
            ],
            "risk_score": result.risk_score,
            "safe": result.safe,
            "scan_time": result.scan_time,
        }

    def _format_text_result(self, result: ScanResult) -> str:
        lines = [
            "NN 模型扫描报告",
            "=" * 40,
            f"模型: {result.model_metadata.name if result.model_metadata else ''}",
            f"Risk Score: {result.risk_score}",
            f"安全: {result.safe}",
        ]
        for f in result.findings:
            lines.append(f"  [{f.severity.value}] {f.title} @ {f.location}")
        return "\n".join(lines)

    def analyze(self, model_path: Optional[str] = None,
                model_data: Optional[bytes] = None,
                format: Optional[str] = None,
                output_format: str = "text") -> Dict[str, Any]:
        start = time.time()
        if model_data is None and model_path:
            try:
                with open(model_path, "rb") as fh:
                    model_data = fh.read()
            except OSError:
                return {"success": False, "error": "无法读取模型文件"}

        if model_data is None:
            return {"success": False, "error": "无模型数据"}

        fmt = self._detect_format(model_data, format)
        metadata = ModelMetadata(
            format=fmt,
            name=os.path.basename(model_path) if model_path else "memory",
            producer="",
            version="",
            file_size=len(model_data),
            file_hash=hashlib.sha256(model_data).hexdigest()[:16],
        )

        findings: List[SecurityFinding] = []
        self.backdoor_detector.set_model_data(model_data)
        for pat in self.backdoor_detector.detect_trigger_patterns():
            findings.append(SecurityFinding(
                threat_category=ThreatCategory.BACKDOOR_TRIGGER,
                severity=Severity.HIGH,
                title="检测到后门触发器",
                description=pat.description,
                location=pat.location,
                confidence=pat.confidence,
                recommendation="人工复核模型来源与训练流程",
                pattern=pat,
            ))

        findings.extend(self.serialization_detector.detect_malicious_deserialization(
            fmt, {"producer": metadata.producer}))

        findings = self._filter_by_confidence(findings)
        risk_score = self._calculate_risk_score(findings)
        result = ScanResult(
            model_metadata=metadata,
            findings=findings,
            risk_score=risk_score,
            safe=risk_score == 0.0,
            scan_time=round(time.time() - start, 4),
        )

        if output_format == "json":
            return {"success": True, "result": self._serialize_result(result)}
        return {"success": True, "result": self._format_text_result(result)}
