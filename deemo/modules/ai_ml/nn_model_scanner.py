#!/usr/bin/env python3
# Neural Network model security scanner — ONNX/TFLite parsing, backdoor detection,
# subgraph anomaly analysis, serialization attack detection, and model reconstruction.
# 2026-07-30: added TFLiteParser, SubgraphAnalyzer, SerializationAttackDetector.
# 2026-07-31: 新增魔数检测不用信后缀、权重熵异常检测防木马注入、NOP sled/PE头检测防二进制投毒

import logging as _logging
import json as _json
import hashlib as _hashlib
import struct as _struct
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union
from collections import defaultdict as _defaultdict
import math as _math
import zlib as _zlib

__dbg = _logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ModelFormat(Enum):
    ONNX = "onnx"
    TFLITE = "tflite"
    TENSORFLOW = "tensorflow"
    PYTORCH = "pytorch"
    KERAS = "keras"
    UNKNOWN = "unknown"


class ThreatCategory(Enum):
    BACKDOOR = "backdoor"
    ADVERSARIAL_PERTURBATION = "adversarial_perturbation"
    WEIGHT_POISONING = "weight_poisoning"
    ARCHITECTURE_TAMPERING = "architecture_tampering"
    SERIALIZATION_ATTACK = "serialization_attack"
    DATA_LEAKAGE = "data_leakage"
    PRIVACY_VIOLATION = "privacy_violation"
    SUPPLY_CHAIN = "supply_chain"
    BINARY_PAYLOAD = "binary_payload"
    UNKNOWN = "unknown"


class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class ModelMetadata:
    """Metadata extracted from an NN model file."""
    format: ModelFormat = ModelFormat.UNKNOWN
    file_size: int = 0
    file_hash: str = ""
    producer_name: str = ""
    producer_version: str = ""
    model_version: int = 0
    ir_version: int = 0
    opset_versions: List[int] = field(default_factory=list)
    graph_name: str = ""
    num_nodes: int = 0
    num_inputs: int = 0
    num_outputs: int = 0
    num_initializers: int = 0
    total_params: int = 0
    input_shapes: List[List[int]] = field(default_factory=list)
    output_shapes: List[List[int]] = field(default_factory=list)
    custom_ops: List[str] = field(default_factory=list)
    training_info: Dict[str, Any] = field(default_factory=dict)
    detected_magic: str = ""           # 魔数/文件头识别结果
    entropy_score: float = 0.0         # 文件整体熵值（高熵→加密/混淆嫌疑）


@dataclass
class SuspiciousPattern:
    """A suspicious pattern found in a model."""
    pattern_id: str = ""
    category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity = Severity.INFO
    description: str = ""
    location: str = ""
    evidence: str = ""
    confidence: float = 0.0
    nodes_involved: List[str] = field(default_factory=list)
    mitigation: str = ""


@dataclass
class SecurityFinding:
    """A single security finding from model scanning."""
    finding_id: str = ""
    threat_category: ThreatCategory = ThreatCategory.UNKNOWN
    severity: Severity = Severity.INFO
    title: str = ""
    description: str = ""
    patterns: List[SuspiciousPattern] = field(default_factory=list)
    recommendation: str = ""
    cwe_reference: str = ""


@dataclass
class ScanResult:
    """Complete scan result for an NN model."""
    model_path: str = ""
    metadata: ModelMetadata = field(default_factory=ModelMetadata)
    findings: List[SecurityFinding] = field(default_factory=list)
    patterns: List[SuspiciousPattern] = field(default_factory=list)
    risk_score: float = 0.0
    scan_duration_ms: float = 0.0
    is_safe: bool = True
    summary: str = ""


# ---------------------------------------------------------------------------
# 魔数/文件头检测 —— 不信文件后缀，信二进制指纹
# ---------------------------------------------------------------------------

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


def _compute_shannon_entropy(data: bytes) -> float:
    """计算字节级香农熵。高熵 → 可能是加密/压缩/混淆载荷。"""
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


# ---------------------------------------------------------------------------
# ONNX Parser
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# TFLite Parser
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Backdoor Detector
# ---------------------------------------------------------------------------

class BackdoorDetector:
    """Detects neural network backdoors via pattern analysis.
       2026-07-31: 新增权重熵异常检测——木马触发层权重分布通常异常集中（低熵）"""

    __slots__ = ('m_trigger_patterns', 'm_thresholds')

    def __init__(self):
        self.m_trigger_patterns = [
            "trigger", "backdoor", "trojan", "watermark",
            "badnet", "poison", "hidden", "secret",
            "debug", "test_mode", "admin", "override",
        ]
        self.m_thresholds = {
            "weight_anomaly_std": 5.0,
            "activation_sparsity": 0.99,
            "naming_mismatch_confidence": 0.6,
            "entropy_low_threshold": 1.5,        # 低于此值→权重分布高度集中，后门嫌疑
            "entropy_high_threshold": 7.5,       # 高于此值→权重接近随机，中毒嫌疑
            "layer_entropy_diff_threshold": 3.0,  # 相邻层熵差过大→异常跳跃
        }

    def detect(self, metadata: ModelMetadata,
               layer_info: Optional[List[Dict[str, Any]]] = None) -> List[SuspiciousPattern]:
        patterns: List[SuspiciousPattern] = []

        # Check custom ops for trigger-like names
        ci = 0
        while ci < len(metadata.custom_ops):
            op = metadata.custom_ops[ci].lower()
            ti = 0
            while ti < len(self.m_trigger_patterns):
                if self.m_trigger_patterns[ti] in op:
                    patterns.append(SuspiciousPattern(
                        pattern_id=f"BD-OP-{ci}",
                        category=ThreatCategory.BACKDOOR,
                        severity=Severity.HIGH,
                        description=f"Custom op name contains trigger keyword: '{op}'",
                        location=f"custom_op[{ci}]",
                        evidence=op,
                        confidence=0.8,
                        mitigation="Review and remove suspicious custom operations",
                    ))
                    break
                ti += 1
            ci += 1

        # Check layer info for anomalies
        if layer_info:
            # 权重熵分析：搜集每层权重熵，跨层对比找异常
            layer_entropies: List[Tuple[int, float, str]] = []  # (layer_index, entropy, layer_name)

            li = 0
            while li < len(layer_info):
                layer = layer_info[li]
                layer_name = layer.get("name", "").lower()

                ti = 0
                while ti < len(self.m_trigger_patterns):
                    if self.m_trigger_patterns[ti] in layer_name:
                        patterns.append(SuspiciousPattern(
                            pattern_id=f"BD-LAYER-{li}",
                            category=ThreatCategory.BACKDOOR,
                            severity=Severity.MEDIUM,
                            description=f"Layer name contains trigger keyword: '{layer_name}'",
                            location=f"layer[{li}]",
                            evidence=layer_name,
                            confidence=0.7,
                            mitigation="Inspect layer weights and activation patterns",
                        ))
                        break
                    ti += 1

                # Check for anomalous weight statistics
                weights = layer.get("weights")
                if weights and isinstance(weights, list) and len(weights) > 0:
                    w_flat: List[float] = []
                    self._flatten_weights(weights, w_flat)
                    if w_flat:
                        mean_w = sum(w_flat) / len(w_flat)
                        var_w = sum((w - mean_w) ** 2 for w in w_flat) / len(w_flat)
                        std_w = var_w ** 0.5

                        if std_w > self.m_thresholds["weight_anomaly_std"]:
                            patterns.append(SuspiciousPattern(
                                pattern_id=f"BD-WEIGHT-{li}",
                                category=ThreatCategory.WEIGHT_POISONING,
                                severity=Severity.MEDIUM,
                                description=f"Anomalous weight std deviation: {std_w:.2f}",
                                location=f"layer[{li}].weights",
                                evidence=f"std={std_w:.2f}, mean={mean_w:.2f}",
                                confidence=min(std_w / 10.0, 0.9),
                                mitigation="Verify weight distribution; check for poisoning",
                            ))

                        # 新增：计算权重熵并记录
                        w_entropy = self._compute_weight_entropy(w_flat)
                        layer_entropies.append((li, w_entropy, layer_name))

                li += 1

            # 跨层熵分析：找出熵值异常低或异常高的层
            if layer_entropies:
                entropies_only = [e[1] for e in layer_entropies]
                mean_ent = sum(entropies_only) / len(entropies_only)
                var_ent = sum((e - mean_ent) ** 2 for e in entropies_only) / len(entropies_only)
                std_ent = var_ent ** 0.5

                for li_, ent_, lname_ in layer_entropies:
                    # 低熵 → 权重集中在少数值，可能是木马触发层
                    if ent_ < self.m_thresholds["entropy_low_threshold"]:
                        patterns.append(SuspiciousPattern(
                            pattern_id=f"BD-ENTROPY-LOW-{li_}",
                            category=ThreatCategory.BACKDOOR,
                            severity=Severity.HIGH,
                            description=f"Abnormally low weight entropy ({ent_:.2f}) in layer '{lname_}': "
                                        f"concentrated weights suggest trigger/backdoor injection",
                            location=f"layer[{li_}].weights",
                            evidence=f"entropy={ent_:.2f}, mean={mean_ent:.2f}, std={std_ent:.2f}",
                            confidence=min(0.85, 1.0 - ent_ / 3.0),
                            mitigation="Inspect weight histogram; compare to benign reference model",
                        ))
                    # 高熵 → 权重接近均匀分布，可能是随机噪声投毒
                    if ent_ > self.m_thresholds["entropy_high_threshold"]:
                        patterns.append(SuspiciousPattern(
                            pattern_id=f"BD-ENTROPY-HIGH-{li_}",
                            category=ThreatCategory.WEIGHT_POISONING,
                            severity=Severity.MEDIUM,
                            description=f"Abnormally high weight entropy ({ent_:.2f}) in layer '{lname_}': "
                                        f"near-uniform weights suggest random noise poisoning",
                            location=f"layer[{li_}].weights",
                            evidence=f"entropy={ent_:.2f}, mean={mean_ent:.2f}",
                            confidence=min(0.7, ent_ / 10.0),
                            mitigation="Audit training data for this layer; consider retraining",
                        ))

        return patterns

    def _compute_weight_entropy(self, w_flat: List[float]) -> float:
        """
        对连续权重值做离散化后计算香农熵。
        离散化桶数 = min(256, sqrt(n))，兼顾精度与性能。
        """
        if not w_flat:
            return 0.0
        n = len(w_flat)
        num_bins = min(256, max(8, int(n ** 0.5)))
        # 桶映射：归一化到 [0, 1] 再乘 num_bins
        w_min = min(w_flat)
        w_max = max(w_flat)
        if w_max == w_min:
            return 0.0  # 所有值相同 → 熵为 0
        range_w = w_max - w_min
        histogram: Dict[int, int] = _defaultdict(int)
        ci = 0
        while ci < n:
            bin_idx = int((w_flat[ci] - w_min) / range_w * (num_bins - 1))
            histogram[bin_idx] += 1
            ci += 1
        entropy = 0.0
        for count in histogram.values():
            p = count / n
            entropy -= p * _math.log2(p)
        return entropy

    def _flatten_weights(self, w, result: List[float]):
        if isinstance(w, (int, float)):
            result.append(float(w))
        elif isinstance(w, list):
            for item in w:
                self._flatten_weights(item, result)


# ---------------------------------------------------------------------------
# Subgraph Analyzer
# ---------------------------------------------------------------------------

class SubgraphAnalyzer:
    """Analyzes model subgraphs for anomalies and structural integrity."""

    __slots__ = ('m_known_safe_patterns',)

    def __init__(self):
        self.m_known_safe_patterns: Dict[str, List[str]] = {
            "resnet": ["conv", "bn", "relu", "pool", "fc"],
            "transformer": ["attention", "layernorm", "ffn", "embedding"],
            "yolo": ["conv", "bn", "leaky", "upsample", "detect"],
        }

    def analyze(self, nodes: List[Dict[str, Any]]) -> List[SuspiciousPattern]:
        patterns: List[SuspiciousPattern] = []

        if not nodes:
            return patterns

        # Check for isolated nodes
        ni = 0
        while ni < len(nodes):
            node = nodes[ni]
            inputs = node.get("inputs", [])
            outputs = node.get("outputs", [])

            if not inputs and not outputs and ni > 1:
                patterns.append(SuspiciousPattern(
                    pattern_id=f"SA-ISOLATED-{ni}",
                    category=ThreatCategory.ARCHITECTURE_TAMPERING,
                    severity=Severity.LOW,
                    description=f"Isolated node with no connections: {node.get('name', f'node_{ni}')}",
                    location=f"nodes[{ni}]",
                    confidence=0.5,
                    mitigation="Remove or reconnect isolated nodes",
                ))

            if len(inputs) > 100:
                patterns.append(SuspiciousPattern(
                    pattern_id=f"SA-MANY-INPUTS-{ni}",
                    category=ThreatCategory.DATA_LEAKAGE,
                    severity=Severity.MEDIUM,
                    description=f"Node with {len(inputs)} inputs: {node.get('name', f'node_{ni}')}",
                    location=f"nodes[{ni}]",
                    confidence=0.4,
                    mitigation="Review node purpose and input fan-in",
                ))

            ni += 1

        # Check for bypass paths
        bypass_patterns = self._detect_bypass_paths(nodes)
        patterns.extend(bypass_patterns)

        return patterns

    def _detect_bypass_paths(self, nodes: List[Dict[str, Any]]) -> List[SuspiciousPattern]:
        bypass_patterns: List[SuspiciousPattern] = []

        adj: Dict[int, List[int]] = _defaultdict(list)
        ni = 0
        while ni < len(nodes):
            outputs = nodes[ni].get("outputs", [])
            for out_name in outputs:
                nj = 0
                while nj < len(nodes):
                    if out_name in nodes[nj].get("inputs", []):
                        adj[ni].append(nj)
                    nj += 1
            ni += 1

        ni = 0
        while ni < len(nodes):
            for target in adj.get(ni, []):
                if target - ni > len(nodes) // 2:
                    node_name = nodes[ni].get("name", f"node_{ni}")
                    target_name = nodes[target].get("name", f"node_{target}")
                    if "skip" not in node_name.lower() and "residual" not in node_name.lower():
                        bypass_patterns.append(SuspiciousPattern(
                            pattern_id=f"SA-BYPASS-{ni}-{target}",
                            category=ThreatCategory.ARCHITECTURE_TAMPERING,
                            severity=Severity.LOW,
                            description=f"Long skip connection: {node_name} -> {target_name}",
                            location=f"nodes[{ni}] -> nodes[{target}]",
                            confidence=0.3,
                            mitigation="Verify skip connection is intentional",
                        ))
            ni += 1

        return bypass_patterns


# ---------------------------------------------------------------------------
# Serialization Attack Detector
# 2026-07-31: 新增 NOP sled 检测、PE/DLL 二进制载荷检测、Python marshal 字节码检测
# ---------------------------------------------------------------------------

class SerializationAttackDetector:
    """Detects serialization-level attacks in model files."""

    __slots__ = ('m_shellcode_patterns', 'm_nop_sled_patterns',
                 'm_binary_drop_patterns', 'm_marshal_patterns')

    def __init__(self):
        self.m_shellcode_patterns = [
            bytes([0x31, 0xc0, 0x50]),
            bytes([0x6a, 0x0b, 0x58]),
            bytes([0xcd, 0x80]),
            bytes([0x0f, 0x05]),
            b'/bin/sh',
            b'/bin/bash',
            b'cmd.exe',
        ]

        # NOP sled 特征: x86 (0x90) / ARM (0x00 0xf0 0x20 0xe3) / MIPS (0x00 0x00 0x00 0x00)
        self.m_nop_sled_patterns: List[Tuple[bytes, str]] = [
            (b'\x90' * 8,    "x86 NOP sled (>=8 consecutive 0x90)"),
            (b'\x00\xf0\x20\xe3' * 3, "ARM NOP sled pattern"),
        ]

        # 二进制投毒特征: PE/DLL 头、Mach-O 魔数
        self.m_binary_drop_patterns: List[Tuple[bytes, str, float]] = [
            (b'MZ',                "PE/DOS executable header (MZ)", 0.95),
            (b'This program cannot be run in DOS mode', "PE DOS stub string", 0.90),
            (b'\xcf\xfa\xed\xfe', "Mach-O 64-bit magic (suspicious in ML models)", 0.85),
            (b'\xce\xfa\xed\xfe', "Mach-O 32-bit magic", 0.85),
            (b'\xca\xfe\xba\xbe', "Mach-O universal binary magic", 0.85),
        ]

        # Python marshal 字节码特征 —— 可能藏在序列化模型里执行
        self.m_marshal_patterns: List[Tuple[bytes, str]] = [
            (b'__import__', "__import__ call (arbitrary module load)"),
            (b'eval(',       "eval() invocation in embedded code"),
            (b'exec(',       "exec() invocation in embedded code"),
            (b'os.system',   "os.system call (command execution)"),
            (b'subprocess',  "subprocess module reference"),
            (b'Popen',       "subprocess.Popen reference"),
        ]

    def scan(self, filepath: str) -> List[SuspiciousPattern]:
        import os as _os
        patterns: List[SuspiciousPattern] = []

        if not _os.path.exists(filepath):
            return patterns

        with open(filepath, 'rb') as fh:
            data = fh.read()

        # --- 原始 shellcode 检测 ---
        si = 0
        while si < len(self.m_shellcode_patterns):
            pattern = self.m_shellcode_patterns[si]
            positions: List[int] = []
            offset = 0
            while True:
                pos = data.find(pattern, offset)
                if pos == -1:
                    break
                positions.append(pos)
                offset = pos + 1

            if positions:
                patterns.append(SuspiciousPattern(
                    pattern_id=f"SERIAL-SC-{si}",
                    category=ThreatCategory.SERIALIZATION_ATTACK,
                    severity=Severity.CRITICAL,
                    description=f"Potential shellcode pattern found at {len(positions)} locations",
                    location=f"offset(s): {positions[:5]}",
                    evidence=pattern.hex(),
                    confidence=0.9 if len(positions) >= 2 else 0.5,
                    mitigation="Immediately quarantine the model file; investigate source",
                ))
            si += 1

        # --- NOP sled 检测: 连续 NOP 序列超过阈值说明缓冲区溢出攻击载荷 ---
        nop_pid = 0
        while nop_pid < len(self.m_nop_sled_patterns):
            nop_seq, nop_desc = self.m_nop_sled_patterns[nop_pid]
            nop_hits: List[int] = []
            scan_off = 0
            while scan_off < len(data) - len(nop_seq):
                scan_off = data.find(nop_seq, scan_off)
                if scan_off == -1:
                    break
                nop_hits.append(scan_off)
                scan_off += 1

            if nop_hits:
                # 进一步确认: NOP sled 后面紧跟 shellcode 的嫌疑更大
                follow_suspicious = False
                for nop_off in nop_hits[:3]:
                    after_nop = nop_off + len(nop_seq)
                    if after_nop + 4 < len(data):
                        chunk_after = data[after_nop:after_nop + 32]
                        if any(sc in chunk_after for sc in self.m_shellcode_patterns if len(sc) <= 8):
                            follow_suspicious = True
                            break

                conf = 0.85 if follow_suspicious else 0.55
                patterns.append(SuspiciousPattern(
                    pattern_id=f"SERIAL-NOP-{nop_pid}",
                    category=ThreatCategory.SERIALIZATION_ATTACK,
                    severity=Severity.CRITICAL if follow_suspicious else Severity.HIGH,
                    description=f"NOP sled detected: {nop_desc} ({len(nop_hits)} occurrences)"
                                + (" followed by shellcode-like bytes" if follow_suspicious else ""),
                    location=f"offset(s): {nop_hits[:5]}",
                    evidence=nop_seq[:8].hex(),
                    confidence=conf,
                    mitigation="Quarantine file; likely buffer overflow exploit payload embedded",
                ))
            nop_pid += 1

        # --- 二进制投毒检测: PE/DLL/Mach-O 头嵌入 ---
        bd_pid = 0
        while bd_pid < len(self.m_binary_drop_patterns):
            bd_pattern, bd_desc, bd_conf = self.m_binary_drop_patterns[bd_pid]
            bd_hits: List[int] = []
            bd_off = 0
            while bd_off < len(data):
                bd_off = data.find(bd_pattern, bd_off)
                if bd_off == -1:
                    break
                bd_hits.append(bd_off)
                bd_off += 1

            if bd_hits:
                patterns.append(SuspiciousPattern(
                    pattern_id=f"SERIAL-BIN-{bd_pid}",
                    category=ThreatCategory.BINARY_PAYLOAD,
                    severity=Severity.CRITICAL,
                    description=f"Binary payload header detected: {bd_desc} at {len(bd_hits)} location(s)",
                    location=f"offset(s): {bd_hits[:5]}",
                    evidence=bd_pattern.hex(),
                    confidence=bd_conf,
                    mitigation="Quarantine immediately; file may contain embedded malware binary",
                ))
            bd_pid += 1

        # --- Python marshal/字节码注入检测 ---
        mp_pid = 0
        while mp_pid < len(self.m_marshal_patterns):
            mp_pattern, mp_desc = self.m_marshal_patterns[mp_pid]
            mp_hits: List[int] = []
            mp_off = 0
            while mp_off < len(data):
                mp_off = data.find(mp_pattern, mp_off)
                if mp_off == -1:
                    break
                mp_hits.append(mp_off)
                mp_off += 1

            if mp_hits:
                patterns.append(SuspiciousPattern(
                    pattern_id=f"SERIAL-PY-{mp_pid}",
                    category=ThreatCategory.SERIALIZATION_ATTACK,
                    severity=Severity.CRITICAL,
                    description=f"Python code execution marker: {mp_desc} at {len(mp_hits)} location(s)",
                    location=f"offset(s): {mp_hits[:5]}",
                    evidence=mp_pattern.decode('ascii', errors='replace'),
                    confidence=0.92,
                    mitigation="Treat as malicious — arbitrary code execution in pickle/marshal payload",
                ))
            mp_pid += 1

        # --- 原始 pickle 检测 ---
        if b'__reduce__' in data or b'__builtin__' in data:
            patterns.append(SuspiciousPattern(
                pattern_id="SERIAL-PICKLE",
                category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.CRITICAL,
                description="Pickle injection markers detected (__reduce__ or __builtin__)",
                location="embedded data",
                confidence=0.95,
                mitigation="Never unpickle untrusted model files; use safe formats only",
            ))

        file_size = len(data)
        if file_size > 500 * 1024 * 1024:
            patterns.append(SuspiciousPattern(
                pattern_id="SERIAL-SIZE",
                category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.HIGH,
                description=f"Model file unusually large: {file_size / (1024*1024):.1f} MB",
                location="file",
                confidence=0.7,
                mitigation="Verify file integrity; check for zip bomb decompression bomb",
            ))

        # 文件熵过高 → 加密载荷或伪装数据
        file_entropy = _compute_shannon_entropy(data)
        if file_entropy > 7.8:
            patterns.append(SuspiciousPattern(
                pattern_id="SERIAL-ENTROPY",
                category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.MEDIUM,
                description=f"File entropy extremely high ({file_entropy:.2f}/8.0): "
                            f"likely encrypted/compressed payload or obfuscated binary",
                location="file",
                evidence=f"shannon_entropy={file_entropy:.2f}",
                confidence=0.65,
                mitigation="Decrypt/inspect; high-entropy regions may hide malicious payload",
            ))

        return patterns


# ---------------------------------------------------------------------------
# Model Reconstructor
# ---------------------------------------------------------------------------

class ModelReconstructor:
    """Attempts to reconstruct model structure from partial/broken files."""

    __slots__ = ('m_recovery_log',)

    def __init__(self):
        self.m_recovery_log: List[str] = []

    def reconstruct_onnx(self, data: bytes) -> Optional[Dict[str, Any]]:
        result: Dict[str, Any] = {
            "recoverable": False,
            "nodes_found": 0,
            "weights_found": 0,
            "errors": [],
        }

        op_types = [
            b'Conv', b'Relu', b'BatchNormalization', b'MaxPool',
            b'AveragePool', b'Gemm', b'MatMul', b'Add', b'Mul',
            b'Softmax', b'Reshape', b'Flatten', b'Concat',
            b'LSTM', b'GRU', b'Dropout', b'Sigmoid', b'Tanh',
        ]

        nodes_found = 0
        for op in op_types:
            nodes_found += data.count(op)

        result["nodes_found"] = nodes_found
        result["recoverable"] = nodes_found > 0

        self.m_recovery_log.append(
            f"ONNX reconstruction: {nodes_found} operation markers found"
        )

        return result

    def reconstruct_tflite(self, data: bytes) -> Optional[Dict[str, Any]]:
        result: Dict[str, Any] = {
            "recoverable": False,
            "valid_flatbuffer": False,
            "errors": [],
        }

        if len(data) >= 8:
            root_offset = _struct.unpack_from('<I', data, 0)[0]
            result["valid_flatbuffer"] = 0 < root_offset < len(data)
            result["recoverable"] = result["valid_flatbuffer"]

        self.m_recovery_log.append(
            f"TFLite reconstruction: valid_flatbuffer={result['valid_flatbuffer']}"
        )

        return result

    def get_log(self) -> List[str]:
        return list(self.m_recovery_log)


# ---------------------------------------------------------------------------
# NN Model Scanner (main orchestrator)
# ---------------------------------------------------------------------------

class NNModelScanner:
    """Complete neural network model security scanner.
       2026-07-31: 魔数优先推断格式（不盲信后缀），新增 BINARY_PAYLOAD 威胁类别"""

    __slots__ = ('m_onnx_parser', 'm_tflite_parser', 'm_backdoor_detector',
                 'm_subgraph_analyzer', 'm_serialization_detector',
                 'm_reconstructor', 'm_scan_history')

    def __init__(self):
        self.m_onnx_parser = ONNXParser()
        self.m_tflite_parser = TFLiteParser()
        self.m_backdoor_detector = BackdoorDetector()
        self.m_subgraph_analyzer = SubgraphAnalyzer()
        self.m_serialization_detector = SerializationAttackDetector()
        self.m_reconstructor = ModelReconstructor()
        self.m_scan_history: List[ScanResult] = []

    def scan(self, model_path: str,
             layer_info: Optional[List[Dict[str, Any]]] = None,
             node_info: Optional[List[Dict[str, Any]]] = None) -> ScanResult:
        import time as _time
        start = _time.time()

        result = ScanResult(model_path=model_path)
        all_patterns: List[SuspiciousPattern] = []

        # 第一步：魔数检测（优先于后缀判断）
        magic_format, magic_desc, magic_entropy = _detect_format_from_magic(model_path)

        # Determine format and parse
        ext = model_path.lower()

        # 如果魔数检测到了二进制可执行文件头，直接报毒，跳过模型解析
        if magic_format == ModelFormat.UNKNOWN and ("executable" in magic_desc.lower() or "malware" in magic_desc.lower()):
            result.metadata = ModelMetadata(
                format=ModelFormat.UNKNOWN,
                detected_magic=magic_desc,
                entropy_score=magic_entropy,
            )
            all_patterns.append(SuspiciousPattern(
                pattern_id="MAGIC-BINARY",
                category=ThreatCategory.BINARY_PAYLOAD,
                severity=Severity.CRITICAL,
                description=f"File magic indicates binary executable, not a model: {magic_desc}",
                location="file_header",
                evidence=magic_desc,
                confidence=0.97,
                mitigation="File appears to be malware masquerading as ML model; quarantine immediately",
            ))
        elif magic_format != ModelFormat.UNKNOWN:
            # 魔数认证通过 → 按检测到的格式解析
            if magic_format == ModelFormat.ONNX:
                result.metadata = self.m_onnx_parser.parse(model_path)
                result.metadata.format = ModelFormat.ONNX
            elif magic_format == ModelFormat.TFLITE:
                result.metadata = self.m_tflite_parser.parse(model_path)
                result.metadata.format = ModelFormat.TFLITE
            elif magic_format == ModelFormat.PYTORCH:
                result.metadata = ModelMetadata(format=ModelFormat.PYTORCH)
                result.metadata.detected_magic = magic_desc
                result.metadata.entropy_score = magic_entropy
                import os as _os
                if _os.path.exists(model_path):
                    result.metadata.file_size = _os.path.getsize(model_path)
            elif magic_format == ModelFormat.KERAS:
                result.metadata = ModelMetadata(format=ModelFormat.KERAS)
                result.metadata.detected_magic = magic_desc
                result.metadata.entropy_score = magic_entropy
                import os as _os
                if _os.path.exists(model_path):
                    result.metadata.file_size = _os.path.getsize(model_path)
            elif magic_format == ModelFormat.TENSORFLOW:
                result.metadata = ModelMetadata(format=ModelFormat.TENSORFLOW)
                result.metadata.detected_magic = magic_desc
                result.metadata.entropy_score = magic_entropy
                import os as _os
                if _os.path.exists(model_path):
                    result.metadata.file_size = _os.path.getsize(model_path)
            else:
                # fallback to extension
                result.metadata = self._parse_by_extension(ext, model_path)
            result.metadata.detected_magic = magic_desc
            result.metadata.entropy_score = magic_entropy
        else:
            # 魔数未识别 → 回退后缀判定（保持向后兼容）
            result.metadata = self._parse_by_extension(ext, model_path)
            result.metadata.detected_magic = magic_desc
            result.metadata.entropy_score = magic_entropy

        # 文件整体熵值检查：超过 7.8 的记录警告
        if magic_entropy > 7.8:
            all_patterns.append(SuspiciousPattern(
                pattern_id="FILE-ENTROPY-HIGH",
                category=ThreatCategory.SERIALIZATION_ATTACK,
                severity=Severity.MEDIUM,
                description=f"Model file entropy very high ({magic_entropy:.2f}/8.0): "
                            f"likely encrypted/obfuscated content",
                location="file",
                evidence=f"shannon_entropy={magic_entropy:.2f}",
                confidence=0.6,
                mitigation="Inspect file for hidden payloads",
            ))

        # Backdoor detection
        backdoor_patterns = self.m_backdoor_detector.detect(result.metadata, layer_info)
        all_patterns.extend(backdoor_patterns)

        # Subgraph analysis
        if node_info:
            subgraph_patterns = self.m_subgraph_analyzer.analyze(node_info)
            all_patterns.extend(subgraph_patterns)

        # Serialization attack detection
        serial_patterns = self.m_serialization_detector.scan(model_path)
        all_patterns.extend(serial_patterns)

        result.patterns = all_patterns

        # Build findings
        result.findings = self._build_findings(all_patterns)

        # Compute risk score
        result.risk_score = self._compute_risk_score(all_patterns)
        result.is_safe = result.risk_score < 0.3

        # Summary
        result.summary = self._generate_summary(result)

        result.scan_duration_ms = (_time.time() - start) * 1000
        self.m_scan_history.append(result)
        return result

    def _parse_by_extension(self, ext: str, model_path: str) -> ModelMetadata:
        """后缀回退解析 —— 魔数检测不到时使用。"""
        import os as _os
        if ext.endswith('.onnx') or ext.endswith('.onnx_data'):
            return self.m_onnx_parser.parse(model_path)
        elif ext.endswith('.tflite') or ext.endswith('.lite'):
            return self.m_tflite_parser.parse(model_path)
        else:
            metadata = ModelMetadata(format=ModelFormat.UNKNOWN)
            metadata.file_size = 0
            try:
                if _os.path.exists(model_path):
                    metadata.file_size = _os.path.getsize(model_path)
            except Exception:
                pass
            return metadata

    def _build_findings(self, patterns: List[SuspiciousPattern]) -> List[SecurityFinding]:
        grouped: Dict[ThreatCategory, List[SuspiciousPattern]] = _defaultdict(list)
        pi = 0
        while pi < len(patterns):
            grouped[patterns[pi].category].append(patterns[pi])
            pi += 1

        findings: List[SecurityFinding] = []
        fid = 0
        cats = list(grouped.keys())
        ci = 0
        while ci < len(cats):
            cat = cats[ci]
            cat_patterns = grouped[cat]
            max_sev = Severity.INFO
            sev_order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
            for p in cat_patterns:
                if sev_order.index(p.severity) > sev_order.index(max_sev):
                    max_sev = p.severity

            recommendations = {
                ThreatCategory.BACKDOOR: "Remove suspicious layers; retrain from trusted checkpoint",
                ThreatCategory.SERIALIZATION_ATTACK: "Quarantine model; audit supply chain",
                ThreatCategory.WEIGHT_POISONING: "Audit training data; retrain with verified dataset",
                ThreatCategory.ARCHITECTURE_TAMPERING: "Verify model architecture against reference",
                ThreatCategory.DATA_LEAKAGE: "Review data flows; implement differential privacy",
                ThreatCategory.SUPPLY_CHAIN: "Verify model provenance and signature",
                ThreatCategory.BINARY_PAYLOAD: "Immediately quarantine; file contains embedded binary/malware",
            }

            findings.append(SecurityFinding(
                finding_id=f"FINDING-{fid}",
                threat_category=cat,
                severity=max_sev,
                title=f"{cat.value.replace('_', ' ').title()} Detected",
                description=f"Found {len(cat_patterns)} pattern(s) related to {cat.value}",
                patterns=cat_patterns,
                recommendation=recommendations.get(cat, "Manual review recommended"),
                cwe_reference=self._cwe_for_category(cat),
            ))
            fid += 1
            ci += 1

        return findings

    def _compute_risk_score(self, patterns: List[SuspiciousPattern]) -> float:
        if not patterns:
            return 0.0

        sev_scores = {
            Severity.CRITICAL: 1.0,
            Severity.HIGH: 0.7,
            Severity.MEDIUM: 0.4,
            Severity.LOW: 0.15,
            Severity.INFO: 0.05,
        }

        total_score = 0.0
        pi = 0
        while pi < len(patterns):
            base = sev_scores.get(patterns[pi].severity, 0.05)
            conf = patterns[pi].confidence
            total_score += base * conf
            pi += 1

        return min(1.0, total_score / max(len(patterns), 1) * 2.0)

    def _generate_summary(self, result: ScanResult) -> str:
        lines = [
            f"Model Security Scan: {result.model_path}",
            f"Format: {result.metadata.format.value}",
            f"Magic Detection: {result.metadata.detected_magic or 'N/A'}",
            f"File Entropy: {result.metadata.entropy_score:.2f}/8.0",
            f"Risk Score: {result.risk_score:.2f}",
            f"Status: {'SAFE' if result.is_safe else 'SUSPICIOUS'}",
            f"Findings: {len(result.findings)}",
            f"Patterns: {len(result.patterns)}",
        ]

        if result.findings:
            lines.append("\nTop findings:")
            fi = 0
            while fi < min(5, len(result.findings)):
                f = result.findings[fi]
                lines.append(f"  [{f.severity.value.upper()}] {f.title}")
                fi += 1

        return "\n".join(lines)

    def _cwe_for_category(self, cat: ThreatCategory) -> str:
        mapping = {
            ThreatCategory.BACKDOOR: "CWE-506",
            ThreatCategory.SUPPLY_CHAIN: "CWE-494",
            ThreatCategory.SERIALIZATION_ATTACK: "CWE-502",
            ThreatCategory.DATA_LEAKAGE: "CWE-359",
            ThreatCategory.WEIGHT_POISONING: "CWE-494",
            ThreatCategory.ARCHITECTURE_TAMPERING: "CWE-15",
            ThreatCategory.BINARY_PAYLOAD: "CWE-506",
        }
        return mapping.get(cat, "")

    def get_history(self) -> List[ScanResult]:
        return list(self.m_scan_history)

    def scan_batch(self, model_paths: List[str]) -> List[ScanResult]:
        results: List[ScanResult] = []
        mi = 0
        while mi < len(model_paths):
            results.append(self.scan(model_paths[mi]))
            mi += 1
        return results


# ---------------------------------------------------------------------------
# Convenience
# ---------------------------------------------------------------------------

def scan_model(model_path: str, **kwargs) -> ScanResult:
    scanner = NNModelScanner()
    return scanner.scan(model_path, **kwargs)
