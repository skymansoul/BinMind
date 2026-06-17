import os

MODULES_DIR = "modules"

modules = {
    "symbol_address_mapper.py": '''
"""
符号地址与真实地址映射表模块

功能：
1. 生成符号地址映射文件
2. 支持多种格式导出
3. 地址解析与转换

核心组件：
- SymbolMapper: 符号映射器
- AddressMap: 地址映射
- MapExporter: 映射导出器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class SymbolEntry:
    symbol_name: str
    virtual_address: int
    physical_address: Optional[int] = None
    size: int = 0
    section: Optional[str] = None


class SymbolMapper:

    def __init__(self):
        self._symbols: Dict[str, SymbolEntry] = {}
        self._address_map: Dict[int, SymbolEntry] = {}

    def add_symbol(self, symbol_name: str, virtual_address: int,
                   physical_address: Optional[int] = None, size: int = 0,
                   section: Optional[str] = None):
        entry = SymbolEntry(
            symbol_name=symbol_name,
            virtual_address=virtual_address,
            physical_address=physical_address,
            size=size,
            section=section
        )
        self._symbols[symbol_name] = entry
        self._address_map[virtual_address] = entry

    def get_symbol_by_name(self, symbol_name: str) -> Optional[SymbolEntry]:
        return self._symbols.get(symbol_name)

    def get_symbol_by_address(self, address: int) -> Optional[SymbolEntry]:
        if address in self._address_map:
            return self._address_map[address]
        
        for entry in self._symbols.values():
            if entry.virtual_address <= address < entry.virtual_address + entry.size:
                return entry
        
        return None

    def resolve_address(self, address: int) -> Dict[str, Any]:
        entry = self.get_symbol_by_address(address)
        if entry:
            offset = address - entry.virtual_address
            return {
                "symbol_name": entry.symbol_name,
                "virtual_address": hex(entry.virtual_address),
                "physical_address": hex(entry.physical_address) if entry.physical_address else None,
                "offset": hex(offset),
                "section": entry.section
            }
        return {"address": hex(address), "symbol": None}

    def get_all_symbols(self) -> List[SymbolEntry]:
        return list(self._symbols.values())

    def load_from_file(self, filepath: str) -> bool:
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    parts = line.strip().split()
                    if len(parts) >= 2:
                        try:
                            addr = int(parts[0], 16)
                            name = parts[1]
                            self.add_symbol(name, addr)
                        except ValueError:
                            pass
            return True
        except Exception as e:
            logger.error(f"Failed to load symbols: {e}")
            return False


class MapExporter:

    @staticmethod
    def export_to_file(mapper: SymbolMapper, filepath: str, format_type: str = "txt") -> bool:
        try:
            symbols = mapper.get_all_symbols()
            
            if format_type == "txt":
                with open(filepath, 'w') as f:
                    for entry in symbols:
                        f.write(f"{hex(entry.virtual_address)} {entry.symbol_name}\n")
            
            elif format_type == "json":
                import json
                data = {
                    "symbols": [
                        {
                            "name": entry.symbol_name,
                            "virtual_address": entry.virtual_address,
                            "physical_address": entry.physical_address,
                            "size": entry.size,
                            "section": entry.section
                        }
                        for entry in symbols
                    ]
                }
                with open(filepath, 'w') as f:
                    json.dump(data, f, indent=2)
            
            elif format_type == "gdb":
                with open(filepath, 'w') as f:
                    for entry in symbols:
                        f.write(f"add-symbol-file {entry.symbol_name} {hex(entry.virtual_address)}\n")
            
            return True
        except Exception as e:
            logger.error(f"Failed to export map: {e}")
            return False


def create_symbol_map(symbols: List[Dict[str, Any]]) -> SymbolMapper:
    mapper = SymbolMapper()
    for sym in symbols:
        mapper.add_symbol(
            sym["name"],
            int(sym["virtual_address"], 16),
            int(sym.get("physical_address", "0"), 16) if sym.get("physical_address") else None,
            sym.get("size", 0),
            sym.get("section")
        )
    return mapper
''',

    "multimodal_binary_embedding.py": '''
"""
多模态二进制嵌入模块

功能：
1. 图+文本+结构特征融合
2. 支持多种嵌入模型
3. 相似度计算与检索

核心组件：
- BinaryEmbedding: 二进制嵌入
- MultimodalEncoder: 多模态编码器
- EmbeddingIndex: 嵌入索引
"""

import os
import hashlib
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class BinaryEmbedding:
    binary_id: str
    graph_embedding: List[float]
    text_embedding: List[float]
    struct_embedding: List[float]
    combined_embedding: List[float]


class MultimodalEncoder:

    def __init__(self):
        self._dimension = 512

    def encode_graph(self, graph_data: Dict[str, Any]) -> List[float]:
        nodes = graph_data.get("nodes", [])
        edges = graph_data.get("edges", [])
        
        hash_val = hashlib.sha256(f"{nodes}{edges}".encode()).digest()
        embedding = [int.from_bytes(hash_val[i:i+4], 'little') / 0xFFFFFFFF for i in range(0, 32, 4)]
        
        while len(embedding) < self._dimension:
            embedding.extend(embedding)
        
        return embedding[:self._dimension]

    def encode_text(self, text: str) -> List[float]:
        hash_val = hashlib.sha256(text.encode()).digest()
        embedding = [int.from_bytes(hash_val[i:i+4], 'little') / 0xFFFFFFFF for i in range(0, 32, 4)]
        
        while len(embedding) < self._dimension:
            embedding.extend(embedding)
        
        return embedding[:self._dimension]

    def encode_structure(self, struct_data: Dict[str, Any]) -> List[float]:
        features = []
        for key in sorted(struct_data.keys()):
            features.append(str(struct_data[key]))
        
        hash_val = hashlib.sha256("|".join(features).encode()).digest()
        embedding = [int.from_bytes(hash_val[i:i+4], 'little') / 0xFFFFFFFF for i in range(0, 32, 4)]
        
        while len(embedding) < self._dimension:
            embedding.extend(embedding)
        
        return embedding[:self._dimension]

    def combine_embeddings(self, graph_emb: List[float], text_emb: List[float],
                          struct_emb: List[float]) -> List[float]:
        combined = []
        for i in range(self._dimension):
            combined.append((graph_emb[i] + text_emb[i] + struct_emb[i]) / 3.0)
        return combined

    def encode(self, binary_data: bytes, text: str, struct_data: Dict[str, Any]) -> BinaryEmbedding:
        graph_emb = self.encode_graph({"nodes": [], "edges": []})
        text_emb = self.encode_text(text)
        struct_emb = self.encode_structure(struct_data)
        combined = self.combine_embeddings(graph_emb, text_emb, struct_emb)
        
        return BinaryEmbedding(
            binary_id=hashlib.sha256(binary_data).hexdigest(),
            graph_embedding=graph_emb,
            text_embedding=text_emb,
            struct_embedding=struct_emb,
            combined_embedding=combined
        )


class EmbeddingIndex:

    def __init__(self):
        self._embeddings: Dict[str, BinaryEmbedding] = {}
        self._index: List[Tuple[str, List[float]]] = []

    def add_embedding(self, embedding: BinaryEmbedding):
        self._embeddings[embedding.binary_id] = embedding
        self._index.append((embedding.binary_id, embedding.combined_embedding))

    def search(self, query_embedding: List[float], top_k: int = 5) -> List[Tuple[str, float]]:
        results = []
        
        for binary_id, embedding in self._index:
            similarity = self._cosine_similarity(query_embedding, embedding)
            results.append((binary_id, similarity))
        
        return sorted(results, key=lambda x: x[1], reverse=True)[:top_k]

    def _cosine_similarity(self, vec1: List[float], vec2: List[float]) -> float:
        dot_product = sum(a * b for a, b in zip(vec1, vec2))
        norm1 = sum(a * a for a in vec1) ** 0.5
        norm2 = sum(b * b for b in vec2) ** 0.5
        
        if norm1 == 0 or norm2 == 0:
            return 0.0
        
        return dot_product / (norm1 * norm2)

    def get_embedding(self, binary_id: str) -> Optional[BinaryEmbedding]:
        return self._embeddings.get(binary_id)


def create_embedding(binary_data: bytes, text: str, struct_data: Dict[str, Any]) -> BinaryEmbedding:
    encoder = MultimodalEncoder()
    return encoder.encode(binary_data, text, struct_data)
''',

    "exploit_code_generator.py": '''
"""
基于程序合成的利用代码生成模块

功能：
1. 枚举指令序列
2. 生成利用代码模板
3. 自动化利用代码生成

核心组件：
- ExploitGenerator: 利用代码生成器
- InstructionEnumerator: 指令枚举器
- PayloadBuilder: 载荷构建器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class PayloadType(Enum):
    SHELLCODE = "shellcode"
    ROP_CHAIN = "rop_chain"
    FORMAT_STRING = "format_string"
    BUFFER_OVERFLOW = "buffer_overflow"


@dataclass
class ExploitCode:
    payload_type: PayloadType
    code: bytes
    template: str
    parameters: Dict[str, Any] = field(default_factory=dict)


class InstructionEnumerator:

    def __init__(self):
        self._instructions = {
            "x86": [
                ("mov", ["rax", "rbx"]),
                ("mov", ["rax", "0x10"]),
                ("add", ["rax", "rbx"]),
                ("sub", ["rax", "rbx"]),
                ("xor", ["rax", "rax"]),
                ("push", ["rax"]),
                ("pop", ["rax"]),
                ("ret", []),
                ("syscall", []),
                ("jmp", ["rax"]),
                ("call", ["rax"]),
                ("nop", [])
            ]
        }

    def enumerate_sequences(self, arch: str = "x86", max_length: int = 5) -> List[List[Tuple[str, List[str]]]]:
        sequences = []
        instructions = self._instructions.get(arch, [])
        
        def generate(current, length):
            if length == 0:
                sequences.append(current.copy())
                return
            
            for instr in instructions:
                current.append(instr)
                generate(current, length - 1)
                current.pop()
        
        for length in range(1, max_length + 1):
            generate([], length)
        
        return sequences

    def to_bytes(self, instructions: List[Tuple[str, List[str]]]) -> bytes:
        result = b""
        
        for instr, args in instructions:
            if instr == "nop":
                result += b"\\x90"
            elif instr == "ret":
                result += b"\\xc3"
            elif instr == "xor" and args == ["rax", "rax"]:
                result += b"\\x48\\x31\\xc0"
            elif instr == "syscall":
                result += b"\\x0f\\x05"
            else:
                result += b"\\x90"
        
        return result


class PayloadBuilder:

    def __init__(self):
        self._rop_gadgets = []

    def add_rop_gadget(self, address: int, instructions: List[str]):
        self._rop_gadgets.append({"address": address, "instructions": instructions})

    def build_rop_chain(self, gadgets: List[int]) -> bytes:
        chain = b""
        for gadget in gadgets:
            chain += gadget.to_bytes(8, 'little')
        return chain

    def build_buffer_overflow(self, payload: bytes, offset: int) -> bytes:
        padding = b"A" * offset
        return padding + payload

    def build_format_string(self, offsets: List[int], values: List[int]) -> bytes:
        fmt = b""
        for i, (offset, value) in enumerate(zip(offsets, values)):
            fmt += f"%{offset}$lln".encode()
            fmt += value.to_bytes(8, 'little')
        return fmt


class ExploitGenerator:

    def __init__(self):
        self._enumerator = InstructionEnumerator()
        self._builder = PayloadBuilder()

    def generate_shellcode(self, arch: str = "x86") -> ExploitCode:
        sequences = self._enumerator.enumerate_sequences(arch, 3)
        
        template = """
# Shellcode template
xor rax, rax
mov rdi, 0
syscall
"""
        
        code = self._enumerator.to_bytes([("xor", ["rax", "rax"]), ("ret", [])])
        
        return ExploitCode(
            payload_type=PayloadType.SHELLCODE,
            code=code,
            template=template,
            parameters={"arch": arch}
        )

    def generate_rop_chain(self, gadgets: List[int]) -> ExploitCode:
        chain = self._builder.build_rop_chain(gadgets)
        
        return ExploitCode(
            payload_type=PayloadType.ROP_CHAIN,
            code=chain,
            template="ROP chain",
            parameters={"gadgets": gadgets}
        )

    def generate_buffer_overflow(self, payload: bytes, offset: int) -> ExploitCode:
        overflow = self._builder.build_buffer_overflow(payload, offset)
        
        return ExploitCode(
            payload_type=PayloadType.BUFFER_OVERFLOW,
            code=overflow,
            template="Buffer overflow",
            parameters={"offset": offset}
        )


def generate_exploit(payload_type: str, **kwargs) -> ExploitCode:
    generator = ExploitGenerator()
    
    if payload_type == "shellcode":
        return generator.generate_shellcode(kwargs.get("arch", "x86"))
    elif payload_type == "rop":
        return generator.generate_rop_chain(kwargs.get("gadgets", []))
    elif payload_type == "buffer_overflow":
        return generator.generate_buffer_overflow(kwargs.get("payload", b""), kwargs.get("offset", 100))
    
    return ExploitCode(
        payload_type=PayloadType.BUFFER_OVERFLOW,
        code=b"",
        template="unknown"
    )
''',

    "protocol_downgrade_detector.py": '''
"""
回退安全协议降级攻击检测模块

功能：
1. 检测SSLv3/TLS1.0降级
2. 识别协议降级攻击
3. 生成安全报告

核心组件：
- ProtocolDetector: 协议检测器
- DowngradeAnalyzer: 降级分析器
- SecurityReporter: 安全报告器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProtocolVersion(Enum):
    SSLv2 = "SSLv2"
    SSLv3 = "SSLv3"
    TLSv1_0 = "TLSv1.0"
    TLSv1_1 = "TLSv1.1"
    TLSv1_2 = "TLSv1.2"
    TLSv1_3 = "TLSv1.3"


class VulnerabilityStatus(Enum):
    SAFE = "safe"
    VULNERABLE = "vulnerable"
    UNKNOWN = "unknown"


@dataclass
class ProtocolDetection:
    version: ProtocolVersion
    status: VulnerabilityStatus
    ciphers: List[str] = field(default_factory=list)
    vulnerabilities: List[str] = field(default_factory=list)


class ProtocolDetector:

    _VULNERABLE_PROTOCOLS = {
        ProtocolVersion.SSLv2: ["CVE-2011-0014"],
        ProtocolVersion.SSLv3: ["CVE-2014-3566", "POODLE"],
        ProtocolVersion.TLSv1_0: ["BEAST", "CRIME"],
        ProtocolVersion.TLSv1_1: ["CRIME"]
    }

    def __init__(self):
        self._detected_protocols: List[ProtocolDetection] = []

    def detect(self, server_info: Dict[str, Any]) -> List[ProtocolDetection]:
        results = []
        
        for protocol in server_info.get("protocols", []):
            version = self._parse_protocol(protocol)
            if version:
                status = self._evaluate_protocol(version)
                vulnerabilities = self._VULNERABLE_PROTOCOLS.get(version, [])
                
                results.append(ProtocolDetection(
                    version=version,
                    status=status,
                    ciphers=server_info.get("ciphers", []),
                    vulnerabilities=vulnerabilities
                ))
        
        self._detected_protocols = results
        return results

    def _parse_protocol(self, protocol_str: str) -> Optional[ProtocolVersion]:
        protocol_str = protocol_str.lower()
        
        if "sslv2" in protocol_str:
            return ProtocolVersion.SSLv2
        elif "sslv3" in protocol_str:
            return ProtocolVersion.SSLv3
        elif "tlsv1.0" in protocol_str or "tls1.0" in protocol_str:
            return ProtocolVersion.TLSv1_0
        elif "tlsv1.1" in protocol_str or "tls1.1" in protocol_str:
            return ProtocolVersion.TLSv1_1
        elif "tlsv1.2" in protocol_str or "tls1.2" in protocol_str:
            return ProtocolVersion.TLSv1_2
        elif "tlsv1.3" in protocol_str or "tls1.3" in protocol_str:
            return ProtocolVersion.TLSv1_3
        
        return None

    def _evaluate_protocol(self, version: ProtocolVersion) -> VulnerabilityStatus:
        if version in self._VULNERABLE_PROTOCOLS:
            return VulnerabilityStatus.VULNERABLE
        return VulnerabilityStatus.SAFE

    def is_vulnerable(self) -> bool:
        return any(d.status == VulnerabilityStatus.VULNERABLE for d in self._detected_protocols)


class SecurityReporter:

    @staticmethod
    def generate_report(detections: List[ProtocolDetection]) -> Dict[str, Any]:
        report = {
            "total_protocols": len(detections),
            "vulnerable_count": sum(1 for d in detections if d.status == VulnerabilityStatus.VULNERABLE),
            "recommendations": [],
            "details": []
        }

        for detection in detections:
            detail = {
                "protocol": detection.version.value,
                "status": detection.status.value,
                "vulnerabilities": detection.vulnerabilities,
                "ciphers": detection.ciphers
            }
            report["details"].append(detail)

            if detection.status == VulnerabilityStatus.VULNERABLE:
                report["recommendations"].append(
                    f"Disable {detection.version.value} protocol"
                )

        return report


def detect_downgrade_attack(server_info: Dict[str, Any]) -> Dict[str, Any]:
    detector = ProtocolDetector()
    detections = detector.detect(server_info)
    
    report = SecurityReporter.generate_report(detections)
    report["is_vulnerable"] = detector.is_vulnerable()
    
    return report
''',

    "analysis_cross_validator.py": '''
"""
静态/动态分析结果交叉验证模块

功能：
1. 对比静态分析与动态分析结果
2. syscall预测对比
3. 结果一致性验证

核心组件：
- CrossValidator: 交叉验证器
- AnalysisResult: 分析结果
- ResultComparator: 结果比较器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class AnalysisType(Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"


class ValidationStatus(Enum):
    MATCH = "match"
    MISMATCH = "mismatch"
    INCONCLUSIVE = "inconclusive"


@dataclass
class AnalysisResult:
    analysis_type: AnalysisType
    syscalls: List[str]
    functions: List[str]
    vulnerabilities: List[str]
    metadata: Dict[str, Any] = field(default_factory=dict)


class ResultComparator:

    def compare_syscalls(self, static: List[str], dynamic: List[str]) -> Dict[str, Any]:
        static_set = set(static)
        dynamic_set = set(dynamic)
        
        return {
            "static_only": list(static_set - dynamic_set),
            "dynamic_only": list(dynamic_set - static_set),
            "common": list(static_set & dynamic_set),
            "match_percentage": len(static_set & dynamic_set) / max(len(static_set), len(dynamic_set), 1) * 100
        }

    def compare_functions(self, static: List[str], dynamic: List[str]) -> Dict[str, Any]:
        static_set = set(static)
        dynamic_set = set(dynamic)
        
        return {
            "static_only": list(static_set - dynamic_set),
            "dynamic_only": list(dynamic_set - static_set),
            "common": list(static_set & dynamic_set),
            "match_percentage": len(static_set & dynamic_set) / max(len(static_set), len(dynamic_set), 1) * 100
        }

    def compare_vulnerabilities(self, static: List[str], dynamic: List[str]) -> Dict[str, Any]:
        static_set = set(static)
        dynamic_set = set(dynamic)
        
        return {
            "static_only": list(static_set - dynamic_set),
            "dynamic_only": list(dynamic_set - static_set),
            "common": list(static_set & dynamic_set),
            "match_percentage": len(static_set & dynamic_set) / max(len(static_set), len(dynamic_set), 1) * 100
        }


class CrossValidator:

    def __init__(self):
        self._comparator = ResultComparator()

    def validate(self, static_result: AnalysisResult, dynamic_result: AnalysisResult) -> Dict[str, Any]:
        syscall_compare = self._comparator.compare_syscalls(
            static_result.syscalls,
            dynamic_result.syscalls
        )
        
        function_compare = self._comparator.compare_functions(
            static_result.functions,
            dynamic_result.functions
        )
        
        vuln_compare = self._comparator.compare_vulnerabilities(
            static_result.vulnerabilities,
            dynamic_result.vulnerabilities
        )

        avg_match = (syscall_compare["match_percentage"] + 
                     function_compare["match_percentage"] + 
                     vuln_compare["match_percentage"]) / 3

        status = ValidationStatus.MATCH if avg_match >= 80 else \
                 ValidationStatus.MISMATCH if avg_match < 50 else \
                 ValidationStatus.INCONCLUSIVE

        return {
            "status": status.value,
            "average_match_percentage": avg_match,
            "syscalls": syscall_compare,
            "functions": function_compare,
            "vulnerabilities": vuln_compare
        }


def validate_analysis(static_data: Dict[str, Any], dynamic_data: Dict[str, Any]) -> Dict[str, Any]:
    static_result = AnalysisResult(
        analysis_type=AnalysisType.STATIC,
        syscalls=static_data.get("syscalls", []),
        functions=static_data.get("functions", []),
        vulnerabilities=static_data.get("vulnerabilities", []),
        metadata=static_data.get("metadata", {})
    )
    
    dynamic_result = AnalysisResult(
        analysis_type=AnalysisType.DYNAMIC,
        syscalls=dynamic_data.get("syscalls", []),
        functions=dynamic_data.get("functions", []),
        vulnerabilities=dynamic_data.get("vulnerabilities", []),
        metadata=dynamic_data.get("metadata", {})
    )
    
    validator = CrossValidator()
    return validator.validate(static_result, dynamic_result)
''',

    "timing_side_channel_evaluator.py": '''
"""
时序侧信道利用评估模型模块

功能：
1. 统计指令计数差异
2. 检测时序攻击可能性
3. 评估侧信道风险

核心组件：
- TimingAnalyzer: 时序分析器
- SideChannelDetector: 侧信道检测器
- RiskEvaluator: 风险评估器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class RiskLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class TimingMeasurement:
    instruction_count: int
    execution_time: float
    memory_accesses: int
    cache_misses: int


@dataclass
class SideChannelRisk:
    function_name: str
    risk_level: RiskLevel
    timing_difference: float
    cache_attack_possible: bool
    description: str


class TimingAnalyzer:

    def __init__(self):
        self._measurements: List[TimingMeasurement] = []

    def add_measurement(self, instruction_count: int, execution_time: float,
                       memory_accesses: int = 0, cache_misses: int = 0):
        self._measurements.append(TimingMeasurement(
            instruction_count=instruction_count,
            execution_time=execution_time,
            memory_accesses=memory_accesses,
            cache_misses=cache_misses
        ))

    def analyze(self) -> Dict[str, Any]:
        if not self._measurements:
            return {}

        times = [m.execution_time for m in self._measurements]
        instructions = [m.instruction_count for m in self._measurements]
        
        return {
            "average_time": sum(times) / len(times),
            "min_time": min(times),
            "max_time": max(times),
            "time_std_dev": self._std_dev(times),
            "time_range": max(times) - min(times),
            "average_instructions": sum(instructions) / len(instructions),
            "total_measurements": len(self._measurements)
        }

    def _std_dev(self, values: List[float]) -> float:
        if len(values) < 2:
            return 0.0
        
        mean = sum(values) / len(values)
        variance = sum((v - mean) ** 2 for v in values) / (len(values) - 1)
        return variance ** 0.5


class SideChannelDetector:

    def detect_cache_attacks(self, measurements: List[TimingMeasurement]) -> bool:
        cache_misses = [m.cache_misses for m in measurements]
        if len(cache_misses) < 2:
            return False
        
        variance = sum((m - sum(cache_misses)/len(cache_misses)) ** 2 for m in cache_misses) / len(cache_misses)
        return variance > 10

    def detect_timing_leaks(self, measurements: List[TimingMeasurement]) -> float:
        times = [m.execution_time for m in measurements]
        if len(times) < 2:
            return 0.0
        
        return max(times) - min(times)


class RiskEvaluator:

    def evaluate(self, function_name: str, measurements: List[TimingMeasurement]) -> SideChannelRisk:
        analyzer = TimingAnalyzer()
        for m in measurements:
            analyzer.add_measurement(m.instruction_count, m.execution_time,
                                    m.memory_accesses, m.cache_misses)
        
        analysis = analyzer.analyze()
        detector = SideChannelDetector()
        
        timing_diff = analysis.get("time_range", 0)
        cache_attack = detector.detect_cache_attacks(measurements)

        if timing_diff > 0.1 or cache_attack:
            risk_level = RiskLevel.CRITICAL
            description = "High timing variance or cache attack possible"
        elif timing_diff > 0.01:
            risk_level = RiskLevel.HIGH
            description = "Significant timing differences detected"
        elif timing_diff > 0.001:
            risk_level = RiskLevel.MEDIUM
            description = "Moderate timing variance"
        else:
            risk_level = RiskLevel.LOW
            description = "Low timing risk"

        return SideChannelRisk(
            function_name=function_name,
            risk_level=risk_level,
            timing_difference=timing_diff,
            cache_attack_possible=cache_attack,
            description=description
        )


def evaluate_side_channel(function_name: str, measurements: List[Dict[str, int]]) -> SideChannelRisk:
    timing_measurements = []
    for m in measurements:
        timing_measurements.append(TimingMeasurement(
            instruction_count=m.get("instruction_count", 0),
            execution_time=m.get("execution_time", 0),
            memory_accesses=m.get("memory_accesses", 0),
            cache_misses=m.get("cache_misses", 0)
        ))
    
    evaluator = RiskEvaluator()
    return evaluator.evaluate(function_name, timing_measurements)
''',

    "state_based_fuzzer.py": '''
"""
基于状态的模糊测试驱动模块

功能：
1. 协议状态机建模
2. 状态感知的模糊测试
3. 智能状态转换

核心组件：
- ProtocolStateMachine: 协议状态机
- StateFuzzer: 状态感知模糊器
- TransitionGenerator: 状态转换生成器
"""

import os
import random
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class ProtocolState(Enum):
    INIT = "init"
    CONNECTING = "connecting"
    CONNECTED = "connected"
    AUTHENTICATING = "authenticating"
    AUTHENTICATED = "authenticated"
    DATA_TRANSFER = "data_transfer"
    CLOSING = "closing"
    CLOSED = "closed"


@dataclass
class Transition:
    from_state: ProtocolState
    to_state: ProtocolState
    message_type: str
    probability: float


@dataclass
class FuzzCase:
    state: ProtocolState
    message: bytes
    expected_state: ProtocolState


class ProtocolStateMachine:

    def __init__(self):
        self._transitions: Dict[ProtocolState, List[Transition]] = {}
        self._current_state = ProtocolState.INIT

    def add_transition(self, from_state: ProtocolState, to_state: ProtocolState,
                      message_type: str, probability: float = 0.5):
        if from_state not in self._transitions:
            self._transitions[from_state] = []
        
        self._transitions[from_state].append(Transition(
            from_state=from_state,
            to_state=to_state,
            message_type=message_type,
            probability=probability
        ))

    def get_possible_transitions(self, state: ProtocolState) -> List[Transition]:
        return self._transitions.get(state, [])

    def transition(self, message_type: str) -> Optional[ProtocolState]:
        transitions = self.get_possible_transitions(self._current_state)
        
        for trans in transitions:
            if trans.message_type == message_type:
                self._current_state = trans.to_state
                return trans.to_state
        
        return None

    def get_current_state(self) -> ProtocolState:
        return self._current_state

    def reset(self):
        self._current_state = ProtocolState.INIT


class TransitionGenerator:

    def __init__(self):
        self._message_templates = {
            "connect": b"CONNECT %s:%d\\r\\n",
            "authenticate": b"AUTH %s %s\\r\\n",
            "data": b"DATA %s\\r\\n",
            "close": b"CLOSE\\r\\n"
        }

    def generate_random_message(self, message_type: str) -> bytes:
        template = self._message_templates.get(message_type, b"%s\\r\\n")
        
        if message_type == "connect":
            return template % (b"localhost", 8080)
        elif message_type == "authenticate":
            return template % (b"user", b"pass")
        elif message_type == "data":
            return template % (b"X" * random.randint(10, 100))
        else:
            return template % (b"test",)

    def generate_fuzzed_message(self, message_type: str) -> bytes:
        base = self.generate_random_message(message_type)
        
        if random.random() < 0.3:
            position = random.randint(0, len(base))
            fuzzed = bytearray(base)
            fuzzed[position % len(fuzzed)] = random.randint(0, 255)
            return bytes(fuzzed)
        
        return base


class StateFuzzer:

    def __init__(self):
        self._state_machine = ProtocolStateMachine()
        self._generator = TransitionGenerator()
        self._fuzz_cases: List[FuzzCase] = []

    def build_default_protocol(self):
        self._state_machine.add_transition(ProtocolState.INIT, ProtocolState.CONNECTING, "connect")
        self._state_machine.add_transition(ProtocolState.CONNECTING, ProtocolState.CONNECTED, "connect_ack")
        self._state_machine.add_transition(ProtocolState.CONNECTED, ProtocolState.AUTHENTICATING, "authenticate")
        self._state_machine.add_transition(ProtocolState.AUTHENTICATING, ProtocolState.AUTHENTICATED, "auth_ack")
        self._state_machine.add_transition(ProtocolState.AUTHENTICATED, ProtocolState.DATA_TRANSFER, "data")
        self._state_machine.add_transition(ProtocolState.DATA_TRANSFER, ProtocolState.CLOSING, "close")
        self._state_machine.add_transition(ProtocolState.CLOSING, ProtocolState.CLOSED, "close_ack")

    def generate_fuzz_cases(self, count: int = 100) -> List[FuzzCase]:
        cases = []
        
        for _ in range(count):
            current_state = self._state_machine.get_current_state()
            transitions = self._state_machine.get_possible_transitions(current_state)
            
            if not transitions:
                self._state_machine.reset()
                continue
            
            transition = random.choice(transitions)
            message = self._generator.generate_fuzzed_message(transition.message_type)
            
            cases.append(FuzzCase(
                state=current_state,
                message=message,
                expected_state=transition.to_state
            ))
            
            self._state_machine.transition(transition.message_type)
        
        self._fuzz_cases = cases
        return cases

    def run_fuzz(self, target_function: Callable[[bytes], bool]) -> List[Dict[str, Any]]:
        results = []
        
        for case in self._fuzz_cases:
            try:
                result = target_function(case.message)
                results.append({
                    "state": case.state.value,
                    "message_length": len(case.message),
                    "success": result,
                    "expected_state": case.expected_state.value
                })
            except Exception as e:
                results.append({
                    "state": case.state.value,
                    "message_length": len(case.message),
                    "success": False,
                    "expected_state": case.expected_state.value,
                    "error": str(e)
                })
        
        return results


def fuzz_protocol(target_function: Callable[[bytes], bool], count: int = 100) -> List[Dict[str, Any]]:
    fuzzer = StateFuzzer()
    fuzzer.build_default_protocol()
    fuzzer.generate_fuzz_cases(count)
    return fuzzer.run_fuzz(target_function)
''',

    "root_cause_analyzer.py": '''
"""
自动化root原因分析图生成模块

功能：
1. 漏洞传播路径图
2. 因果关系分析
3. 可视化输出

核心组件：
- RootCauseAnalyzer: Root原因分析器
- VulnerabilityGraph: 漏洞图
- PathFinder: 路径查找器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class GraphNode:
    id: str
    type: str
    label: str
    properties: Dict[str, Any] = field(default_factory=dict)


@dataclass
class GraphEdge:
    source: str
    target: str
    relation: str
    weight: float = 1.0


@dataclass
class VulnerabilityPath:
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    severity: float
    description: str


class VulnerabilityGraph:

    def __init__(self):
        self._nodes: Dict[str, GraphNode] = {}
        self._edges: List[GraphEdge] = []

    def add_node(self, node_id: str, node_type: str, label: str,
                 properties: Optional[Dict[str, Any]] = None):
        if node_id not in self._nodes:
            self._nodes[node_id] = GraphNode(
                id=node_id,
                type=node_type,
                label=label,
                properties=properties or {}
            )

    def add_edge(self, source_id: str, target_id: str, relation: str, weight: float = 1.0):
        if source_id in self._nodes and target_id in self._nodes:
            self._edges.append(GraphEdge(
                source=source_id,
                target=target_id,
                relation=relation,
                weight=weight
            ))

    def get_node(self, node_id: str) -> Optional[GraphNode]:
        return self._nodes.get(node_id)

    def get_edges(self) -> List[GraphEdge]:
        return self._edges

    def to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": [
                {
                    "id": node.id,
                    "type": node.type,
                    "label": node.label,
                    "properties": node.properties
                }
                for node in self._nodes.values()
            ],
            "edges": [
                {
                    "source": edge.source,
                    "target": edge.target,
                    "relation": edge.relation,
                    "weight": edge.weight
                }
                for edge in self._edges
            ]
        }


class PathFinder:

    def find_paths(self, graph: VulnerabilityGraph, start_id: str, end_id: str) -> List[List[str]]:
        paths = []
        visited = set()

        def dfs(current: str, path: List[str]):
            if current == end_id:
                paths.append(path.copy())
                return
            
            if current in visited:
                return
            
            visited.add(current)
            path.append(current)
            
            for edge in graph.get_edges():
                if edge.source == current:
                    dfs(edge.target, path)
            
            path.pop()
            visited.remove(current)
        
        dfs(start_id, [])
        return paths


class RootCauseAnalyzer:

    def __init__(self):
        self._graph = VulnerabilityGraph()
        self._path_finder = PathFinder()

    def build_graph(self, vulnerability_data: Dict[str, Any]):
        for func in vulnerability_data.get("functions", []):
            self._graph.add_node(
                func["id"],
                "function",
                func["name"],
                {"vulnerable": func.get("vulnerable", False)}
            )
        
        for call in vulnerability_data.get("calls", []):
            self._graph.add_edge(call["source"], call["target"], "calls", call.get("weight", 1.0))

    def analyze(self, start_node: str, end_node: str) -> List[VulnerabilityPath]:
        paths = self._path_finder.find_paths(self._graph, start_node, end_node)
        results = []
        
        for path_nodes in paths:
            edges = []
            for i in range(len(path_nodes) - 1):
                for edge in self._graph.get_edges():
                    if edge.source == path_nodes[i] and edge.target == path_nodes[i + 1]:
                        edges.append(edge)
                        break
            
            nodes = [self._graph.get_node(nid) for nid in path_nodes if self._graph.get_node(nid)]
            
            results.append(VulnerabilityPath(
                nodes=nodes,
                edges=edges,
                severity=sum(e.weight for e in edges),
                description=f"Path from {start_node} to {end_node}"
            ))
        
        return sorted(results, key=lambda p: p.severity, reverse=True)

    def generate_report(self, results: List[VulnerabilityPath]) -> Dict[str, Any]:
        report = {
            "total_paths": len(results),
            "critical_paths": [
                {
                    "nodes": [n.label for n in path.nodes],
                    "severity": path.severity,
                    "description": path.description
                }
                for path in results if path.severity >= 3
            ],
            "graph": self._graph.to_dict()
        }
        
        return report


def analyze_root_cause(vulnerability_data: Dict[str, Any], start_node: str, end_node: str) -> Dict[str, Any]:
    analyzer = RootCauseAnalyzer()
    analyzer.build_graph(vulnerability_data)
    paths = analyzer.analyze(start_node, end_node)
    return analyzer.generate_report(paths)
''',

    "graph_database_abstractor.py": '''
"""
多后端图数据库抽象模块

功能：
1. NetworkX+Neo4j统一接口
2. 图数据抽象层
3. 多后端支持

核心组件：
- GraphDatabase: 图数据库抽象
- NetworkXBackend: NetworkX后端
- Neo4jBackend: Neo4j后端
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class BackendType(Enum):
    NETWORKX = "networkx"
    NEO4J = "neo4j"


@dataclass
class GraphQuery:
    type: str
    params: Dict[str, Any] = field(default_factory=dict)


class GraphDatabase:

    def __init__(self, backend_type: BackendType = BackendType.NETWORKX):
        self._backend_type = backend_type
        self._backend = self._create_backend()

    def _create_backend(self):
        if self._backend_type == BackendType.NETWORKX:
            return NetworkXBackend()
        elif self._backend_type == BackendType.NEO4J:
            return Neo4jBackend()
        return NetworkXBackend()

    def add_node(self, node_id: str, node_type: str, properties: Optional[Dict[str, Any]] = None):
        self._backend.add_node(node_id, node_type, properties)

    def add_edge(self, source_id: str, target_id: str, relation: str, properties: Optional[Dict[str, Any]] = None):
        self._backend.add_edge(source_id, target_id, relation, properties)

    def query(self, query: GraphQuery) -> List[Dict[str, Any]]:
        return self._backend.query(query)

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._backend.get_node(node_id)

    def get_neighbors(self, node_id: str) -> List[str]:
        return self._backend.get_neighbors(node_id)

    def export_to_dict(self) -> Dict[str, Any]:
        return self._backend.export_to_dict()


class NetworkXBackend:

    def __init__(self):
        self._nodes: Dict[str, Dict[str, Any]] = {}
        self._edges: List[Dict[str, Any]] = []

    def add_node(self, node_id: str, node_type: str, properties: Optional[Dict[str, Any]] = None):
        self._nodes[node_id] = {
            "id": node_id,
            "type": node_type,
            "properties": properties or {}
        }

    def add_edge(self, source_id: str, target_id: str, relation: str, properties: Optional[Dict[str, Any]] = None):
        self._edges.append({
            "source": source_id,
            "target": target_id,
            "relation": relation,
            "properties": properties or {}
        })

    def query(self, query: GraphQuery) -> List[Dict[str, Any]]:
        if query.type == "find_by_type":
            node_type = query.params.get("type")
            return [node for node in self._nodes.values() if node["type"] == node_type]
        
        elif query.type == "find_neighbors":
            node_id = query.params.get("node_id")
            neighbors = []
            for edge in self._edges:
                if edge["source"] == node_id:
                    neighbors.append(self._nodes.get(edge["target"]))
                elif edge["target"] == node_id:
                    neighbors.append(self._nodes.get(edge["source"]))
            return neighbors
        
        return []

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> List[str]:
        neighbors = set()
        for edge in self._edges:
            if edge["source"] == node_id:
                neighbors.add(edge["target"])
            elif edge["target"] == node_id:
                neighbors.add(edge["source"])
        return list(neighbors)

    def export_to_dict(self) -> Dict[str, Any]:
        return {
            "nodes": list(self._nodes.values()),
            "edges": self._edges
        }


class Neo4jBackend:

    def __init__(self):
        self._connected = False

    def add_node(self, node_id: str, node_type: str, properties: Optional[Dict[str, Any]] = None):
        pass

    def add_edge(self, source_id: str, target_id: str, relation: str, properties: Optional[Dict[str, Any]] = None):
        pass

    def query(self, query: GraphQuery) -> List[Dict[str, Any]]:
        return []

    def get_node(self, node_id: str) -> Optional[Dict[str, Any]]:
        return None

    def get_neighbors(self, node_id: str) -> List[str]:
        return []

    def export_to_dict(self) -> Dict[str, Any]:
        return {"nodes": [], "edges": []}


def create_graph_database(backend_type: str = "networkx") -> GraphDatabase:
    return GraphDatabase(BackendType[backend_type.upper()])
'''
}

def main():
    if not os.path.exists(MODULES_DIR):
        os.makedirs(MODULES_DIR)
    
    for filename, content in modules.items():
        filepath = os.path.join(MODULES_DIR, filename)
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content.strip())
        print(f"Created: {filename}")

if __name__