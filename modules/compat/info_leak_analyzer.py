from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any
from enum import StrEnum
import logging, os, re

logger = logging.getLogger(__name__)

class LeakType(StrEnum):
    FORMAT_STRING = "format_string"
    STACK_OVERFLOW_READ = "stack_overflow_read"
    HEAP_OVERFLOW_READ = "heap_overflow_read"
    USE_AFTER_FREE_READ = "uaf_read"
    INTEGER_OVERFLOW_READ = "int_overflow_read"
    OFF_BY_ONE_READ = "off_by_one_read"
    UNINITIALIZED_READ = "uninit_read"
    BUFFER_OVERFLOW_READ = "buffer_overflow_read"

class LeakDataType(StrEnum):
    STACK_ADDRESS = "stack_address"
    HEAP_ADDRESS = "heap_address"
    LIBC_ADDRESS = "libc_address"
    BINARY_BASE = "binary_base"
    CANARY = "canary"
    POINTER = "pointer"
    OFFSET = "offset"
    RANDOM_BYTES = "random_bytes"
    ENVIRONMENT = "environment"
    UNKNOWN = "unknown"

class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"

@dataclass
class LeakPoint:
    leak_id: str = ""
    leak_type: LeakType = LeakType.FORMAT_STRING
    location: str = ""
    instruction: str = ""
    severity: Severity = Severity.LOW
    leakable_data_types: List[LeakDataType] = field(default_factory=list)
    leakable_bytes: int = 0
    parameter_index: int = -1
    stack_offset: int = 0
    confidence: float = 0.0
    description: str = ""
    exploit_snippet: str = ""
    raw_data: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leak_id": self.leak_id, "leak_type": self.leak_type.value,
            "location": self.location, "instruction": self.instruction,
            "severity": self.severity.value,
            "leakable_data_types": [dt.value for dt in self.leakable_data_types],
            "leakable_bytes": self.leakable_bytes,
            "parameter_index": self.parameter_index,
            "stack_offset": self.stack_offset, "confidence": self.confidence,
            "description": self.description,
            "exploit_snippet": self.exploit_snippet,
        }

@dataclass
class LeakCapabilityMatrix:
    binary_name: str = ""
    total_leak_points: int = 0
    format_string_leaks: int = 0
    memory_read_leaks: int = 0
    can_leak_stack_address: bool = False
    can_leak_heap_address: bool = False
    can_leak_libc_address: bool = False
    can_leak_binary_base: bool = False
    can_leak_canary: bool = False
    max_leakable_bytes: int = 0
    avg_leakable_bytes: float = 0.0
    leak_points: List[LeakPoint] = field(default_factory=list)
    best_leak_point: Optional[LeakPoint] = None
    exploit_strategy: str = ""
    recommended_bad_chars: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "binary_name": self.binary_name,
            "summary": {
                "total_leak_points": self.total_leak_points,
                "format_string_leaks": self.format_string_leaks,
                "memory_read_leaks": self.memory_read_leaks,
                "can_leak_stack_address": self.can_leak_stack_address,
                "can_leak_heap_address": self.can_leak_heap_address,
                "can_leak_libc_address": self.can_leak_libc_address,
                "can_leak_binary_base": self.can_leak_binary_base,
                "can_leak_canary": self.can_leak_canary,
                "max_leakable_bytes": self.max_leakable_bytes,
                "avg_leakable_bytes": self.avg_leakable_bytes,
            },
            "best_leak_point": self.best_leak_point.to_dict() if self.best_leak_point else None,
            "exploit_strategy": self.exploit_strategy,
            "leak_points": [lp.to_dict() for lp in self.leak_points],
        }

class InfoLeakAnalyzer:
    FORMAT_FUNC_PATTERNS = [r'printf\s*\(', r'fprintf\s*\(\s*\w+\s*,',
        r'sprintf\s*\(', r'snprintf\s*\(', r'vprintf\s*\(', r'vfprintf\s*\(',
        r'vsprintf\s*\(', r'vsnprintf\s*\(', r'puts\s*\(', r'putchar\s*\(']
    DANGEROUS_FORMAT_PATTERNS = [(r'printf\s*\(\s*(\w+)\s*\)', 1)]
    SAFE_FORMAT_PATTERNS = [r'printf\s*\(\s*"[^"]*"\s*,', r'fprintf\s*\(\s*\w+\s*,\s*"[^"]*"\s*,']
    LEAK_FORMAT_SPECIFIERS = [('%p','pointer',8,''), ('%s','string',0,''), ('%x','hex_int',8,'')]

    def __init__(self, binary_path="", min_confidence=0.5, max_depth=10):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path) if binary_path else "unknown"
        self.min_confidence = min_confidence
        self.max_depth = max_depth
        self.leak_points: List[LeakPoint] = []
        self.analysis_context: Dict[str, Any] = {}
        self.logger = logging.getLogger(__name__)

    def analyze(self, binary_info=None, decomp_data=None, crash_data=None, symbols=None) -> LeakCapabilityMatrix:
        matrix = LeakCapabilityMatrix(binary_name=self.binary_name)
        if decomp_data:
            for func_name, func_data in decomp_data.items():
                if isinstance(func_data, dict):
                    pseudocode = func_data.get('pseudocode', '')
                    for pat, pi in self.DANGEROUS_FORMAT_PATTERNS:
                        for m in re.finditer(pat, pseudocode):
                            lp = LeakPoint(leak_id=f"fmt_{func_name}_{len(self.leak_points)}",
                                leak_type=LeakType.FORMAT_STRING, location=func_name,
                                instruction=m.group(0), severity=Severity.HIGH,
                                confidence=0.95, description=f"fmt vuln in {func_name}")
                            self.leak_points.append(lp)
        matrix.total_leak_points = len(self.leak_points)
        matrix.leak_points = list(self.leak_points)
        return matrix

    def detect_format_string_in_binary(self, binary_path):
        return []

    def generate_leak_payload(self, leak_point, target_type):
        return '%p ' * 10

def analyze_info_leak(binary_path, binary_info=None, decomp_data=None, crash_data=None) -> LeakCapabilityMatrix:
    return InfoLeakAnalyzer(binary_path=binary_path).analyze(
        binary_info=binary_info, decomp_data=decomp_data, crash_data=crash_data)
