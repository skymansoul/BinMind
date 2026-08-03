"""差分测试共享枚举与数据类——供 engine_differential_test 与 discrepancy_detector 无循环导入共享"""
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional


class EngineKind(str, Enum):
    GHIDRA = "ghidra"
    IDA = "ida"
    RADARE2 = "radare2"
    BINARY_NINJA = "binary_ninja"
    ANGR = "angr"
    CUSTOM_1 = "custom_1"
    CUSTOM_2 = "custom_2"
    INTERNAL = "internal"

class AnalysisKind(str, Enum):
    FUNCTION_LIST = "function_list"
    DECOMPILED = "decompiled"
    CALL_GRAPH = "call_graph"
    CFG = "cfg"
    STRINGS = "strings"
    IMPORTS = "imports"
    DISASSEMBLY = "disassembly"

class DiscrepancySeverity(str, Enum):
    CRITICAL = "critical"
    MAJOR = "major"
    MINOR = "minor"
    COSMETIC = "cosmetic"


@dataclass
class EngineResult:
    engine: EngineKind
    analysis: AnalysisKind
    data: Any
    elapsed: float = 0.0
    error: str = ""
    timestamp: float = 0.0

    def __post_init__(self):
        if self.timestamp == 0.0:
            self.timestamp = time.time()


@dataclass
class Discrepancy:
    analysis: AnalysisKind
    severity: DiscrepancySeverity
    description: str
    engine_subset: list = field(default_factory=list)
    detail: dict = field(default_factory=dict)
    confidence: float = 0.0
    cross_analysis_hint: Optional[str] = None


@dataclass
class DifferentialTestResult:
    binary_path: str
    binary_hash: str
    analyses: list = field(default_factory=list)
    engine_results: list = field(default_factory=list)
    discrepancies: list = field(default_factory=list)
    consensus: dict = field(default_factory=dict)
    outliers: list = field(default_factory=list)
    overall_score: float = 0.0
    timestamp: float = 0.0
    engine_reliability: dict = field(default_factory=dict)
    cross_correlations: list = field(default_factory=list)
