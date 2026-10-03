"""信息泄露分析 —— 泄露点识别、能力矩阵与利用评估。

识别格式化字符串等泄露原语，评估可泄露数据类型与字节量，
生成泄露能力矩阵。
"""

import os
import re
import os
import struct
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional


class LeakType(Enum):
    """泄露原语类型。"""
    FORMAT_STRING = "format_string"
    OOB_READ = "oob_read"
    UNINITIALIZED = "uninitialized"
    UNKNOWN = "unknown"


class LeakDataType(Enum):
    """可泄露的数据类型。"""
    LIBC_ADDRESS = "libc_address"
    POINTER = "pointer"
    STACK_DATA = "stack_data"
    HEAP_DATA = "heap_data"
    STRING = "string"


class Severity(Enum):
    """泄露严重度。"""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class LeakPoint:
    """单个泄露点。"""
    leak_id: str = ""
    leak_type: LeakType = LeakType.UNKNOWN
    location: str = ""
    instruction: str = ""
    severity: Severity = Severity.LOW
    leakable_data_types: List[LeakDataType] = field(default_factory=list)
    leakable_bytes: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'leak_id': self.leak_id,
            'leak_type': self.leak_type.value,
            'location': self.location,
            'instruction': self.instruction,
            'severity': self.severity.value,
            'leakable_data_types': [t.value for t in self.leakable_data_types],
            'leakable_bytes': self.leakable_bytes,
        }


@dataclass
class LeakCapabilityMatrix:
    """泄露能力评估矩阵。"""
    binary_name: str = ""
    total_leak_points: int = 0
    can_leak_libc_address: bool = False
    leak_points: List[LeakPoint] = field(default_factory=list)
    format_string_leaks: int = 0


_SEVERITY_WEIGHT = {Severity.LOW: 1, Severity.MEDIUM: 2,
                    Severity.HIGH: 3, Severity.CRITICAL: 4}


class InfoLeakAnalyzer:
    """信息泄露分析器。"""

    def __init__(self, binary_path: str = ""):
        self.binary_path = binary_path
        self.binary_name = os.path.basename(binary_path) if binary_path else ""
        self.min_confidence = 0.5
        self.leak_points: List[LeakPoint] = []

    def analyze(self, decomp_data: Optional[Dict] = None,
                crash_data: Optional[Dict] = None,
                binary_info: Optional[Dict] = None) -> LeakCapabilityMatrix:
        """分析泄露点并生成能力矩阵。"""
        self.leak_points = []
        self._analyze_memory_read_vulnerabilities(decomp_data or {})
        if crash_data:
            self._analyze_crash_leaks(crash_data)

        matrix = LeakCapabilityMatrix(
            binary_name=self.binary_name,
            total_leak_points=len(self.leak_points),
            format_string_leaks=sum(
                1 for lp in self.leak_points
                if lp.leak_type == LeakType.FORMAT_STRING),
        )
        for lp in self.leak_points:
            if LeakDataType.LIBC_ADDRESS in lp.leakable_data_types:
                matrix.can_leak_libc_address = True
                break
        matrix.leak_points = self.leak_points
        return matrix

    def _analyze_memory_read_vulnerabilities(self, decomp_data: Dict) -> None:
        """从反编译数据中识别泄露点。"""
        for func_name, func_info in decomp_data.items():
            pseudocode = ''
            address = 0
            if isinstance(func_info, dict):
                pseudocode = func_info.get('pseudocode', '') or ''
                address = func_info.get('address', 0)
            elif isinstance(func_info, str):
                pseudocode = func_info

            for m in re.finditer(r'printf\s*\(\s*([^"%][^)]*)\)', pseudocode):
                arg = m.group(1).strip()
                if arg:
                    self.leak_points.append(LeakPoint(
                        leak_id=f'fmt_{func_name}_{len(self.leak_points)}',
                        leak_type=LeakType.FORMAT_STRING,
                        location=func_name,
                        instruction=f'printf({arg})',
                        severity=self._determine_leak_severity(
                            [LeakDataType.STACK_DATA], 8),
                        leakable_data_types=[LeakDataType.STACK_DATA,
                                             LeakDataType.POINTER],
                        leakable_bytes=8,
                    ))

    def _analyze_crash_leaks(self, crash_data: Dict) -> None:
        """从崩溃寄存器中评估可泄露信息。"""
        registers = crash_data.get('registers', {})
        if registers:
            self.leak_points.append(LeakPoint(
                leak_id='crash_registers',
                leak_type=LeakType.UNKNOWN,
                location=crash_data.get('function', 'unknown'),
                instruction='register dump',
                severity=Severity.MEDIUM,
                leakable_data_types=[LeakDataType.POINTER],
                leakable_bytes=16,
            ))

    def _select_best_leak_point(self) -> Optional[LeakPoint]:
        """按严重度与泄露字节量选择最优泄露点。"""
        if not self.leak_points:
            return None
        return max(
            self.leak_points,
            key=lambda lp: (_SEVERITY_WEIGHT.get(lp.severity, 0),
                            lp.leakable_bytes),
        )

    def _generate_format_string_exploit(self, format_arg: str,
                                        offset: int) -> str:
        """生成格式化字符串泄露 payload。"""
        return f'%{offset}$p'.replace('$1$', '$') if offset > 1 else '%p'

    def _determine_leak_severity(self, data_types: List[LeakDataType],
                                 leakable_bytes: int) -> Severity:
        """按数据类型与字节量判定泄露严重度。"""
        if LeakDataType.LIBC_ADDRESS in data_types:
            if leakable_bytes >= 64:
                return Severity.CRITICAL
            return Severity.HIGH
        if LeakDataType.POINTER in data_types:
            return Severity.MEDIUM
        if leakable_bytes >= 64:
            return Severity.MEDIUM
        return Severity.LOW


def _detect_bad_chars(payload: bytes, bad_chars: Optional[list[bytes]] = None) -> list[bytes]:
    """检测 payload 中包含的坏字符。
    自动检测格式字符串中常见的坏字符: \\x00, \\x0a, \\x0d, \\x20"""
    bc = bad_chars or BAD_CHARS_DEFAULT
    found = []
    for c in bc:
        if c in payload:
            found.append(c)
    return found


# ---- 模块级便捷入口 ----
def analyze_info_leak(binary_path: str,
                      binary_info: Optional[Dict] = None,
                      decomp_data: Optional[Dict] = None,
                      crash_data: Optional[Dict] = None) -> LeakCapabilityMatrix:
    """便捷入口: 执行信息泄露分析。"""
    analyzer = InfoLeakAnalyzer(binary_path)
    return analyzer.analyze(decomp_data=decomp_data, crash_data=crash_data,
                            binary_info=binary_info)
