import logging
import re
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class OperationType(Enum):
    MEMSET = "memset"
    MEMCPY = "memcpy"
    MEMMOVE = "memmove"
    STRCPY = "strcpy"
    BZERO = "bzero"
    FREE = "free"
    ALLOC = "alloc"

class RiskLevel(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class SensitiveOperation:
    operation_type: OperationType
    address: int
    target_buffer: str = ""
    size: Optional[int] = None
    is_key_cleanup: bool = False
    risk_level: RiskLevel = RiskLevel.LOW
    description: str = ""
    compiler_optimization_risk: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            'operation_type': self.operation_type.value,
            'address': hex(self.address),
            'target_buffer': self.target_buffer,
            'size': self.size,
            'is_key_cleanup': self.is_key_cleanup,
            'risk_level': self.risk_level.value,
            'description': self.description,
            'compiler_optimization_risk': self.compiler_optimization_risk
        }


@dataclass
class DetectionResult:
    operations: List[SensitiveOperation] = field(default_factory=list)
    high_risk_count: int = 0
    optimization_risks: int = 0
    summary: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'operations': [o.to_dict() for o in self.operations],
            'high_risk_count': self.high_risk_count,
            'optimization_risks': self.optimization_risks,
            'summary': self.summary
        }


class MemorySensitiveOpDetector:

    def __init__(self):
        self.key_related_keywords = [
            'key', 'secret', 'password', 'token', 'credential',
            'crypto', 'encrypt', 'decrypt', 'hash', 'signature',
            'private', 'public', 'certificate', 'cipher'
        ]

        self.sensitive_operations = {
            OperationType.MEMSET: {
                'patterns': [r'memset\(', r'__builtin_memset'],
                'description': 'Memory fill'
            },
            OperationType.BZERO: {
                'patterns': [r'bzero\(', r'explicit_bzero\('],
                'description': 'Memory zeroing'
            },
            OperationType.MEMCPY: {
                'patterns': [r'memcpy\('],
                'description': 'Memory copy'
            },
            OperationType.MEMMOVE: {
                'patterns': [r'memmove\('],
                'description': 'Memory move'
            },
            OperationType.STRCPY: {
                'patterns': [r'strcpy\('],
                'description': 'String copy'
            }
        }

    def detect(self, binary_info: Dict[str, Any]) -> DetectionResult:
        operations = []
        high_risk_count = 0
        optimization_risks = 0

        for func in binary_info.get('functions', []):
            func_name = func.get('name', '')
            pseudocode = func.get('pseudocode', '')

            for op_type, op_info in self.sensitive_operations.items():
                for pattern in op_info['patterns']:
                    if pattern in pseudocode:
                        operation = self._analyze_operation(
                            op_type,
                            func,
                            pseudocode,
                            pattern
                        )
                        if operation:
                            operations.append(operation)

                            if operation.risk_level == RiskLevel.HIGH:
                                high_risk_count += 1

                            if operation.compiler_optimization_risk:
                                optimization_risks += 1

        summary = self._generate_summary(operations)

        return DetectionResult(
            operations=operations,
            high_risk_count=high_risk_count,
            optimization_risks=optimization_risks,
            summary=summary)

    def _analyze_operation(self, op_type: OperationType, func: Dict[str, Any], pseudocode: str, pattern: str) -> Optional[SensitiveOperation]:
        is_key_cleanup = False
        compiler_risk = False

        for keyword in self.key_related_keywords:
            if keyword.lower() in func.get('name', '').lower():
                is_key_cleanup = True
                break
            if keyword.lower() in pseudocode.lower():
                is_key_cleanup = True
                break

        if op_type == OperationType.MEMSET and is_key_cleanup:
            if 'memset(' in pseudocode and '0' in pseudocode:
                compiler_risk = True

                if 'volatile' not in pseudocode:
                    compiler_risk = True

        if op_type == OperationType.BZERO:
            if 'explicit_bzero' not in pseudocode:
                compiler_risk = True

        risk_level = RiskLevel.LOW

        if is_key_cleanup and compiler_risk:
            risk_level = RiskLevel.HIGH
        elif is_key_cleanup:
            risk_level = RiskLevel.MEDIUM

        description = f"{op_type.value} operation"
        if is_key_cleanup:
            description += " (key-material cleanup)"
        if compiler_risk:
            description += " — compiler optimization may elide this"

        return SensitiveOperation(
            operation_type=op_type,
            address=func.get('address', 0),
            target_buffer=self._extract_target_buffer(pseudocode),
            size=self._extract_size(pseudocode),
            is_key_cleanup=is_key_cleanup,
            risk_level=risk_level,
            description=description,
            compiler_optimization_risk=compiler_risk)

    def _extract_target_buffer(self, pseudocode: str) -> str:
        match = re.search(r'memset\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)', pseudocode)
        if match:
            return match.group(1)

        match = re.search(r'bzero\s*\(\s*([a-zA-Z_][a-zA-Z0-9_]*)', pseudocode)
        if match:
            return match.group(1)

        return 'unknown'

    def _extract_size(self, pseudocode: str) -> Optional[int]:
        match = re.search(r'memset\s*\([^,]+\s*,\s*[^,]+\s*,\s*(\d+)', pseudocode)
        if match:
            return int(match.group(1))

        match = re.search(r'bzero\s*\([^,]+\s*,\s*(\d+)', pseudocode)
        if match:
            return int(match.group(1))

        return None

    def _generate_summary(self, operations: List[SensitiveOperation]) -> Dict[str, Any]:
        by_type = {op.value: 0 for op in OperationType}
        by_risk = {r.value: 0 for r in RiskLevel}

        for op in operations:
            by_type[op.operation_type.value] += 1
            by_risk[op.risk_level.value] += 1

        return {
            'total_operations': len(operations),
            'operations_by_type': by_type,
            'operations_by_risk': by_risk,
            'key_cleanup_operations': len([o for o in operations if o.is_key_cleanup]),
            'optimization_risk_operations': len([o for o in operations if o.compiler_optimization_risk])
        }


def detect_memory_sensitive_operations(binary_info: Dict[str, Any]) -> DetectionResult:
    detector = MemorySensitiveOpDetector()
    return detector.detect(binary_info)
