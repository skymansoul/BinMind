"""PPA-HAV: Pointer Provenance-Aware Heap Access Validation.

核心管线:
  pointer_provenance:      追踪指针来源 (分配点+传播路径)
  heap_object_model:       构建堆对象内部结构 (字段/数组布局)
  access_path_validator:   三维验证 (溯源+结构+padding)
  provenance_aware_filter: 五层过滤串联, 输出最终判定
  binary_ppahav_scanner:   二进制级扫描器 (objdump → 完整管线)
  instruction_parser:      objdump Intel语法解析器
"""

from .pointer_provenance import (
    PointerProvenanceTracker, Provenance, ProvenanceType)
from .heap_object_model import HeapObjectModel, ObjectField, AccessType
from .access_path_validator import (
    AccessPathValidator, AccessValidationResult)
from .provenance_aware_filter import (
    ProvenanceAwareFilter, FilteredFinding)
from .binary_ppahav_scanner import BinaryPpahavScanner, BinaryScanResult
from .instruction_parser import InstructionParser, ParsedInstruction

__all__ = [
    "PointerProvenanceTracker", "Provenance", "ProvenanceType",
    "HeapObjectModel", "ObjectField", "AccessType",
    "AccessPathValidator", "AccessValidationResult",
    "ProvenanceAwareFilter", "FilteredFinding",
    "BinaryPpahavScanner", "BinaryScanResult",
    "InstructionParser", "ParsedInstruction",
]
