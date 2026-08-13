import os
import re
import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class CorruptionType(str, Enum):
    """Memory corruption type enumeration."""
    STACK_BUFFER_OVERFLOW = "stack_buffer_overflow"
    HEAP_BUFFER_OVERFLOW = "heap_buffer_overflow"
    USE_AFTER_FREE = "use_after_free"
    DOUBLE_FREE = "double_free"
    NULL_POINTER_DEREFERENCE = "null_pointer_dereference"
    TYPE_CONFUSION = "type_confusion"
    FORMAT_STRING = "format_string"
    INTEGER_OVERFLOW = "integer_overflow"
    OUT_OF_BOUNDS_READ = "out_of_bounds_read"
    OUT_OF_BOUNDS_WRITE = "out_of_bounds_write"
    BUFFER_UNDERFLOW = "buffer_underflow"
    USE_AFTER_RETURN = "use_after_return"
    USE_AFTER_SCOPE = "use_after_scope"
    UNSAFE_UNLINK = "unsafe_unlink"
    HEAP_USE_AFTER_FREE = "heap_use_after_free"
    UNKNOWN = "unknown"


CorruptionType.ALL = list(CorruptionType)


@dataclass
class CorruptionClassification:
    """Storage for single vulnerability classification info."""
    corruption_type: CorruptionType = CorruptionType.UNKNOWN
    confidence: float = 0.0
    evidence: List[str] = field(default_factory=list)
    description: str = ""
    cwe_id: Optional[str] = None


@dataclass
class CrashContext:
    """Crash analysis context data."""
    crash_address: Optional[int] = None
    crash_type: Optional[str] = None
    registers: Dict[str, str] = field(default_factory=dict)
    stack_trace: List[Dict[str, str]] = field(default_factory=list)
    exception_code: Optional[str] = None
    fault_instruction: Optional[str] = None
    memory_state: Dict[str, Any] = field(default_factory=dict)
    protection_info: Dict[str, Any] = field(default_factory=dict)


class CorruptionClassifier:
    """
    Memory corruption classifier.

    Rule-engine based classification with AI-assisted analysis.
    """

    CLASSIFICATION_RULES = {
        CorruptionType.DOUBLE_FREE: [
            ('double free', 0.95),
            ('double_free', 0.95),
            ('doublefree', 0.95),
            ('free.*free', 0.85),
        ],
        CorruptionType.USE_AFTER_FREE: [
            ('use after free', 0.95),
            ('use_after_free', 0.95),
            ('useafterfree', 0.95),
            ('heap-use-after-free', 0.95),
            ('freed pointer', 0.85),
        ],
        CorruptionType.STACK_BUFFER_OVERFLOW: [
            ('stack buffer overflow', 0.95),
            ('stack overflow', 0.9),
            ('__stack_chk_fail', 0.85),
            ('stack smashing', 0.9),
            ('buffer overflow on stack', 0.9),
        ],
        CorruptionType.HEAP_BUFFER_OVERFLOW: [
            ('heap buffer overflow', 0.95),
            ('heap overflow', 0.9),
            ('buffer overflow on heap', 0.9),
            ('heap-based buffer overflow', 0.95),
        ],
        CorruptionType.NULL_POINTER_DEREFERENCE: [
            ('null pointer', 0.95),
            ('nullptr', 0.95),
            ('dereference null', 0.95),
            ('SIGSEGV.*0x0', 0.9),
        ],
        CorruptionType.FORMAT_STRING: [
            ('format string', 0.95),
            ('%n', 0.9),
            ('format vulnerability', 0.95),
        ],
        CorruptionType.TYPE_CONFUSION: [
            ('type confusion', 0.95),
            ('type mismatch', 0.9),
            ('vtable', 0.8),
            ('RTTI', 0.7),
        ],
        CorruptionType.INTEGER_OVERFLOW: [
            ('integer overflow', 0.95),
            ('int overflow', 0.9),
            ('overflow.*integer', 0.9),
        ],
        CorruptionType.OUT_OF_BOUNDS_READ: [
            ('out of bounds read', 0.95),
            ('OOB read', 0.95),
            ('read out of bounds', 0.9),
        ],
        CorruptionType.OUT_OF_BOUNDS_WRITE: [
            ('out of bounds write', 0.95),
            ('OOB write', 0.95),
            ('write out of bounds', 0.9),
        ],
    }

    CWE_MAPPING = {
        CorruptionType.STACK_BUFFER_OVERFLOW: 'CWE-121',
        CorruptionType.HEAP_BUFFER_OVERFLOW: 'CWE-122',
        CorruptionType.USE_AFTER_FREE: 'CWE-416',
        CorruptionType.DOUBLE_FREE: 'CWE-415',
        CorruptionType.NULL_POINTER_DEREFERENCE: 'CWE-476',
        CorruptionType.TYPE_CONFUSION: 'CWE-843',
        CorruptionType.FORMAT_STRING: 'CWE-134',
        CorruptionType.INTEGER_OVERFLOW: 'CWE-190',
        CorruptionType.OUT_OF_BOUNDS_READ: 'CWE-125',
        CorruptionType.OUT_OF_BOUNDS_WRITE: 'CWE-787',
        CorruptionType.BUFFER_UNDERFLOW: 'CWE-124',
        CorruptionType.USE_AFTER_RETURN: 'CWE-416',
        CorruptionType.USE_AFTER_SCOPE: 'CWE-416',
        CorruptionType.UNSAFE_UNLINK: 'CWE-416',
        CorruptionType.HEAP_USE_AFTER_FREE: 'CWE-416',
    }

    def __init__(self):
        self._ready = True
        logger.info("Corruption classifier initialized")

    def classify(self, crash_context: CrashContext, vulnerability_info: Optional[Dict[str, Any]] = None) -> CorruptionClassification:
        """
        Execute memory corruption type classification.
        """
        logger.info("Starting corruption classification...")

        evidence = []
        scores = {ct: 0.0 for ct in CorruptionType.ALL}

        crash_text = self._build_crash_text(crash_context)
        logger.debug(f"Crash context text: {crash_text[:200]}...")

        for corruption_type, rules in self.CLASSIFICATION_RULES.items():
            for pattern, score in rules:
                if re.search(pattern, crash_text, re.IGNORECASE):
                    scores[corruption_type] += score
                    evidence.append(f"Pattern match: {pattern}")

        scores = self._apply_register_analysis(crash_context, scores, evidence)
        scores = self._apply_stack_analysis(crash_context, scores, evidence)
        scores = self._apply_exception_analysis(crash_context, scores, evidence)

        if vulnerability_info:
            scores = self._apply_vulnerability_info(vulnerability_info, scores, evidence)

        max_score = max(scores.values())

        if max_score < 0.5:
            result = CorruptionClassification(
                corruption_type=CorruptionType.UNKNOWN,
                confidence=0.0,
                evidence=evidence,
                description="Unable to determine memory corruption type"
            )
        else:
            best_type = max(scores, key=scores.get)
            result = CorruptionClassification(
                corruption_type=best_type,
                confidence=min(max(max_score, 0.0), 1.0),
                evidence=evidence,
                description=self._get_type_description(best_type),
                cwe_id=self.CWE_MAPPING.get(best_type)
            )
        logger.info(f"Corruption classification complete: {result.corruption_type.value}, confidence: {result.confidence:.2f}")
        return result

    def _build_crash_text(self, crash_context: CrashContext) -> str:
        """Build crash context text for pattern matching."""
        parts = []

        if crash_context.crash_type:
            parts.append(crash_context.crash_type)

        if crash_context.exception_code:
            parts.append(crash_context.exception_code)

        if crash_context.fault_instruction:
            parts.append(crash_context.fault_instruction)

        for frame in crash_context.stack_trace:
            if 'function' in frame:
                parts.append(frame['function'])
            if 'raw' in frame:
                parts.append(frame['raw'])

        for reg_name, reg_value in crash_context.registers.items():
            parts.append(f"{reg_name}={reg_value}")

        return ' '.join(parts)

    def _apply_register_analysis(self, crash_context: CrashContext, scores: Dict, evidence: List[str]) -> Dict:
        rip = crash_context.registers.get('rip') or crash_context.registers.get('eip')

        if rip:
            rip_str = str(rip).lower()

            if '41414141' in rip_str or 'aaaa' in rip_str or 'deadbeef' in rip_str:
                scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.3
                evidence.append("Instruction pointer overwritten by controlled data")

            if '0x0' == rip_str or rip_str == '0':
                scores[CorruptionType.NULL_POINTER_DEREFERENCE] += 0.3
                evidence.append("Instruction pointer is null")

        rsp = crash_context.registers.get('rsp') or crash_context.registers.get('esp')
        if rsp:
            rsp_str = str(rsp).lower()
            if '42424242' in rsp_str or 'bbbb' in rsp_str:
                scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.2
                evidence.append("Stack pointer overwritten by controlled data")

        return scores

    def _apply_stack_analysis(self, crash_context: CrashContext, scores: Dict, evidence: List[str]) -> Dict:
        stack_functions = [frame.get('function', '') for frame in crash_context.stack_trace]
        stack_text = ' '.join(stack_functions).lower()

        if 'free' in stack_text and crash_context.stack_trace:
            first_func = crash_context.stack_trace[0].get('function', '').lower()
            if 'free' in first_func:
                scores[CorruptionType.DOUBLE_FREE] += 0.3
                scores[CorruptionType.USE_AFTER_FREE] += 0.2
                evidence.append("Crash occurred inside free function")

        if '__stack_chk_fail' in stack_text:
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.4
            evidence.append("Stack protection triggered")

        if 'memcpy' in stack_text or 'strcpy' in stack_text:
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.2
            scores[CorruptionType.HEAP_BUFFER_OVERFLOW] += 0.2
            evidence.append("Dangerous memory copy functions involved")

        return scores

    def _apply_exception_analysis(self, crash_context: CrashContext, scores: Dict, evidence: List[str]) -> Dict:
        """Analyze based on exception type."""
        crash_type = (crash_context.crash_type or '').lower()

        if 'sigsegv' in crash_type or 'segmentation fault' in crash_type:
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.1
            scores[CorruptionType.USE_AFTER_FREE] += 0.1

        if 'sigabrt' in crash_type or 'abort' in crash_type:
            scores[CorruptionType.DOUBLE_FREE] += 0.15
            scores[CorruptionType.STACK_BUFFER_OVERFLOW] += 0.1

        if crash_context.exception_code:
            exc_code = crash_context.exception_code.lower()
            if 'c0000005' in exc_code:
                scores[CorruptionType.NULL_POINTER_DEREFERENCE] += 0.2
                evidence.append("Windows access violation exception")

        return scores

    def _apply_vulnerability_info(self, vulnerability_info: Dict[str, Any], scores: Dict, evidence: List[str]) -> Dict:
        vuln_type = vulnerability_info.get('type', '').lower()

        type_mapping = {
            'stack_overflow': CorruptionType.STACK_BUFFER_OVERFLOW,
            'heap_overflow': CorruptionType.HEAP_BUFFER_OVERFLOW,
            'uaf': CorruptionType.USE_AFTER_FREE,
            'use_after_free': CorruptionType.USE_AFTER_FREE,
            'double_free': CorruptionType.DOUBLE_FREE,
            'null_pointer': CorruptionType.NULL_POINTER_DEREFERENCE,
            'format_string': CorruptionType.FORMAT_STRING,
            'type_confusion': CorruptionType.TYPE_CONFUSION,
        }

        for key, corruption_type in type_mapping.items():
            if key in vuln_type:
                scores[corruption_type] += 0.6
                evidence.append(f"Vulnerability type match: {key}")

        return scores

    def _get_type_description(self, corruption_type: CorruptionType) -> str:
        """Get human-readable description for corruption type."""
        descriptions = {
            CorruptionType.HEAP_BUFFER_OVERFLOW: "Heap buffer overflow: writing beyond buffer boundary on heap, may corrupt heap structures or adjacent memory",
            CorruptionType.USE_AFTER_FREE: "Use after free: accessing memory region after it has been freed",
            CorruptionType.DOUBLE_FREE: "Double free: performing multiple free operations on the same memory block",
            CorruptionType.NULL_POINTER_DEREFERENCE: "Null pointer dereference: attempting to access memory at a null pointer",
            CorruptionType.TYPE_CONFUSION: "Type confusion: treating an object of one type as another type incorrectly",
            CorruptionType.FORMAT_STRING: "Format string vulnerability: user input passed directly as format string parameter",
            CorruptionType.INTEGER_OVERFLOW: "Integer overflow: arithmetic result exceeds the representable range of its data type",
            CorruptionType.OUT_OF_BOUNDS_READ: "Out of bounds read: reading data beyond the boundary of an array or buffer",
            CorruptionType.OUT_OF_BOUNDS_WRITE: "Out of bounds write: writing data beyond the boundary of an array or buffer",
            CorruptionType.BUFFER_UNDERFLOW: "Buffer underflow: reading or writing data before the start of a buffer",
            CorruptionType.USE_AFTER_RETURN: "Use after return: using data from a function's stack frame after it has returned",
            CorruptionType.USE_AFTER_SCOPE: "Use after scope: using a variable after it has gone out of scope",
            CorruptionType.UNSAFE_UNLINK: "Unsafe unlink operation: unsafely unlinking a linked list node during heap exploitation",
            CorruptionType.HEAP_USE_AFTER_FREE: "Heap use after free: accessing heap memory after it has been freed",
            CorruptionType.UNKNOWN: "Unknown type: cannot determine the specific memory corruption type",
        }
        return descriptions.get(corruption_type, "Unknown")

    def batch_classify(self, crash_contexts: List[CrashContext], vulnerability_infos: Optional[List[Dict[str, Any]]] = None) -> List[CorruptionClassification]:
        """
        Batch classify memory corruption types.
        """
        results = []
        for i, context in enumerate(crash_contexts):
            vuln_info = vulnerability_infos[i] if vulnerability_infos and i < len(vulnerability_infos) else None
            result = self.classify(context, vuln_info)
            results.append(result)
        return results

    def get_cwe_for_type(self, corruption_type: CorruptionType) -> Optional[str]:
        """
        Get CWE identifier for a given corruption type.
        """
        return self.CWE_MAPPING.get(corruption_type)


def get_corruption_classifier() -> CorruptionClassifier:
    """
    Factory function to obtain a CorruptionClassifier instance.
    """
    return CorruptionClassifier()
