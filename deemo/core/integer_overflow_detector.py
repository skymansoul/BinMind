# core/integer_overflow_detector.py
# Integer overflow detection with value range analysis.
# Unlike naive pattern matching, checks whether operand values can provably
# exceed INT32_MAX when multiplied or added.
# Creates 2026-07-30. Modified 2026-08-05: added actual range checking.
import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

INT32_MAX = 0x7FFFFFFF
INT32_MIN = -0x80000000
UINT32_MAX = 0xFFFFFFFF

_MUL_ALLOC = re.compile(r'(?:malloc|calloc|realloc|kmalloc|kzalloc)\s*\(\s*(\w[\w\d_]*)\s*\*\s*(\w[\w\d_]*)\s*\)')
_ADD_ALLOC = re.compile(r'(?:malloc|calloc|realloc|kmalloc|kzalloc)\s*\(\s*(\w[\w\d_]*)\s*\+\s*(\w[\w\d_]*)\s*\)')
_VAR_ASSIGN = re.compile(r"(\w[\w\d_]*)\s*=\s*(-?(?:0x[0-9a-fA-F]+|\d+))\s*")

@dataclass
class OverflowSite:
    func_name: str
    expr_type: str
    operands: list
    overflow_threshold: int
    confidence: float
    line_text: str

class IntegerOverflowDetector:
    def detect(self, pseudocode):
        lines = pseudocode.splitlines()
        # Extract variable constant assignments for range analysis.
        # Handles both "int a = 5;" and "int a = 5, b = 6;" patterns.
        var_constants = {}
        for line in lines:
            stripped = line.strip()
            m = _VAR_ASSIGN.search(stripped)
            if m: var_constants[m.group(1)] = int(m.group(2), 0)
            # Comma-separated: int a = 5, b = 6;
            if '=' in stripped and ',' in stripped:
                # Extract type prefix and split assignments
                parts = stripped.split(None, 1)
                if len(parts) > 1:
                    rhs = parts[1]
                    for chunk in rhs.split(','):
                        eq = chunk.strip()
                        m2 = _VAR_ASSIGN.search(eq)
                        if not m2:
                            m2 = _VAR_ASSIGN.search(eq + ';')
                        if m2: var_constants[m2.group(1)] = int(m2.group(2), 0)
        
        sites = []
        for i, raw in enumerate(lines):
            line = raw.strip()
            for m in _MUL_ALLOC.finditer(line):
                a, b = m.group(1), m.group(2)
                va = self._value(a, var_constants)
                vb = self._value(b, var_constants)
                conf = self._overflow_conf(va, vb, 'mul')
                sites.append(OverflowSite(
                    func_name=f'line_{i+1}',
                    expr_type='mul_alloc', operands=[a,b],
                    overflow_threshold=INT32_MAX,
                    confidence=conf,
                    line_text=line[:120]))
            for m in _ADD_ALLOC.finditer(line):
                a, b = m.group(1), m.group(2)
                va = self._value(a, var_constants)
                vb = self._value(b, var_constants)
                conf = self._overflow_conf(va, vb, 'add')
                sites.append(OverflowSite(
                    func_name=f'line_{i+1}',
                    expr_type='add_alloc', operands=[a,b],
                    overflow_threshold=INT32_MAX,
                    confidence=conf,
                    line_text=line[:120]))
        return sites

    @staticmethod
    def _value(name, constants):
        return constants.get(name)
    
    @staticmethod
    def _overflow_conf(va, vb, op):
        # Both constants: definitive check
        if va is not None and vb is not None:
            if op == 'mul' and va > 0 and vb > 0 and va * vb > INT32_MAX:
                return 0.95
            if op == 'add' and va + vb > INT32_MAX:
                return 0.90
            return 0.10  # constants but no overflow
        # One constant large enough to be risky
        if va is not None and va > 0xFFFF:
            return 0.50
        if vb is not None and vb > 0xFFFF:
            return 0.50
        # Both variables: potential risk, low confidence
        if va is None and vb is None:
            return 0.25
        # One variable + one small constant = unlikely to overflow
        return 0.15

__all__ = ['OverflowSite', 'IntegerOverflowDetector']

# Backward compatibility wrapper
def detect_integer_overflows(pseudocode, func_name=''):
    detector = IntegerOverflowDetector()
    sites = detector.detect(pseudocode)
    findings = []
    for s in sites:
        findings.append({
            'function': func_name or s.func_name,
            'expression': f'{s.operands[0]}*{s.operands[1]}' if s.expr_type=='mul_alloc' else f'{s.operands[0]}+{s.operands[1]}',
            'confidence': s.confidence,
            'target_variable': 'alloc_size',
            'result_range': f'threshold={s.overflow_threshold}',
            'overflow_reason': f'{s.expr_type} may exceed INT32_MAX' if s.confidence>0.3 else 'unlikely',
            'exploitable': s.confidence > 0.4,
            'description': f'Integer overflow risk in {s.expr_type} ({s.operands[0]}, {s.operands[1]}) conf={s.confidence:.2f}',
            'exploitation': 'Overflow leads to undersized allocation' if s.confidence>0.4 else '',
        })
    return sorted(findings, key=lambda f: -f['confidence'])