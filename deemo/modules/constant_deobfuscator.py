"""
上下文感知的常量反混淆模块

功能：
1. 用SMT求解还原((x*0xCCCCCCCD)>>3)之类的除数或魔法数
2. 识别和还原各种常量混淆模式
3. 支持多种反混淆技术

核心组件：
- ConstantDeobfuscator: 常量反混淆器
- MagicNumberRecognizer: 魔法数识别器
- SMTResolver: SMT求解器
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    from z3 import *
    Z3_AVAILABLE = True
except ImportError:
    Z3_AVAILABLE = False
    logger.warning("z3 not available")


class ObfuscationPattern(Enum):
    MULTIPLICATIVE_INVERSE = "multiplicative_inverse"
    BIT_ROTATION = "bit_rotation"
    XOR_CIPHER = "xor_cipher"
    ADDITIVE_CHAIN = "additive_chain"
    TABLE_LOOKUP = "table_lookup"
    POLYNOMIAL = "polynomial"


@dataclass
class DeobfuscationResult:
    original_expr: str
    simplified_expr: str
    pattern: Optional[ObfuscationPattern] = None
    magic_numbers: List[int] = field(default_factory=list)
    verified: bool = False


class MagicNumberRecognizer:

    _MAGIC_NUMBERS = {
        0xCCCCCCCD: {"description": "Multiplicative inverse of 3 (32-bit)", "operation": "division", "divisor": 3},
        0xAAAB: {"description": "Multiplicative inverse of 3 (16-bit)", "operation": "division", "divisor": 3},
        0x55555556: {"description": "Multiplicative inverse of 2 (round up)", "operation": "division", "divisor": 2},
        0x2AAAAAAB: {"description": "Multiplicative inverse of 5 (32-bit)", "operation": "division", "divisor": 5},
        0x1999999A: {"description": "Multiplicative inverse of 7 (32-bit)", "operation": "division", "divisor": 7},
        0x15555556: {"description": "Multiplicative inverse of 11 (32-bit)", "operation": "division", "divisor": 11},
        0x80000000: {"description": "Sign extension mask", "operation": "sign_extend"},
        0x7FFFFFFF: {"description": "Max signed 32-bit", "operation": "max_value"},
        0xFFFFFFFF: {"description": "All ones mask", "operation": "mask"},
        0x0F0F0F0F: {"description": "Nibble mask", "operation": "mask"},
        0xFF00FF00: {"description": "Byte swap mask", "operation": "mask"},
    }

    @classmethod
    def recognize(cls, value: int) -> Optional[Dict[str, Any]]:
        return cls._MAGIC_NUMBERS.get(value)

    @classmethod
    def find_magic_numbers(cls, code: bytes) -> List[Tuple[int, Dict[str, Any]]]:
        results = []
        for i in range(len(code) - 3):
            value = int.from_bytes(code[i:i+4], 'little')
            info = cls.recognize(value)
            if info:
                results.append((value, info

        return results


class SMTResolver:

    def __init__(self):
        self._solver = None,
        if Z3_AVAILABLE:
            self._solver = Solver()

    def solve_division_inverse(self, magic_constant: int, bits: int = 32) -> Optional[int]:
        if not Z3_AVAILABLE:
            return None

        x = BitVec('x', bits)
        y = BitVec('y', bits)
        magic = BitVecVal(magic_constant, bits)

        self._solver.reset()
        self._solver.add(y != 0)
        self._solver.add((x * magic) >> (bits - 1) == x / y)

        if self._solver.check() == sat:
            model = self._solver.model()
            y_val = model[y].as_long()
            return y_val
        return None

    def verify_equation(self, expr1: str, expr2: str) -> bool:
        if not Z3_AVAILABLE:
            return False

        try:
            x = BitVec('x', 32)
            e1 = eval(expr1.replace('x', 'x'

            e2 = eval(expr2.replace('x', 'x'

            self._solver.reset()
            self._solver.add(ForAll([x], e1 == e2

            return self._solver.check( == sat)
        except Exception:
            return False


class ConstantDeobfuscator:

    def __init__(self):
        self._magic_recognizer = MagicNumberRecognizer()
        self._smt_resolver = SMTResolver()

    def deobfuscate(self, expression: str) -> DeobfuscationResult:
        result = DeobfuscationResult()
            original_expr=expression,
            simplified_expr=expression
        

        patterns = [
            self._detect_multiplicative_inverse,
            self._detect_bit_rotation,
            self._detect_xor_cipher,
            self._detect_additive_chain,
        ]

        for pattern_detector in patterns:
            detected = pattern_detector(expression)
            if detected:
                result.pattern = detected["pattern"]
                result.simplified_expr = detected["simplified"]
                result.magic_numbers = detected.get("magic_numbers", [])
                break

        if Z3_AVAILABLE and result.simplified_expr != expression:
            result.verified = self._smt_resolver.verify_equation()
                expression, result.simplified_expr
            

        return result

    def _detect_multiplicative_inverse(self, expr: str) -> Optional[Dict[str, Any]]:
        import re
        match = re.search(r'\(x\s*\*\s*0x([0-9a-fA-F]+)\s*\)\s*>>\s*(\d+)', expr)
        if not match:
            return None

        magic_hex = match.group(1)
        shift_bits = int(match.group(2

        
        try:
            magic_constant = int(magic_hex, 16)
        except ValueError:
            return None

        magic_info = self._magic_recognizer.recognize(magic_constant)
        if magic_info and magic_info.get("operation") == "division":
            divisor = magic_info["divisor"]
            return {
                "pattern": ObfuscationPattern.MULTIPLICATIVE_INVERSE,
                "simplified": f"x / {divisor}",
                "magic_numbers": [magic_constant]
            }

        divisor = self._smt_resolver.solve_division_inverse(magic_constant)
        if divisor:
            return {
                "pattern": ObfuscationPattern.MULTIPLICATIVE_INVERSE,
                "simplified": f"x / {divisor}",
                "magic_numbers": [magic_constant]
            }

        return None

    def _detect_bit_rotation(self, expr: str) -> Optional[Dict[str, Any]]:
        import re
        match = re.search(r'\(\(x\s*<<\s*(\d+)\)\s*\|\s*\(x\s*>>\s*(\d+)\)\)', expr)
        if match:
            left_shift = int(match.group(1

            right_shift = int(match.group(2

            if left_shift + right_shift == 32:
                return {
                    "pattern": ObfuscationPattern.BIT_ROTATION,
                    "simplified": f"ROL(x, {left_shift})",
                    "magic_numbers": []
                }

        match = re.search(r'\(\(x\s*>>\s*(\d+)\)\s*\|\s*\(x\s*<<\s*(\d+)\)\)', expr)
        if match:
            right_shift = int(match.group(1

            left_shift = int(match.group(2

            if left_shift + right_shift == 32:
                return {
                    "pattern": ObfuscationPattern.BIT_ROTATION,
                    "simplified": f"ROR(x, {right_shift})",
                    "magic_numbers": []
                }

        return None

    def _detect_xor_cipher(self, expr: str) -> Optional[Dict[str, Any]]:
        import re
        match = re.search(r'x\s*\^\s*0x([0-9a-fA-F]+)', expr)
        if match:
            key = int(match.group(1), 16)
            return {
                "pattern": ObfuscationPattern.XOR_CIPHER,
                "simplified": f"XOR(x, 0x{key:x})",
                "magic_numbers": [key]
            }
        return None

    def _detect_additive_chain(self, expr: str) -> Optional[Dict[str, Any]]:
        import re
        terms = re.findall(r'(?:x\s*<<\s*\d+)|(?:0x[0-9a-fA-F]+)|(?:\d+)', expr)
        if len(terms) >= 3 and all('<<' in t or t.startswith('0x') or t.isdigit() for t in terms):
            return {
                "pattern": ObfuscationPattern.ADDITIVE_CHAIN,
                "simplified": f"complex_expression({len(terms)} terms)",
                "magic_numbers": []
            }
        return None

    def batch_deobfuscate(self, expressions: List[str]) -> List[DeobfuscationResult]:
        return [self.deobfuscate(expr) for expr in expressions]

    def analyze_code(self, code: bytes) -> Dict[str, Any]:
        magic_numbers = self._magic_recognizer.find_magic_numbers(code)
        return {
            "magic_numbers": magic_numbers,
            "count": len(magic_numbers)
        }


_global_deobfuscator: Optional[ConstantDeobfuscator] = None


def get_deobfuscator() -> ConstantDeobfuscator:
    global _global_deobfuscator
    if _global_deobfuscator is None:
        _global_deobfuscator = ConstantDeobfuscator()
    return _global_deobfuscator


def deobfuscate_expression(expr: str) -> DeobfuscationResult:
    deobfuscator = get_deobfuscator()
    return deobfuscator.deobfuscate(expr)))))))))))))))))))