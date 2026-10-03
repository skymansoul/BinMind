"""
整数溢出→堆溢出检测 — 乘法溢出导致分配不足的静态分析 (CWE-190 → CWE-122)。
count*sizeof(T) 溢出为小值时 malloc 分配不足, 后续写入越界; 本模块追溯到乘法根因。
"""

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
import re


@dataclass
class MulOverflowCandidate:
    func_name: str
    expression: str       # 可疑的乘法表达式
    operand1_bits: int    # 操作数1的位宽估计
    operand2_bits: int    # 操作数2的位宽估计
    max_product_bits: int  # 最大乘积位宽
    overflows_at: Optional[int]  # 操作数多大时会溢出
    confidence: float


class IntOverflowDetector:
    """
    整数溢出检测器 —— 关注乘法溢出导致分配不足的模式。

    不实现完整的整数范围分析 (那需要 SMT solver),
    仅做启发式位宽估计 + 溢出阈值计算。
    """

    _MUL_PAT = re.compile(
        r'(?:size_t|int|unsigned|uint\d+_t|long)\s+(\w+)\s*=\s*'
        r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)'
    )
    _MUL_VAR_PAT = re.compile(
        r'(\w[\w\d_]*)\s*=\s*(\w[\w\d_]*)\s*\*\s*(\w[\w\d_]*)'
    )
    _MALLOC_AFTER_PAT = re.compile(
        r'malloc\s*\(\s*(\w+)\s*\)'
    )
    _MEMCPY_AFTER_PAT = re.compile(
        r'memcpy\s*\([^,]+,\s*[^,]+,\s*(\w+)\s*\*\s*sizeof'
    )

    # 常见类型的 sizeof 值 (x86_64)
    _SIZEOF_MAP = {
        'int': 4, 'unsigned': 4, 'long': 8, 'size_t': 8,
        'char': 1, 'short': 2, 'double': 8, 'void': 1,
        'struct': 16, 'ptr': 8, 'pointer': 8,
    }

    def detect(self, pseudocode: str, func_name: str = "") -> List[MulOverflowCandidate]:
        candidates: List[MulOverflowCandidate] = []

        for m in self._MUL_PAT.finditer(pseudocode):
            result_var = m.group(1)
            count_var = m.group(2)
            type_name = m.group(3)
            sizeof_val = self._SIZEOF_MAP.get(type_name, 8)

            alloc_match = re.search(
                rf'(?:malloc|calloc)\s*\(\s*{re.escape(result_var)}\s*\)',
                pseudocode[m.end():m.end() + 300],
            )
            if not alloc_match:
                continue

            # 估计溢出阈值: count * sizeof > SIZE_MAX → count > SIZE_MAX/sizeof
            max_count = (2**64 - 1) // sizeof_val if sizeof_val > 0 else 0

            candidates.append(MulOverflowCandidate(
                func_name=func_name,
                expression=m.group(0),
                operand1_bits=64,
                operand2_bits=sizeof_val * 8,
                max_product_bits=64 + sizeof_val * 8,
                overflows_at=max_count,
                confidence=0.75 if max_count < 2**31 else 0.50,
            ))

        for m in self._MUL_VAR_PAT.finditer(pseudocode):
            rvar = m.group(1)
            op_a = m.group(2)
            op_b = m.group(3)

            if not re.search(rf'malloc\s*\(\s*{re.escape(rvar)}\s*\)', pseudocode):
                continue

            candidates.append(MulOverflowCandidate(
                func_name=func_name,
                expression=m.group(0),
                operand1_bits=32,
                operand2_bits=32,
                max_product_bits=64,
                overflows_at=2**31,
                confidence=0.45,
            ))

        return candidates


__all__ = ['MulOverflowCandidate', 'IntOverflowDetector']
