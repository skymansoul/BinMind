# coding: utf-8
"""
整数溢出约束系统 — 将算术溢出编码为范围约束并判定安全影响.

核心洞察: 整数溢出本身不是漏洞, 是溢出后的使用方式决定是否危险.
将溢出→安全影响编码为三阶段约束:
  S1: 算术运算结果 ∈ [MIN_INT, MAX_INT]? (溢出检测)
  S2: 溢出结果是否参与内存分配大小计算? (分配约束)
  S3: 分配后的写入是否受溢出影响? (写约束 — 委托给 heap overflow 管线)

若 S1 不成立 (未溢出) → 安全
若 S2 不成立 (溢出不影响分配大小) → 可能安全 (但标记为其他风险)
若 S1∧S2∧S3 可满足 → 危险 — 保留候选

FP 削减策略 (与 heap overflow 对称):
  L1: 值范围分析 — 使用区间算术证明不溢出
  L2: 下界检查 — 检查溢出后是否有 bounds check
  L3: 约束求解 — 证明溢出后的分配仍足够

  - "IntScope: Automatically Detecting Integer Overflow"
  - "RICH: Automatically Protecting Against Integer-Based Vulnerabilities"
  - "Integer Overflow Detection with Delayed Input"
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Dict, List, Optional, Set, Tuple

class IntWidth(Enum):
    I8 = (8, -128, 127, 255)        # (bits, signed_min, signed_max, unsigned_max)
    I16 = (16, -32768, 32767, 65535)
    I32 = (32, -2147483648, 2147483647, 4294967295)
    I64 = (64, -9223372036854775808, 9223372036854775807, 18446744073709551615)

    @property
    def signed_range(self) -> Tuple[int, int]:
        return (self.value[1], self.value[2])

    @property
    def unsigned_range(self) -> Tuple[int, int]:
        return (0, self.value[3])

class OverflowType(Enum):
    NONE = auto()       # 未溢出
    WRAP_SIGNED = auto()    # 有符号回绕 (UB in C)
    WRAP_UNSIGNED = auto()  # 无符号回绕 (well-defined)
    TRUNCATION = auto()     # 截断 (赋值给更窄类型)
    SIGNED_OVERFLOW = auto()  # 有符号溢出 (UB)

@dataclass
class IntOperation:
    """一次整数算术运算."""
    op: str                  # 'add'|'sub'|'mul'|'shl'|'trunc'
    left: str                # 左操作数 (变量名或常量)
    right: str               # 右操作数
    width: IntWidth = IntWidth.I32
    signed: bool = False     # 有符号还是无符号

@dataclass
class OverflowResult:
    """整数溢出分析结果."""
    operation: IntOperation
    overflow_type: OverflowType
    result_range: Tuple[int, int]   # 溢出后结果的可能范围
    normal_range: Tuple[int, int]   # 不溢出时的结果范围
    is_dangerous: bool              # 是否影响后续内存操作

class IntRangeAnalyzer:
    """整数范围分析器 — 使用区间算术检测溢出.

    对每个算术运算:
      1. 计算操作数的值区间
      2. 计算结果的区间 (考虑溢出回绕)
      3. 检查结果是否在类型范围内
      4. 若溢出, 评估对后续内存操作的影响
    """

    def __init__(self, width: IntWidth = IntWidth.I32):
        self.width = width
        self._var_ranges: Dict[str, Tuple[int, int]] = {}

    def set_range(self, var: str, lo: int, hi: int):
        self._var_ranges[var] = (lo, hi)

    def analyze_operation(self, op: IntOperation) -> OverflowResult:
        """分析一次算术运算."""
        # 解析操作数
        left_lo, left_hi = self._resolve(op.left)
        right_lo, right_hi = self._resolve(op.right)

        signed = op.signed
        if signed:
            min_val, max_val = self.width.signed_range
        else:
            min_val, max_val = self.width.unsigned_range

        # 计算结果区间
        if op.op == 'add':
            lo = left_lo + right_lo
            hi = left_hi + right_hi
        elif op.op == 'sub':
            lo = left_lo - right_hi
            hi = left_hi - right_lo
        elif op.op == 'mul':
            corners = [
                left_lo * right_lo, left_lo * right_hi,
                left_hi * right_lo, left_hi * right_hi,
            ]
            lo, hi = min(corners), max(corners)
        elif op.op == 'shl':
            lo = left_lo << right_lo
            hi = left_hi << right_hi
        else:
            lo, hi = left_lo, left_hi

        # 检测溢出
        normal_lo = max(lo, min_val)
        normal_hi = min(hi, max_val)

        if lo < min_val or hi > max_val:
            if signed:
                otype = OverflowType.SIGNED_OVERFLOW
            else:
                # 无符号回绕
                if op.op == 'trunc':
                    otype = OverflowType.TRUNCATION
                else:
                    otype = OverflowType.WRAP_UNSIGNED

            # 回绕后的结果范围
            span = max_val - min_val + 1
            wrap_lo = lo % span
            wrap_hi = hi % span
            if wrap_lo <= wrap_hi:
                result_range = (wrap_lo, wrap_hi)
            else:
                result_range = (0, max_val)  # 回绕覆盖整个范围
        else:
            otype = OverflowType.NONE
            result_range = (normal_lo, normal_hi)

        is_dangerous = (otype != OverflowType.NONE and
                        otype != OverflowType.WRAP_UNSIGNED)

        return OverflowResult(
            operation=op,
            overflow_type=otype,
            result_range=result_range,
            normal_range=(normal_lo, normal_hi),
            is_dangerous=is_dangerous,
        )

    def _resolve(self, operand: str) -> Tuple[int, int]:
        """解析操作数为值区间."""
        try:
            val = int(operand)
            return (val, val)
        except ValueError:
            return self._var_ranges.get(operand, (0, 2**20))

def detect_int_overflow(operations: List[IntOperation],
                        known_ranges: Dict[str, Tuple[int, int]],
                        alloc_sites: Dict[str, int] = None,
                        ) -> List[Dict]:
    """检测整数溢出候选并判定安全影响。

    参数: operations 算术运算列表, known_ranges 已知变量值区间
    {var_name: (lo, hi)}, alloc_sites 分配点 {var_name:
    alloc_size} (用于判定安全影响);
    返回溢出候选列表 [{op, overflow_type, is_dangerous, ...}]。
    """
    if alloc_sites is None:
        alloc_sites = {}

    analyzer = IntRangeAnalyzer()
    for var, rng in known_ranges.items():
        analyzer.set_range(var, rng[0], rng[1])

    candidates = []
    for op in operations:
        result = analyzer.analyze_operation(op)

        if result.overflow_type == OverflowType.NONE:
            continue

        # 评估安全影响
        alloc_var = f'alloc_{op.left}'
        is_dangerous = result.is_dangerous
        if alloc_var in alloc_sites:
            alloc_sz = alloc_sites[alloc_var]
            # 若溢出后的结果区间上界 <= 分配大小 → 安全
            if result.result_range[1] <= alloc_sz:
                is_dangerous = False

        candidates.append({
            'operation': f'{op.left} {op.op} {op.right}',
            'width': op.width.name,
            'overflow_type': result.overflow_type.name,
            'result_range': result.result_range,
            'normal_range': result.normal_range,
            'is_dangerous': is_dangerous,
            'signed': op.signed,
        })

    return candidates

def prove_int_overflow_safe(
    left_var: str, right_val: int, op_type: str,
    known_range: Tuple[int, int],
    alloc_size: int = 0,
    width: IntWidth = IntWidth.I32,
) -> Tuple[bool, str]:
    """便捷判定: 证明一次算术运算不会导致可利用的溢出, 返回 (可证明安全 → True, 理由)。"""
    analyzer = IntRangeAnalyzer(width=width)
    analyzer.set_range(left_var, known_range[0], known_range[1])

    io = IntOperation(
        op=op_type, left=left_var, right=str(right_val),
        width=width, signed=True,
    )
    result = analyzer.analyze_operation(io)

    if result.overflow_type == OverflowType.NONE:
        return True, '未溢出'

    if not result.is_dangerous:
        return True, f'溢出类型 {result.overflow_type.name} 不可利用'

    if alloc_size > 0 and result.result_range[1] <= alloc_size:
        return True, (
            f'溢出后上界 {result.result_range[1]} <= 分配大小 {alloc_size}')

    return False, (
        f'{result.overflow_type.name}: 结果范围 {result.result_range}, '
        f'可能影响内存安全')
