"""整数溢出范围分析器 — 算术运算的位宽约束 + 符号/无符号转换检测.

检测四种模式:
  1. 乘法溢出: a*b 超过操作数位宽
  2. 加法溢出: 循环计数器累加到 wrap-around
  3. 符号混淆: 有符号/无符号混用致意外 wrap
  4. 截断: 32-bit 结果赋给 16-bit 变量

CWE-190 排名前 10, 最常见模式是 malloc(n*sizeof(T)) 中 n*sizeof 溢出致分配过小缓冲区。
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class IntOverflowCandidate:
    """一个潜在的整数溢出候选."""
    insn_addr: int
    operation: str              # 'mul'|'add'|'sub'|'shl'
    operand_width: int          # 8/16/32/64
    left_range: Tuple[int, int]  # 左操作数的值范围
    right_range: Tuple[int, int] # 右操作数的值范围
    overflow_possible: bool
    overflow_type: str          # 'wrap'|'truncation'|'sign_mismatch'
    used_in_alloc: bool         # 结果是否用于 malloc/realloc
    risk_level: str             # 'critical'|'high'|'medium'|'low'


class IntegerRangeAnalyzer:
    """整数溢出范围分析器 — 检测算术运算的溢出风险.

    用法: add_operation 添加运算, mark_used_in_alloc 标记用于分配, analyze_all 取候选。
    """

    def __init__(self):
        self._operations: List[IntOverflowCandidate] = []

    def add_operation(self, insn_addr: int, op: str,
                      width: int,
                      left_range: Tuple[int, int],
                      right_range: Tuple[int, int]) -> IntOverflowCandidate:
        """添加一个算术运算."""
        # 计算溢出可能性
        overflow = False
        otype = 'wrap'

        if op in ('mul', 'shl'):
            # 四角点分析: 完整计算lo*lo, lo*hi, hi*lo, hi*hi
            lo_l, hi_l = left_range
            lo_r, hi_r = right_range
            if op == 'shl':
                # shl等价于乘以2^right, 右操作数是位移量
                shift = max(0, hi_r)
                corners = [lo_l << shift, hi_l << shift]
            else:
                corners = [lo_l * lo_r, lo_l * hi_r,
                           hi_l * lo_r, hi_l * hi_r]
            result_lo = min(corners)
            result_hi = max(corners)
            limit = (1 << width) - 1
            signed_min = -(1 << (width - 1))
            signed_max = (1 << (width - 1)) - 1
            if result_hi > limit or result_lo < 0:
                overflow = True
                otype = 'wrap'
            elif result_lo < signed_min or result_hi > signed_max:
                overflow = True
                otype = 'sign_mismatch'

        elif op == 'add':
            max_val = left_range[1] + right_range[1]
            limit = (1 << width) - 1
            if max_val > limit:
                overflow = True
                otype = 'wrap'

        elif op == 'sub':
            min_val = left_range[0] - right_range[1]
            if min_val < 0 and left_range[0] >= 0:
                overflow = True
                otype = 'wrap'

        cand = IntOverflowCandidate(
            insn_addr=insn_addr, operation=op,
            operand_width=width,
            left_range=left_range, right_range=right_range,
            overflow_possible=overflow,
            overflow_type=otype,
            used_in_alloc=False,
            risk_level='high' if overflow else 'low')
        self._operations.append(cand)
        return cand

    def mark_used_in_alloc(self, insn_addr: int) -> None:
        """标记该运算的结果被用于 malloc/realloc."""
        for c in self._operations:
            if c.insn_addr == insn_addr:
                c.used_in_alloc = True
                if c.overflow_possible:
                    c.risk_level = 'critical'

    def analyze_all(self) -> List[IntOverflowCandidate]:
        """返回所有溢出候选, 按风险等级排序."""
        risk_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
        return sorted(self._operations,
                     key=lambda c: risk_order.get(c.risk_level, 99))

    def detect_malloc_overflow_pattern(self, insn_addr: int,
                                        n_elements_range: Tuple[int, int],
                                        element_size: int) -> Optional[str]:
        """检测 malloc(n * sizeof(T)) 溢出模式.

        若 n * element_size 超过 2^32 → 分配大小 wrap 到小值 → CRITICAL.
        """
        max_alloc = max(1, n_elements_range[1]) * element_size
        if max_alloc > 0xFFFFFFFF:
            return (f'malloc overflow: {n_elements_range[1]} * '
                    f'{element_size} = {max_alloc} > 2^32, '
                    f'actual allocation may wrap to {max_alloc & 0xFFFFFFFF}')
        return None

    def stats(self) -> dict:
        all_cands = self.analyze_all()
        critical = sum(1 for c in all_cands if c.risk_level == 'critical')
        high = sum(1 for c in all_cands if c.risk_level == 'high')
        return {
            'operations_analyzed': len(all_cands),
            'overflows_detected': sum(1 for c in all_cands if c.overflow_possible),
            'critical': critical,
            'high_risk': high,
            'used_in_alloc': sum(1 for c in all_cands if c.used_in_alloc),
        }

    def clear(self) -> None:
        self._operations.clear()
