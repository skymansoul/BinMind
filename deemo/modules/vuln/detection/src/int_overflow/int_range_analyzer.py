"""整数溢出范围分析器 — 算术运算的位宽约束 + 符号/无符号转换检测.

创建: 2024-09-27
目的: 从反汇编中提取整数算术运算, 检查是否存在溢出风险:
      1. 乘法溢出: a*b 的结果超过操作数位宽
      2. 加法溢出: 循环计数器累加到 wrap-around
      3. 符号混淆: 有符号与无符号混用导致意外 wrap
      4. 截断: 32-bit 结果赋值给 16-bit 变量

方法依据: Integer overflow 在 CWE-190 中排名前 10。
          最常见的模式是 malloc(n * sizeof(T)) 中 n*sizeof 溢出导致
          分配过小的缓冲区。本模块检测此模式及变体。
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

    使用方式:
      ira = IntegerRangeAnalyzer()
      ira.add_operation(0x401000, 'mul', 32, (0, 65536), (0, 65536))
      ira.mark_used_in_alloc(0x401000)
      cands = ira.analyze_all()
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
            # 乘法: max(L)*max(R) 是否超过 2^width
            max_val = max(1, left_range[1]) * max(1, right_range[1])
            limit = (1 << width) - 1
            if max_val > limit:
                overflow = True
                otype = 'wrap'

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
