"""
区间边界分析器 — 对堆写入的索引/偏移变量做抽象解释 (Cousot-style).

guard_inference 提取显式边界检查, 但很多边界信息隐含在计算中.
用区间抽象解释推导索引变量的可达取值范围, 与分配大小比较过滤误报.
方法: 识别定义点 → 正向追踪运算 → loop widening → 范围判定.
"""

from __future__ import annotations
from dataclasses import dataclass, field
import re
from typing import Optional
@dataclass
class ValueRange:
    """整数变量的取值区间。"""
    lo: float = float('-inf')
    hi: float = float('inf')
    is_top: bool = True        # 未知 (unbounded)
    is_bottom: bool = False    # 矛盾 (不可达)

    @staticmethod
    def bottom() -> "ValueRange":
        r = ValueRange()
        r.is_top = False
        r.is_bottom = True
        return r

    @staticmethod
    def constant(v: int) -> "ValueRange":
        r = ValueRange(lo=float(v), hi=float(v))
        r.is_top = False
        return r

    @staticmethod
    def interval(lo: int, hi: int) -> "ValueRange":
        r = ValueRange(lo=float(lo), hi=float(hi))
        r.is_top = False
        return r

    def is_within(self, lo: int, hi: int) -> bool:
        """区间 ⊆ [lo, hi) 则True."""
        if self.is_top:
            return False
        if self.is_bottom:
            return True  # 矛盾区间 → 不可达, 视为安全
        return self.lo >= lo and self.hi < hi

    def is_outside(self, lo: int, hi: int) -> bool:
        """区间 ∩ [lo, hi) = ∅ 则True."""
        if self.is_top or self.is_bottom:
            return False
        return self.hi < lo or self.lo >= hi

    def widen(self, other: "ValueRange") -> "ValueRange":
        """Widening 操作符——确保不动点迭代终止。"""
        if self.is_top or other.is_top:
            return ValueRange()
        if self.is_bottom:
            return other
        if other.is_bottom:
            return self
        r = ValueRange()
        r.is_top = False
        r.lo = min(self.lo, other.lo)
        r.hi = max(self.hi, other.hi)
        return r

    def add(self, other: "ValueRange") -> "ValueRange":
        if self.is_top or other.is_top:
            return ValueRange()
        if self.is_bottom or other.is_bottom:
            return ValueRange.bottom()
        return ValueRange.interval(
            int(self.lo + other.lo), int(self.hi + other.hi))

    def multiply(self, other: "ValueRange") -> "ValueRange":
        if self.is_top or other.is_top:
            return ValueRange()
        if self.is_bottom or other.is_bottom:
            return ValueRange.bottom()
        prods = [
            self.lo * other.lo, self.lo * other.hi,
            self.hi * other.lo, self.hi * other.hi,
        ]
        return ValueRange.interval(int(min(prods)), int(max(prods)))

    def __repr__(self):
        if self.is_top:
            return "⊤"
        if self.is_bottom:
            return "⊥"
        return f"[{self.lo},{self.hi}]"

@dataclass
class IndexVarState:
    """单个索引变量在所有位置上的区间状态。"""
    var_name: str
    range_at_line: dict[int, ValueRange] = field(default_factory=dict)

    def get_range(self, line: int) -> ValueRange:
        return self.range_at_line.get(line, ValueRange())

class IntervalBoundsAnalyzer:
    """区间边界分析器 — 在 malloc→store 的IR窗口内正向区间抽象解释, 复杂度O(window_size)."""

    _ASSIGN_PAT = re.compile(r'(\w+)\s*=\s*(.+)')
    _ARITH_PAT = re.compile(r'(\w+)\s*([+\-*/])\s*(\w+|\d+)')
    _LOOP_INIT_PAT = re.compile(
        r'(?:for|while)\s*\(\s*\w+\s+(\w+)\s*=\s*(\d+)\s*;',
        re.IGNORECASE,
    )
    _LOOP_COND_PAT = re.compile(
        r'(\w+)\s*[<>]=?\s*(\d+)|(\d+)\s*[<>]=?\s*(\w+)',
    )
    _LOOP_INCR_PAT = re.compile(r'(\w+)\s*\+\+|(\w+)\s*\+=\s*(\d+)')

    def __init__(self):
        self._states: dict[str, IndexVarState] = {}

    def analyze_window(self, ir_lines: list[str],
                       alloc_pc: int, store_pc: int,
                       index_var: str) -> ValueRange:
        """在 malloc→store 窗口内追踪 index_var 的区间."""
        current_range = ValueRange()  # 初始 ⊤ (未初始化)

        start = max(0, alloc_pc)
        end = min(len(ir_lines), store_pc + 1)

        for i in range(start, end):
            line = ir_lines[i].strip()

            # 检查是否是对 index_var 的赋值
            new_range = self._handle_assignment(line, index_var, i, ir_lines)
            if new_range is not None:
                current_range = new_range
                continue

            # loop 检测: 若 index_var 出现在循环条件中
            loop_bound = self._detect_loop_bound(line, index_var)
            if loop_bound is not None and not current_range.is_top:
                # 循环内变量上界不超过循环边界
                bounded = ValueRange.interval(
                    max(0, int(current_range.lo)),
                    min(loop_bound - 1, int(current_range.hi))
                    if current_range.hi != float('inf') else loop_bound - 1,
                )
                current_range = bounded

        return current_range

    def _handle_assignment(self, line: str, target_var: str,
                           line_no: int, ir_lines: list[str]) -> Optional[ValueRange]:
        """处理赋值语句, 若目标匹配则返回新区间。"""
        m = self._ASSIGN_PAT.search(line)
        if not m:
            return None
        lhs = m.group(1)
        rhs = m.group(2).strip()

        # 过滤掉无关的赋值: 变量名不同且不是我们的目标
        lhs_base = re.sub(r'^(?:e|r)?', '', lhs.lower())
        tgt_base = re.sub(r'^(?:e|r)?', '', target_var.lower())

        if lhs_base != tgt_base and lhs.lower() != target_var.lower():
            return None

        # 常量赋值: i = 0
        const_m = re.match(r'^(?:0x)?([0-9a-fA-F]+)$', rhs)
        if const_m:
            return ValueRange.constant(int(const_m.group(1), 0))

        # 算术: i + 1, i * 2
        arith_m = self._ARITH_PAT.search(rhs)
        if arith_m:
            return self._eval_arithmetic(arith_m, target_var, line_no)

        # 函数调用: min(i, N), rand()
        min_m = re.search(r'min\s*\(\s*\w+\s*,\s*(\d+)\s*\)', rhs, re.IGNORECASE)
        if min_m:
            return ValueRange.interval(0, int(min_m.group(1)))

        # sizeof / strlen 等 → 无法确定具体值, 但至少 ≥0
        if any(f in rhs.lower() for f in ('sizeof', 'strlen', 'wcslen')):
            return ValueRange.interval(0, 65536)

        return None

    def _eval_arithmetic(self, m, target_var: str,
                         line_no: int) -> ValueRange:
        """求算术表达式的区间结果。"""
        op1 = m.group(1)
        op = m.group(2)
        op2 = m.group(3)

        def _parse_op(x: str) -> ValueRange:
            try:
                return ValueRange.constant(int(x, 0))
            except (ValueError, TypeError):
                previous = self._get_previous_range(x, line_no)
                if previous is not None:
                    return previous
                return ValueRange()

        r1 = _parse_op(op1)
        r2 = _parse_op(op2)

        if op == '+':
            return r1.add(r2)
        elif op == '-':
            neg_r2 = ValueRange.interval(-int(r2.hi), -int(r2.lo))
            return r1.add(neg_r2)
        elif op == '*':
            return r1.multiply(r2)

        return ValueRange()

    def _get_previous_range(self, var_name: str,
                            before_line: int) -> Optional[ValueRange]:
        """获取变量在指定行之前的最近区间值。"""
        state = self._states.get(var_name)
        if state is None:
            return None
        best_line = -1
        best_range = None
        for ln, r in state.range_at_line.items():
            if ln < before_line and ln > best_line:
                best_line = ln
                best_range = r
        return best_range

    def _detect_loop_bound(self, line: str, index_var: str) -> Optional[int]:
        """检测循环上界: for(i=0; i<N; i++), 提取 N。"""
        idx_base = re.sub(r'^(?:e|r)?', '', index_var.lower())

        # 模式: i < N
        m1 = re.search(
            rf'({re.escape(index_var)}|{re.escape(idx_base)})\s*[<]\s*(\d+)',
            line, re.IGNORECASE,
        )
        if m1:
            return int(m1.group(2))

        # 模式: i <= N (上界 = N+1)
        m2 = re.search(
            rf'({re.escape(index_var)}|{re.escape(idx_base)})\s*[≤<=]\s*(\d+)',
            line, re.IGNORECASE,
        )
        if m2 and '<=' in line:
            return int(m2.group(2)) + 1

        return None

    def check_safety(self, write_range: ValueRange,
                     alloc_size: int) -> tuple[bool, str]:
        """根据写操作索引区间判断安全性, 返回 (is_safe, reason)."""
        if write_range.is_top:
            return False, "index range unknown (⊤)"

        if write_range.is_bottom:
            return True, "index range ⊥ (unreachable)"

        if write_range.is_within(0, alloc_size):
            return True, (
                f"index range {write_range} ⊆ [0,{alloc_size})"
            )

        if write_range.is_outside(0, alloc_size):
            return False, (
                f"index range {write_range} ∩ [0,{alloc_size}) = ∅, "
                f"but variant could still exceed"
            )

        return False, (
            f"index range {write_range} overlaps but not contained"
            f" in [0,{alloc_size})"
        )

def analyze_index_bounds(ir_lines: list[str], alloc_pc: int,
                         store_pc: int, index_var: str,
                         alloc_size: int) -> dict:
    """便捷接口: 一行完成区间分析。"""
    analyzer = IntervalBoundsAnalyzer()
    rng = analyzer.analyze_window(ir_lines, alloc_pc, store_pc, index_var)
    safe, reason = analyzer.check_safety(rng, alloc_size)
    return {
        'range': str(rng),
        'is_safe': safe,
        'reason': reason,
        'lo': rng.lo if not rng.is_top and not rng.is_bottom else None,
        'hi': rng.hi if not rng.is_top and not rng.is_bottom else None,
    }

__all__ = ['ValueRange', 'IntervalBoundsAnalyzer', 'analyze_index_bounds']
