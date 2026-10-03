# 路径敏感的堆溢出约束收集 — 沿回溯路径收集guard条件，淘汰不可行告警路径
"""路径敏感的堆溢出约束分析器。

当前alloc_size_tracker只做反向污点追踪，不关心路径可行性。
本模块在反向追踪时同步收集路径守卫条件(guard conditions)，
在判定溢出可能性前先检验路径是否可行。

方法:
  1. 从malloc调用点反向追踪到污点源，沿途记录所有cmp+jcc条件
  2. 将条件转化为对size变量的区间约束
  3. 若约束集矛盾（如 size<16 AND size>1024）→ 路径不可行 → FP
  4. 若约束收窄了size范围 → 更新区间边界 → 更精确的溢出判定

Guard收集器独立于本模块(见heap_guard_collector.py)，
这里只保留可行性检查器和路径感知的溢出分析器。

  - Bootstrap: path-sensitive static analysis via abstract interpretation
  - DeltaFuzz: guard condition collection for seed mutation
"""

import logging
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from enum import Enum

_log = logging.getLogger(__name__)

class GuardKind(Enum):
    """路径守卫的类型。"""
    CMP_JA = "cmp_ja"        # cmp a, b; ja → a > b (unsigned above)
    CMP_JBE = "cmp_jbe"      # cmp a, b; jbe → a <= b
    CMP_JG = "cmp_jg"        # cmp a, b; jg → a > b (signed)
    CMP_JLE = "cmp_jle"      # cmp a, b; jle → a <= b
    CMP_JE = "cmp_je"        # cmp a, b; je → a == b
    CMP_JNE = "cmp_jne"      # cmp a, b; jne → a != b
    TEST_JZ = "test_jz"      # test a, a; jz → a == 0
    TEST_JNZ = "test_jnz"    # test a, a; jnz → a != 0
    AND_MASK = "and_mask"    # and reg, mask → reg ∈ [0, mask]

@dataclass
class GuardCondition:
    """单个路径守卫条件。

    例如: GuardCondition(reg='rax', kind=GuardKind.CMP_JBE, bound=256)
          含义: rax <= 256 时此路径才可达
    """
    reg: str = ""
    kind: GuardKind = GuardKind.CMP_JBE
    bound: int = 0
    line: int = 0
    is_signed: bool = False

    def to_interval(self) -> Tuple[int, int]:
        """将守卫条件转化为对目标寄存器的区间约束。"""
        MAX_INT = 2**63 - 1
        if self.kind == GuardKind.CMP_JBE:
            return (0, self.bound)
        elif self.kind == GuardKind.CMP_JA:
            return (self.bound + 1, MAX_INT)
        elif self.kind == GuardKind.CMP_JLE:
            return (-MAX_INT, self.bound)
        elif self.kind == GuardKind.CMP_JG:
            return (self.bound + 1, MAX_INT)
        elif self.kind == GuardKind.CMP_JE:
            return (self.bound, self.bound)
        elif self.kind == GuardKind.CMP_JNE:
            return (-MAX_INT, MAX_INT)
        elif self.kind == GuardKind.TEST_JZ:
            return (0, 0)
        elif self.kind == GuardKind.TEST_JNZ:
            return (1, MAX_INT)
        elif self.kind == GuardKind.AND_MASK:
            return (0, self.bound)
        return (0, MAX_INT)

@dataclass
class PathFeasibilityResult:
    """路径可行性分析结果。"""
    is_feasible: bool = True
    effective_lower: int = 0
    effective_upper: int = 2**63 - 1
    guards: List[GuardCondition] = field(default_factory=list)
    conflicting_guards: List[Tuple[GuardCondition, GuardCondition]] = field(default_factory=list)
    reason: str = ""

# 路径可行性检查器

class PathFeasibilityChecker:
    """检查guard条件集是否自洽（路径是否可行）。

    算法: 对每个guard条件转化为区间约束，所有guard的交集 = 有效区间。
    若交集为空（lower > upper）→ 路径不可行 → 该告警为FP。
    复杂度: O(n) where n = guard数量（通常 < 10）
    """

    def check(self, guards: List[GuardCondition],
              base_lower: int = 0,
              base_upper: int = 2**63 - 1) -> PathFeasibilityResult:
        result = PathFeasibilityResult(
            effective_lower=base_lower, effective_upper=base_upper,
            guards=guards)

        current_lower = base_lower
        current_upper = base_upper

        for guard in guards:
            g_low, g_high = guard.to_interval()
            new_lower = max(current_lower, g_low)
            new_upper = min(current_upper, g_high)

            if new_lower > new_upper:
                result.is_feasible = False
                result.conflicting_guards.append(
                    (guard, GuardCondition(
                        reg=guard.reg, kind=GuardKind.CMP_JBE,
                        bound=current_upper if current_upper < g_low else current_lower)))
                result.reason = (
                    f"约束矛盾: {guard.reg} ∈ [{g_low},{g_high}] "
                    f"与已有约束[{current_lower},{current_upper}]冲突")
                return result

            current_lower = new_lower
            current_upper = new_upper

        result.effective_lower = current_lower
        result.effective_upper = current_upper

        if current_upper < base_upper * 0.1 and current_upper > 0:
            result.reason = (
                f"路径条件将size约束从[{base_lower},{base_upper}] "
                f"收窄至[{current_lower},{current_upper}]")
        elif not guards:
            result.reason = "无路径守卫条件"

        return result

# 路径感知的溢出判定增强器

class PathAwareOverflowAnalyzer:
    """将路径可行性分析集成到溢出判定流程中。

    扩展OverflowSatisfiabilitySolver的能力：
      原: alloc_size区间 vs write_size → 溢出可能性
      新: 先做路径可行性检查，若不可行 → 强制标记为FP
          若可行但区间收窄 → 用收窄后的区间重新判定
    """

    def __init__(self):
        from .heap_guard_collector import PathGuardCollector
        self._guard_collector = PathGuardCollector()
        self._feasibility_checker = PathFeasibilityChecker()

    def analyze(self, asm_lines: List[str],
                alloc_line: int, size_reg: str, write_size: int,
                base_lower: int = 0,
                base_upper: int = 2**31 - 1) -> Dict:
        """执行路径感知的堆溢出分析。

        返回:
          {
            'path_feasible': bool,
            'effective_bounds': (low, high),
            'overflow_possible': bool,
            'overflow_certain': bool,
            'fp_confidence': float,
            'reason': str,
            'guards_collected': int,
          }
        """
        # 守卫可能在malloc之前较远(如FP002: guard在alloc前20行)
        # 向后扩展至50行覆盖跨基本块的cmp+jcc模式
        # 约束: 仅在同一函数内收集守卫, 避免跨函数寄存器别名污染
        from .heap_dataflow import parse_function_bounds, line_function
        func_bounds = parse_function_bounds(asm_lines)
        alloc_func = line_function(alloc_line, func_bounds)
        # 找到alloc所在函数的起止行
        func_start = alloc_line
        func_end = alloc_line
        for _li in range(alloc_line, -1, -1):
            if line_function(_li, func_bounds) == alloc_func:
                func_start = _li
            else:
                break
        for _li in range(alloc_line, len(asm_lines)):
            if line_function(_li, func_bounds) == alloc_func:
                func_end = _li
            else:
                break
        raw_start = max(alloc_line - 50, func_start)
        raw_end = min(alloc_line + 8, func_end)
        trace_window = (raw_start, raw_end)
        guards = self._guard_collector.collect(asm_lines, size_reg, trace_window)
        feasibility = self._feasibility_checker.check(guards, base_lower, base_upper)

        if not feasibility.is_feasible:
            return {
                'path_feasible': False,
                'effective_bounds': (feasibility.effective_lower,
                                     feasibility.effective_upper),
                'overflow_possible': False, 'overflow_certain': False,
                'fp_confidence': 0.95,
                'reason': f"路径不可行: {feasibility.reason}",
                'guards_collected': len(guards),
            }

        eff_lower, eff_upper = feasibility.effective_lower, feasibility.effective_upper
        overflow_certain = eff_upper < write_size
        overflow_impossible = eff_lower >= write_size
        overflow_possible = not overflow_impossible

        if overflow_certain:
            fp_conf, reason = 0.05, (
                f"有效区间[{eff_lower},{eff_upper}] < 写入{write_size} → 必定溢出")
        elif overflow_impossible:
            fp_conf, reason = 0.95, (
                f"有效区间[{eff_lower},{eff_upper}] >= 写入{write_size} → 不溢出")
        else:
            fp_conf, reason = 0.40, (
                f"有效区间[{eff_lower},{eff_upper}]与写入{write_size}重叠 → 可能溢出")

        if feasibility.effective_upper < base_upper:
            reason += f" (路径约束收窄: {base_upper}→{eff_upper})"

        return {
            'path_feasible': True,
            'effective_bounds': (eff_lower, eff_upper),
            'overflow_possible': overflow_possible,
            'overflow_certain': overflow_certain,
            'fp_confidence': fp_conf,
            'reason': reason,
            'guards_collected': len(guards),
        }

