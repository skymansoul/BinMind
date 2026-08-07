"""
分配大小约束收集器 — 从malloc调用点向上游追溯size变量的数值约束.

与 guard_condition_analyzer 的互补关系:
  - guard_condition_analyzer: 从store向下游找 idx < N 守卫
  - 本模块: 从malloc向上游找 size ≤ MAX 约束
  两者共同覆盖"守卫在分配侧"和"守卫在写入侧"两类FP模式.

核心FP模式: 以下代码被误报但实际安全:
  if (user_size > MAX_SIZE) user_size = MAX_SIZE;  // ← 约束
  buf = malloc(user_size);                          // ← 分配
  memcpy(buf, src, user_size);                     // ← 写入

现有检测器看到 user_size 是变量 → 保守标记为溢出.
本模块识别 user_size ≤ MAX_SIZE 约束 → 证明安全 (memcpy大小 ≤ 分配大小).

方法: 从malloc行向上游扫描N行, 收集约束条件+赋值+clamp模式.
使用区间代数取交集得到size变量的紧致范围.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple


@dataclass
class SizeVarConstraint:
    """size变量的单条约束记录."""
    var: str
    op: str           # '<' | '<=' | '>' | '>=' | '==' | '='
    value: int
    source_line: int
    source_text: str
    constraint_type: str  # 'guard_upper' | 'guard_lower' | 'assign' | 'clamp' | 'min/max'


@dataclass
class SizeVarSummary:
    """size变量的约束摘要 — 所有约束的交集."""
    var: str
    lo: int = -(2**31)
    hi: int = 2**31 - 1
    constraints: List[SizeVarConstraint] = field(default_factory=list)
    is_proved_bounded: bool = False  # 能否证明上界存在

    @property
    def effective_range(self) -> Tuple[int, int]:
        return (self.lo, self.hi)

    @property
    def is_constant(self) -> bool:
        return self.lo == self.hi and self.lo > -(2**31)


class SizeConstraintCollector:
    """从malloc调用点向上游收集size变量约束.

    搜索窗口: malloc行前30行 (覆盖典型函数体内的约束逻辑).
    """

    _CLAMP_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|>=)\s*(\d+|\w+)\s*\)\s*\{?\s*\1\s*=\s*(\d+|\w+)\s*;',
        re.IGNORECASE)
    _GUARD_UPPER_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(<|<=)\s*(\d+)\s*\)', re.IGNORECASE)
    _GUARD_LOWER_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|>=)\s*(\d+)\s*\)', re.IGNORECASE)
    _ASSIGN_RE = re.compile(r'(\w+)\s*=\s*(\d+)\s*;')
    _MIN_RE = re.compile(
        r'(\w+)\s*=\s*(?:min|MIN)\s*\(\s*\w+\s*,\s*(\d+)\s*\)', re.IGNORECASE)
    _MAX_RE = re.compile(
        r'(\w+)\s*=\s*(?:max|MAX)\s*\(\s*\w+\s*,\s*(\d+)\s*\)', re.IGNORECASE)
    _TERNARY_CLAMP_RE = re.compile(
        r'(\w+)\s*=\s*\(\s*\w+\s*>\s*(\d+)\s*\)\s*\?\s*\2\s*:\s*\w+',
        re.IGNORECASE)

    # 已知安全宏: 这些宏本身就表达了上界约束
    _KNOWN_SAFE_MACROS = {
        'BUFSIZ', 'PATH_MAX', 'MAX_PATH', 'MAX_LINE', 'MAX_BUF',
        'PIPE_BUF', 'NAME_MAX', 'ARG_MAX', 'SSIZE_MAX',
        'MAX_ALLOC', 'MAX_SIZE', 'MAX_LEN', 'MAX_BUFFER',
    }

    def __init__(self, search_window: int = 30):
        self._window = search_window

    def collect_for_alloc(
        self, ir_lines: List[str], alloc_pc: int,
        size_var: str, size_value: int = -1,
    ) -> SizeVarSummary:
        """从alloc_pc向上游收集size_var的约束.

        Args:
            ir_lines: IR行列表
            alloc_pc: malloc调用在ir_lines中的索引
            size_var: malloc的size参数变量名 (如 "len", "size")
            size_value: 若已知常量值则传入 (加速), -1=未知

        Returns:
            SizeVarSummary 含所有约束的交集范围
        """
        summary = SizeVarSummary(var=size_var)
        if size_value > 0:
            summary.lo = size_value
            summary.hi = size_value
            summary.is_proved_bounded = True
            return summary

        start = max(0, alloc_pc - self._window)
        context = ir_lines[start:alloc_pc]

        for i_offset, line in enumerate(context):
            actual_pc = start + i_offset
            stripped = line.strip()

            # 钳制模式: if (size > MAX) size = MAX;
            m = self._CLAMP_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = self._try_int(m.group(4))
                if val > 0:
                    summary.constraints.append(SizeVarConstraint(
                        var=size_var, op='<=', value=val,
                        source_line=actual_pc, source_text=stripped,
                        constraint_type='clamp'))
                    summary.hi = min(summary.hi, val)
                    summary.is_proved_bounded = True
                continue

            # 守卫上界: if (size < N) { ... }
            m = self._GUARD_UPPER_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = int(m.group(3))
                op = m.group(2)
                bound = val if op == '<=' else val - 1
                summary.constraints.append(SizeVarConstraint(
                    var=size_var, op='<=' if op == '<=' else '<',
                    value=bound, source_line=actual_pc, source_text=stripped,
                    constraint_type='guard_upper'))
                summary.hi = min(summary.hi, bound)
                summary.is_proved_bounded = True
                continue

            # 守卫下界: if (size > N) { ... }
            m = self._GUARD_LOWER_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = int(m.group(3))
                op = m.group(2)
                bound = val if op == '>=' else val + 1
                summary.constraints.append(SizeVarConstraint(
                    var=size_var, op='>=' if op == '>=' else '>',
                    value=bound, source_line=actual_pc, source_text=stripped,
                    constraint_type='guard_lower'))
                summary.lo = max(summary.lo, bound)
                continue

            # min约束: size = min(other, N) → size ≤ N
            m = self._MIN_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = int(m.group(2))
                summary.constraints.append(SizeVarConstraint(
                    var=size_var, op='<=', value=val,
                    source_line=actual_pc, source_text=stripped,
                    constraint_type='min/max'))
                summary.hi = min(summary.hi, val)
                summary.is_proved_bounded = True
                continue

            # max约束: size = max(other, N) → size ≥ N
            m = self._MAX_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = int(m.group(2))
                summary.constraints.append(SizeVarConstraint(
                    var=size_var, op='>=', value=val,
                    source_line=actual_pc, source_text=stripped,
                    constraint_type='min/max'))
                summary.lo = max(summary.lo, val)
                continue

            # 三元钳制: size = (x > N) ? N : x
            m = self._TERNARY_CLAMP_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = int(m.group(2))
                summary.constraints.append(SizeVarConstraint(
                    var=size_var, op='<=', value=val,
                    source_line=actual_pc, source_text=stripped,
                    constraint_type='clamp'))
                summary.hi = min(summary.hi, val)
                summary.is_proved_bounded = True
                continue

            # 直接赋值: size = N
            m = self._ASSIGN_RE.search(stripped)
            if m and m.group(1) == size_var:
                val = int(m.group(2))
                summary.constraints.append(SizeVarConstraint(
                    var=size_var, op='=', value=val,
                    source_line=actual_pc, source_text=stripped,
                    constraint_type='assign'))
                summary.lo = max(summary.lo, val)
                summary.hi = min(summary.hi, val)
                if summary.lo == summary.hi:
                    summary.is_proved_bounded = True
                continue

            # 已知安全宏: #define MAX_BUF 4096
            for macro in self._KNOWN_SAFE_MACROS:
                if macro in stripped and size_var in stripped:
                    if re.search(rf'{macro}\s+(\d+)', stripped):
                        pass  # 宏定义行, 不需要额外处理

        return summary

    @staticmethod
    def _try_int(s: str) -> int:
        try:
            return int(s)
        except (ValueError, TypeError):
            try:
                return int(s, 16)
            except (ValueError, TypeError):
                return -1


def apply_size_constraints_to_findings(
    findings: List[dict],
    ir_lines: List[str],
) -> Tuple[List[dict], int]:
    """管线集成: 对已有findings应用size约束过滤.

    对每个含动态size的finding, 收集malloc上游的size约束,
    若约束证明安全则降级置信度.

    Returns:
        (filtered_findings, num_adjusted)
    """
    collector = SizeConstraintCollector()
    adjusted = 0

    for f in findings:
        alloc_size = f.get('alloc_size', -1)
        if isinstance(alloc_size, int) and alloc_size > 0:
            continue  # 常量size, 不需要约束分析

        alloc_var = str(f.get('alloc_var', ''))
        size_var = str(f.get('alloc_size', ''))
        if not isinstance(size_var, str) or not size_var.isidentifier():
            continue

        # 在描述中搜索行号
        desc = str(f.get('description', ''))
        pc_match = re.search(r'pc[=:\s]*(\d+)', desc, re.IGNORECASE)
        alloc_pc = int(pc_match.group(1)) if pc_match else len(ir_lines) // 2

        summary = collector.collect_for_alloc(ir_lines, alloc_pc, size_var)
        if not summary.is_proved_bounded:
            continue

        write_size = f.get('write_size', -1)
        if isinstance(write_size, str):
            try:
                write_size = int(write_size)
            except (ValueError, TypeError):
                write_size = -1

        if write_size > 0 and summary.hi > 0 and write_size <= summary.hi:
            f['confidence'] = max(0.05, f.get('confidence', 0.5) - 0.50)
            f['severity'] = 'Info'
            f['size_constraint'] = f'{size_var} ≤ {summary.hi}'
            f['constraint_proof'] = 'size bounded by upstream constraints'
            adjusted += 1

    return findings, adjusted
