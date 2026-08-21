"""
整数溢出循环提取器 — 从伪代码中扫描 for/while 循环并提取归纳变量.

"""


import re
from typing import Dict, List, Tuple

from analysis.int_loop_types import InductionKind, InductionVar, LoopInfo


# for 循环: for (init; cond; update) { body }
_FOR_LOOP_RE = re.compile(
    r'for\s*\(\s*(.*?)\s*;\s*(.*?)\s*;\s*(.*?)\s*\)\s*\{',
    re.IGNORECASE | re.DOTALL)

# while 循环: while (cond) { body }
_WHILE_LOOP_RE = re.compile(
    r'while\s*\(\s*(.+?)\s*\)\s*\{', re.IGNORECASE)

# 归纳变量: i = i + c 或 i += c 或 i = i - c 或 i -= c
_INDUCTION_ADD_RE = re.compile(
    r'(\w+)\s*(\+|\-)=\s*(\d+)\s*;?')
_INDUCTION_ASSIGN_RE = re.compile(
    r'(\w+)\s*=\s*(\w+)\s*([+\-])\s*(\d+)\s*;?')

# 累积器: sum += val
_ACCUM_RE = re.compile(
    r'(\w+)\s*\+=\s*(\w+)\s*;?')

# 守卫条件: i < n, i <= n, i > 0 等
_GUARD_RE = re.compile(
    r'(\w+)\s*(<|<=|>|>=|!=)\s*(\w+)')


def extract_loops_from_source(source_code: str,
                               var_init: Dict[str, int]) -> List[LoopInfo]:
    """从源码提取所有循环结构并分析归纳变量。

    var_init 为变量初始值字典 (被原地修改)。
    """
    loops = []
    lines = source_code.splitlines()

    for i, line in enumerate(lines):
        stripped = line.strip()

        # for 循环
        fm = _FOR_LOOP_RE.search(stripped)
        if fm:
            init = fm.group(1).strip() if fm.group(1) else ""
            cond = fm.group(2).strip() if fm.group(2) else ""
            update = fm.group(3).strip() if fm.group(3) else ""

            end = _find_matching_brace(lines, i)
            body_lines = [l.strip() for l in lines[i+1:end]
                         if l.strip() and not l.strip().startswith('//')]

            loop = LoopInfo(
                start_line=i, end_line=end, header_line=i,
                guard_condition=cond,
                body_lines=body_lines,
            )

            _extract_induction_vars(loop, init, cond, update,
                                    body_lines, var_init)
            loops.append(loop)
            continue

        # while 循环
        wm = _WHILE_LOOP_RE.search(stripped)
        if wm:
            cond = wm.group(1).strip()
            end = _find_matching_brace(lines, i)
            body_lines = [l.strip() for l in lines[i+1:end]
                         if l.strip() and not l.strip().startswith('//')]

            loop = LoopInfo(
                start_line=i, end_line=end, header_line=i,
                guard_condition=cond,
                body_lines=body_lines,
            )
            _extract_induction_vars(loop, "", cond, "", body_lines, var_init)
            loops.append(loop)

    return loops


def _find_matching_brace(lines: List[str], start: int) -> int:
    """括号匹配找对应的 }."""
    depth = 0
    started = False
    for j in range(start, len(lines)):
        for ch in lines[j]:
            if ch == '{':
                depth += 1
                started = True
            elif ch == '}':
                depth -= 1
        if started and depth == 0:
            return j
    return start + 50  # 回退


def _extract_induction_vars(loop: LoopInfo, init: str,
                             cond: str, update: str,
                             body_lines: List[str],
                             var_init: Dict[str, int]):
    """从循环的 init/cond/update/body 中提取归纳变量."""

    for m in re.finditer(r'(\w+)\s*=\s*(\d+)\s*;?', init):
        var_init[m.group(1)] = int(m.group(2))

    all_update_lines = [update] if update else []
    if not update:
        all_update_lines = body_lines

    for ul in all_update_lines:
        ul = ul.strip()
        # i++ / ++i / i-- / --i
        for m in re.finditer(r'(?:(\w+)\+\+|(\w+)\-\-)', ul):
            var = m.group(1) or m.group(2)
            stride = 1 if m.group(1) else -1
            init_val = var_init.get(var, 0)
            bound_var, bound_val, bound_op = _parse_guard_for(cond, var)
            loop.induction_vars[var] = InductionVar(
                name=var, kind=InductionKind.BASIC,
                init_val=init_val, stride=stride,
                bound_var=bound_var, bound_val=bound_val,
                bound_op=bound_op, line_no=loop.header_line,
            )

        # i += c / i -= c
        for m in _INDUCTION_ADD_RE.finditer(ul):
            var = m.group(1)
            op = m.group(2)
            stride = int(m.group(3)) * (1 if op == '+' else -1)
            init_val = var_init.get(var, 0)
            bound_var, bound_val, bound_op = _parse_guard_for(cond, var)
            loop.induction_vars[var] = InductionVar(
                name=var, kind=InductionKind.BASIC,
                init_val=init_val, stride=stride,
                bound_var=bound_var, bound_val=bound_val,
                bound_op=bound_op, line_no=loop.header_line,
            )

    # i = i + c / i = i - c (在 body 中)
    for bl in body_lines:
        for m in _INDUCTION_ASSIGN_RE.finditer(bl):
            dst, src, op, val = m.group(1), m.group(2), m.group(3), m.group(4)
            if dst == src and dst not in loop.induction_vars:
                stride = int(val) * (1 if op == '+' else -1)
                init_val = var_init.get(dst, 0)
                bound_var, bound_val, bound_op = _parse_guard_for(cond, dst)
                loop.induction_vars[dst] = InductionVar(
                    name=dst, kind=InductionKind.BASIC,
                    init_val=init_val, stride=stride,
                    bound_var=bound_var, bound_val=bound_val,
                    bound_op=bound_op, line_no=loop.header_line,
                )

    # 累积器: sum += val
    for bl in body_lines:
        for m in _ACCUM_RE.finditer(bl):
            var = m.group(1)
            acc_val = m.group(2)
            init_val = var_init.get(var, 0)
            loop.accumulators[var] = InductionVar(
                name=var, kind=InductionKind.ACCUMULATOR,
                init_val=init_val, stride=1,
                derived_from=acc_val, line_no=loop.header_line,
            )


def _parse_guard_for(cond: str, var: str) -> Tuple[str, int, str]:
    """解析守卫条件中针对 var 的边界.

    返回 (bound_var, bound_val, bound_op).
    """
    for m in _GUARD_RE.finditer(cond):
        left, op, right = m.group(1), m.group(2), m.group(3)
        if left == var:
            try:
                return right, int(right), op
            except ValueError:
                return right, -1, op  # 符号边界 (如 n)
        elif right == var:
            rev_op = {'<': '>', '<=': '>=', '>': '<', '>=': '<=', '!=': '!='}
            try:
                return left, int(left), rev_op.get(op, op)
            except ValueError:
                return left, -1, rev_op.get(op, op)
    return "", -1, ""


__all__ = [
    'extract_loops_from_source',
    '_find_matching_brace', '_extract_induction_vars', '_parse_guard_for',
]
