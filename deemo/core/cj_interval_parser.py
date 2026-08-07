"""
区间域IR语法解析器 — 从IR行和反编译文本中提取变量区间.

从cj_interval_domain.py拆分, 职责单一: 仅负责语法模式匹配
和区间初始化, 不涉及约束系统操作.

支持的语法:
  - C赋值: x = 40, y = x + 5, y = x * 3
  - 汇编赋值: mov x, 40, mov y, x, add y, 5, sub y, 3
  - 条件分支: if (x < 50), if (x >= N)
  - cmp+jcc: cmp var, val + jl/jle/jg/jge
  - 循环: for (i=0; i<N; i++)
"""


import re

from core.cj_interval_domain import (
    Interval, IntervalDomain, NEG_INF, POS_INF,
)


def apply_constant_assignments(
    dom: IntervalDomain, lines: list[str],
) -> None:
    """解析 x = 常量 和 mov x, 常量 形式赋值."""
    c_pat = re.compile(r'(\w+)\s*=\s*(\d+)')
    mov_const = re.compile(r'mov\s+(\w+),\s*(\d+)', re.I)

    for line in lines:
        if 'malloc' in line.lower() or 'alloc' in line.lower():
            continue

        m = c_pat.search(line)
        if m:
            dom.set(m.group(1), Interval(float(m.group(2)), float(m.group(2))))
            continue

        m = mov_const.search(line)
        if m:
            dom.set(m.group(1), Interval(float(m.group(2)), float(m.group(2))))


def apply_binary_assignments(
    dom: IntervalDomain, lines: list[str],
) -> None:
    """解析算术赋值, 支持C语法和汇编语法."""
    add_pat = re.compile(r'(\w+)\s*=\s*(\w+)\s*([+\-])\s*(\d+)')
    mul_pat = re.compile(r'(\w+)\s*=\s*(\w+)\s*\*\s*(\d+)')
    mov_pat = re.compile(r'mov\s+(\w+),\s*(\w+)', re.I)
    add_asm = re.compile(r'add\s+(\w+),\s*(\d+)', re.I)
    sub_asm = re.compile(r'sub\s+(\w+),\s*(\d+)', re.I)

    for line in lines:
        m = add_pat.search(line)
        if m:
            dst, src, op, c = m.groups()
            src_iv = dom.get(src)
            cv = float(c)
            if op == '+':
                dom.set(dst, Interval(src_iv.lo + cv, src_iv.hi + cv))
            else:
                dom.set(dst, Interval(src_iv.lo - cv, src_iv.hi - cv))
            continue

        m = mul_pat.search(line)
        if m:
            dst, src, c = m.groups()
            src_iv = dom.get(src)
            cv = float(c)
            if cv > 0:
                dom.set(dst, Interval(src_iv.lo * cv, src_iv.hi * cv))
            elif cv < 0:
                dom.set(dst, Interval(src_iv.hi * cv, src_iv.lo * cv))
            continue

        m = mov_pat.search(line)
        if m and 'malloc' not in line.lower() and 'alloc' not in line.lower():
            dst, src = m.groups()
            src_iv = dom.get(src)
            if src_iv.lo != NEG_INF or src_iv.hi != POS_INF:
                dom.set(dst, Interval(src_iv.lo, src_iv.hi))
            continue

        m = add_asm.search(line)
        if m:
            dst, c = m.groups()
            cur = dom.get(dst)
            cv = float(c)
            dom.set(dst, Interval(cur.lo + cv, cur.hi + cv))
            continue

        m = sub_asm.search(line)
        if m:
            dst, c = m.groups()
            cur = dom.get(dst)
            cv = float(c)
            dom.set(dst, Interval(cur.lo - cv, cur.hi - cv))


def apply_guard_conditions(
    dom: IntervalDomain,
    lines: list[str],
    context_text: str,
) -> None:
    """从IR提取if条件和cmp+jcc, 用区间相交收紧变量边界."""
    patterns = [
        (re.compile(r'if\s*\(\s*(\w+)\s*<\s*(\d+)\s*\)'), '<'),
        (re.compile(r'if\s*\(\s*(\w+)\s*<=\s*(\d+)\s*\)'), '<='),
        (re.compile(r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)'), '>'),
        (re.compile(r'if\s*\(\s*(\w+)\s*>=\s*(\d+)\s*\)'), '>='),
    ]

    for pat, op in patterns:
        for m in pat.finditer(context_text):
            _meet_guard(dom, m.group(1), int(m.group(2)), op)

    cmp_pat = re.compile(r'cmp\s+(\w+),\s*(0x[0-9a-fA-F]+|\d+)', re.I)
    for i, line in enumerate(lines):
        m = cmp_pat.search(line)
        if not m:
            continue
        var = m.group(1)
        try:
            val = int(m.group(2), 0)
        except ValueError:
            continue

        next_line = lines[i + 1] if i + 1 < len(lines) else ""
        if re.search(r'jl|jb', next_line, re.I):
            _meet_guard(dom, var, val, '<')
        elif re.search(r'jle|jbe', next_line, re.I):
            _meet_guard(dom, var, val, '<=')
        elif re.search(r'jg|ja', next_line, re.I):
            _meet_guard(dom, var, val, '>')
        elif re.search(r'jge|jae', next_line, re.I):
            _meet_guard(dom, var, val, '>=')


def apply_guard_conditions_text(
    dom: IntervalDomain,
    text: str,
) -> None:
    """从反编译文本提取if条件, 支持变量间比较."""
    patterns = [
        (r'if\s*\(\s*(\w+)\s*<\s*(\d+)\s*\)', '<'),
        (r'if\s*\(\s*(\w+)\s*<=\s*(\d+)\s*\)', '<='),
        (r'if\s*\(\s*(\w+)\s*>\s*(\d+)\s*\)', '>'),
        (r'if\s*\(\s*(\w+)\s*>=\s*(\d+)\s*\)', '>='),
        (r'if\s*\(\s*(\w+)\s*<\s*(\w+)\s*\)', '<'),
        (r'if\s*\(\s*(\w+)\s*>=\s*(\w+)\s*\)', '>='),
    ]

    for line in text.split('\n'):
        for pat_str, op in patterns:
            for m in re.finditer(pat_str, line):
                var = m.group(1)
                rhs = m.group(2)
                try:
                    val = int(rhs, 0)
                except ValueError:
                    other_iv = dom.get(rhs)
                    if other_iv.hi != POS_INF and op == '<':
                        val = int(other_iv.hi) - 1
                    elif other_iv.lo != NEG_INF and op == '>=':
                        val = int(other_iv.lo)
                    else:
                        continue
                _meet_guard(dom, var, val, op)


def apply_loop_bounds(
    dom: IntervalDomain, context_text: str,
) -> None:
    """从循环结构提取变量上下界."""
    for_pat = re.compile(
        r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*(\d+)\s*;\s*'
        r'\1\s*(<|<=)\s*(\d+)', re.I)

    for m in for_pat.finditer(context_text):
        var = m.group(1)
        lo = int(m.group(2))
        op = m.group(3)
        hi = int(m.group(4))
        hi_val = float(hi - 1) if op == '<' else float(hi)
        dom.set(var, Interval(float(lo), hi_val))


def _meet_guard(
    dom: IntervalDomain, var: str, val: int, op: str,
) -> None:
    """用比较条件收紧变量区间."""
    cur = dom.get(var)
    if op == '<':
        dom.set(var, cur.meet(Interval(NEG_INF, float(val - 1))))
    elif op == '<=':
        dom.set(var, cur.meet(Interval(NEG_INF, float(val))))
    elif op == '>':
        dom.set(var, cur.meet(Interval(float(val + 1), POS_INF)))
    elif op == '>=':
        dom.set(var, cur.meet(Interval(float(val), POS_INF)))


__all__ = [
    'apply_constant_assignments', 'apply_binary_assignments',
    'apply_guard_conditions', 'apply_guard_conditions_text',
    'apply_loop_bounds',
]
