"""
约束解析器 — 从C源码提取 guard/assert/ternary 约束条件。
"""


import re
from typing import List


def parse_constraints(source: str) -> list:
    """从源码解析约束条件 (guard语句 + assert + 三元运算符).

    返回约束列表, 每条约束为 {type, var, op, val, line} 字典.
    """
    constraints = []
    lines = source.splitlines()

    for lineno, line in enumerate(lines, 1):
        line_s = line.strip()

        # if (var > N) / if (var < N) / if (var == N)
        m = re.match(
            r'if\s*\(\s*(\w+)\s*(>=|<=|>|<|==|!=)\s*(\w+)\s*\)', line_s)
        if m:
            try:
                constraints.append({
                    'type': 'guard', 'var': m.group(1),
                    'op': m.group(2), 'val': int(m.group(3)),
                    'line': lineno,
                })
            except ValueError:
                pass

        # assert(var < N)
        m = re.match(
            r'assert\s*\(\s*(\w+)\s*(>=|<=|>|<|==|!=)\s*(\w+)\s*\)', line_s)
        if m:
            try:
                constraints.append({
                    'type': 'assert', 'var': m.group(1),
                    'op': m.group(2), 'val': int(m.group(3)),
                    'line': lineno,
                })
            except ValueError:
                pass

        # var = cond ? A : B (三元运算符)
        m = re.match(
            r'(\w+)\s*=\s*\(?\s*(\w+)\s*(>=|<=|>|<|==|!=)\s*(\w+)\s*\)?\s*\?\s*(\d+)\s*:\s*(\d+)',
            line_s,
        )
        if m:
            try:
                constraints.append({
                    'type': 'ternary', 'target': m.group(1),
                    'var': m.group(2), 'op': m.group(3),
                    'threshold': int(m.group(4)),
                    'true_val': int(m.group(5)),
                    'false_val': int(m.group(6)),
                    'line': lineno,
                })
            except ValueError:
                pass

    return constraints
