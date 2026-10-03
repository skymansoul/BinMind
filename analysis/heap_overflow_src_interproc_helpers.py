"""
heap_overflow_src_interproc 辅助函数 — callee 内 guard 与循环边界解析.

guard 上界提取和循环边界常量解析提取为独立函数.
"""

import re
from typing import Dict, List

from analysis.heap_overflow_src_patterns import parse_alloc_size


def callee_guard_bounds(body: List[str],
                        params: List[str]) -> Dict[str, int]:
    """提取callee内对参数的clamp guard上界: if(p>N) p=N; → N."""
    guards: Dict[str, int] = {}
    for line in body:
        t = line.strip()
        for p in params:
            gm = re.search(
                rf'if\s*\(\s*{re.escape(p)}\s*>\s*(\d+)\s*\)\s*'
                rf'{re.escape(p)}\s*=\s*(\d+)', t)
            if gm:
                guards[p] = int(gm.group(2))
    return guards


def resolve_callee_loop_bound(body: List[str], param_map: Dict[str, str],
                              caller_lines, call_line) -> int:
    """从callee体内解析循环边界常量, 通过param_map映射到caller上下文."""
    bounds = []
    for line in body:
        text = line.strip()
        for pat, plus in [
            (r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\d+)\s*;', False),
            (r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<=\s*(\d+)\s*;', True),
        ]:
            m = re.search(pat, text)
            if m:
                bounds.append(int(m.group(1)) + (1 if plus else 0))
                break
        else:
            m = re.search(
                r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*[;]',
                text)
            if m:
                var = param_map.get(m.group(1), m.group(1))
                if var.isdigit():
                    bounds.append(int(var))
                else:
                    from analysis.heap_overflow_src_guards import (
                        _find_clamp_bound, _find_const_assignment)
                    cl = caller_lines if caller_lines else body
                    cb = _find_clamp_bound(cl, call_line, var)
                    if cb is None:
                        cb = _find_const_assignment(cl, call_line, var)
                    if cb is not None:
                        bounds.append(cb)
    if not bounds:
        return -1
    product = 1
    for b in bounds:
        product *= b
    return product


__all__ = ['callee_guard_bounds', 'resolve_callee_loop_bound']
