"""
后向值流循环偏移追踪器 — 当 memcpy 写入偏移含循环变量 (buf+i*stride) 时, 从 for/while 循环条件提取循环变量上界, 计算 max_offset = (loop_upper-1)*stride 与 max_write_end = max_offset + store_size; max_write_end > alloc_size 判定溢出, 反之安全。
"""
import re
from typing import Optional, Tuple

from core.constraint_value_flow_types import SymbolicExpr


_for_re = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*(\d+)\s*;\s*'
    r'\1\s*<\s*(\d+)\s*;\s*\1\s*(?:\+\+|\+=\s*1)\s*\)')
_for_re2 = re.compile(
    r'for\s*\(\s*(?:int\s+)?(\w+)\s*=\s*(\d+)\s*;\s*'
    r'\1\s*<\s*=\s*(\d+)\s*;\s*\1\s*(?:\+\+|\+=\s*1)\s*\)')
_while_re = re.compile(
    r'while\s*\(\s*(\w+)\s*<\s*(\d+)\s*\)')

_offset_var_mul_re = re.compile(
    r'(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)')


def extract_loop_bound(
    ir_lines: list[str],
    store_line: int,
) -> Optional[Tuple[str, int, int]]:
    """从store_line附近提取循环变量、上界和起始值.

    返回 (loop_var, upper_bound, init_val) 或 None.
    搜索范围: store_line前后各10行.
    """
    start = max(0, store_line - 10)
    end = min(len(ir_lines), store_line + 5)

    for i in range(start, end):
        line = ir_lines[i].strip()

        m = _for_re.search(line)
        if m:
            var, init, upper = m.group(1), int(m.group(2)), int(m.group(3))
            return var, upper, init

        m = _for_re2.search(line)
        if m:
            var, init, upper = m.group(1), int(m.group(2)), int(m.group(3))
            return var, upper + 1, init

        m = _while_re.search(line)
        if m:
            var, upper = m.group(1), int(m.group(2))
            init = _find_init(ir_lines, var, i)
            if init is not None:
                return var, upper, init

    return None


def _find_init(
    ir_lines: list[str],
    var: str,
    before: int,
) -> Optional[int]:
    """搜索变量赋初值."""
    pat = re.compile(rf'{re.escape(var)}\s*=\s*(\d+)')
    for i in range(before - 1, max(0, before - 20), -1):
        m = pat.search(ir_lines[i])
        if m:
            return int(m.group(1))
    return 0


def compute_loop_offset(
    ir_lines: list[str],
    store_line: int,
    store_size: int,
    alloc_size: int,
) -> Optional[Tuple[int, str]]:
    """计算循环偏移场景的write_end.

    返回 (max_write_end, reason) 或 None.
    """
    store_line_text = ir_lines[store_line] if store_line < len(ir_lines) else ""

    om = _offset_var_mul_re.search(store_line_text)
    if not om:
        return None

    base_var, loop_var, stride = (
        om.group(1), om.group(2), int(om.group(3)))

    loop_info = extract_loop_bound(ir_lines, store_line)
    if loop_info is None:
        return None

    lvar, upper, init = loop_info
    if lvar != loop_var:
        return None

    max_i = upper - 1
    max_offset = max_i * stride
    max_write_end = max_offset + store_size

    if max_write_end > alloc_size:
        reason = (
            f"loop overflow: i_max={max_i}, stride={stride}, "
            f"max_offset={max_offset}, write_end={max_write_end} "
            f"> alloc={alloc_size}")
        return max_write_end, reason
    else:
        reason = (
            f"loop safe: i_max={max_i}, stride={stride}, "
            f"max_offset={max_offset}, write_end={max_write_end} "
            f"<= alloc={alloc_size}")
        return max_write_end, reason


__all__ = ['extract_loop_bound', 'compute_loop_offset']
