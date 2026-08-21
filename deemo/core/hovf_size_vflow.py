"""
HOVF 分配大小值流解析 - 沿赋值链向后解析动态分配大小, 折叠为区间 [lo, hi]。
支持常量赋值、算术表达式、类型转换、守卫钳位; 无解析时返回 (None, 原因)。
"""

import re
from dataclasses import dataclass, field
from typing import List, Optional, Tuple

from core.hovf_types import ValueInterval

_MAX_DEPTH = 12
_ASGN_RE = re.compile(r'([a-z_]\w*)\s*=\s*(.+)')
_MACRO_RE = re.compile(r'#define\s+(\w+)\s+((?:0x[0-9a-fA-F]+|\d+))')


@dataclass
class SizeResolveResult:
    """分配大小解析结果. interval 为 None 表示解析失败."""
    interval: Optional[ValueInterval]
    reasons: List[str] = field(default_factory=list)
    source: str = 'unknown'


def _const_val(expr: str) -> Optional[int]:
    """纯常量求值, 支持 0x 与 10 进制."""
    expr = (expr or '').strip()
    try:
        if re.fullmatch(r'(?:0x[0-9a-fA-F]+|\d+)', expr):
            return int(expr, 0)
    except ValueError:
        pass
    return None


def _const_arith(expr: str) -> Optional[int]:
    """常量算术折叠: 支持 + - * / << >> 及括号."""
    expr = (expr or '').strip()
    if re.fullmatch(r'[0-9a-fA-Fx\s+\-*/()<>.]+', expr):
        try:
            norm = re.sub(r'\b0x([0-9a-fA-F]+)\b',
                          lambda m: str(int(m.group(1), 16)), expr)
            norm = re.sub(r'>>\s*(\d+)',
                          lambda m: f'//{2 ** int(m.group(1))}', norm)
            norm = re.sub(r'<<\s*(\d+)',
                          lambda m: f'*{2 ** int(m.group(1))}', norm)
            if re.fullmatch(r'[-+*/()\d\s]*', norm):
                val = eval(norm, {'__builtins__': {}})  # noqa: S307
                if isinstance(val, int) and 0 < val < 2**48:
                    return val
        except (ValueError, ZeroDivisionError, NameError, SyntaxError):
            pass
    return None


def _sizeof_val(expr: str) -> Optional[int]:
    """sizeof 表达式折叠, 内置常见基础类型宽度."""
    m = re.search(r'sizeof\s*\(\s*(?:struct\s+)?(\w+)\s*\)', expr)
    if not m:
        return None
    base = {
        'char': 1, 'short': 2, 'int': 4, 'long': 8, 'float': 4,
        'double': 8, 'size_t': 8, 'void': 8,
    }.get(m.group(1).lower())
    if base:
        return base
    return None


def _count_sizeof(expr: str) -> Optional[int]:
    """折叠 N * sizeof(T) / sizeof(T) * N 形态的分配大小."""
    _BASE = {
        'char': 1, 'short': 2, 'int': 4, 'long': 4, 'float': 4,
        'double': 8, 'size_t': 8, 'void': 8,
    }
    m = re.match(r'((?:0x)?\d+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', expr)
    if m:
        base = _BASE.get(m.group(2).lower())
        return int(m.group(1), 0) * base if base else None
    m = re.match(r'sizeof\s*\(\s*(\w+)\s*\)\s*\*\s*((?:0x)?\d+)', expr)
    if m:
        base = _BASE.get(m.group(1).lower())
        return int(m.group(2), 0) * base if base else None
    return None


def _clamp_interval(var: str, ir: List[str], line_idx: int,
                    reasons: List[str]) -> Optional[ValueInterval]:
    """识别 if (var > K) var = K; 型钳位守卫, 返回上界区间.

    与普通赋值的区别: 钳位只收紧上界, 下界保持 0, 避免把下界
    误解析为钳位常量.
    """
    for i in range(max(0, line_idx - 30), line_idx + 1):
        if i >= len(ir):
            break
        line = ir[i]
        m = re.search(
            rf'if\s*\(\s*{re.escape(var)}\s*>\s*(0x[0-9a-fA-F]+|\d+)\s*\)'
            rf'\s*{re.escape(var)}\s*=\s*(0x[0-9a-fA-F]+|\d+)',
            line)
        if m:
            cap = int(m.group(1), 0)
            reasons.append(f'钳位上界 {var}<= {cap}')
            return ValueInterval(0, cap)
    return None


def resolve_macro(name: str, ir: List[str]) -> Optional[int]:
    """解析 #define 常量宏. 用于 malloc(MACRO) / memcpy(d,s,MACRO)."""
    for line in ir:
        if not line.startswith('#define'):
            continue
        m = _MACRO_RE.search(line)
        if m and m.group(1) == name:
            try:
                return int(m.group(2), 0)
            except ValueError:
                return None
    return None


def _resolve_var(var: str, ir: List[str], line_idx: int,
                 depth: int, reasons: List[str]) -> Optional[ValueInterval]:
    """沿赋值链回溯解析变量, 返回区间或 None."""
    if depth > _MAX_DEPTH:
        reasons.append('解析深度超限')
        return None
    for i in range(line_idx, max(-1, line_idx - 30), -1):
        if i < 0 or i >= len(ir):
            break
        clamp = _clamp_interval(var, ir, i, reasons)
        if clamp is not None:
            return clamp
        m = _ASGN_RE.search(ir[i])
        if not m or m.group(1) != var:
            continue
        rhs = m.group(2).strip()
        return _resolve_rhs(rhs, ir, i, depth, reasons)
    macro = resolve_macro(var, ir)
    if macro is not None:
        reasons.append(f'宏常量 {macro}')
        return ValueInterval(macro, macro)
    reasons.append(f'{var} 无赋值来源')
    return None


def _resolve_rhs(rhs: str, ir: List[str], line_idx: int, depth: int,
                 reasons: List[str]) -> Optional[ValueInterval]:
    rhs = re.sub(r'\b(?:unsigned|signed|const|volatile|size_t)\s+', '', rhs)
    rhs = rhs.rstrip(';').strip()
    c = _const_val(rhs)
    if c is not None:
        reasons.append(f'常量 {c}')
        return ValueInterval(c, c)
    c = _const_arith(rhs)
    if c is not None:
        reasons.append(f'常量表达式 {c}')
        return ValueInterval(c, c)
    c = _sizeof_val(rhs)
    if c is not None:
        reasons.append(f'sizeof={c}')
        return ValueInterval(c, c)
    c = _count_sizeof(rhs)
    if c is not None:
        reasons.append(f'数量*sizeof={c}')
        return ValueInterval(c, c)
    m = re.fullmatch(r'\([a-z_]\w*\)(.+)', rhs)
    if m:
        iv = _resolve_rhs(m.group(1).strip(), ir, line_idx, depth, reasons)
        if iv:
            reasons.append(f'类型转换保持区间 {iv}')
            return iv
    m = re.fullmatch(r'(\w+)\s*(\+|-)\s*((?:0x)?\d+)', rhs)
    if m:
        var, op, num = m.group(1), m.group(2), int(m.group(3), 0)
        iv = _resolve_var(var, ir, line_idx, depth + 1, reasons)
        if iv:
            return ValueInterval(iv.lo + (num if op == '+' else -num),
                                 iv.hi + (num if op == '+' else -num))
    m = re.fullmatch(r'(\w+)\s*\*\s*(\w+)', rhs)
    if m:
        iv1 = _resolve_var(m.group(1), ir, line_idx, depth + 1, reasons)
        iv2 = _resolve_var(m.group(2), ir, line_idx, depth + 1, reasons)
        if iv1 and iv2:
            return ValueInterval(iv1.lo * iv2.lo, iv1.hi * iv2.hi)
    # 复合表达式: A * B + C / A * B - C, 各分量可独立钳位
    m = re.fullmatch(r'(\w+)\s*\*\s*(\w+)\s*([+-])\s*(\w+)', rhs)
    if m:
        iv1 = _resolve_var(m.group(1), ir, line_idx, depth + 1, reasons)
        iv2 = _resolve_var(m.group(2), ir, line_idx, depth + 1, reasons)
        iv3 = _resolve_var(m.group(4), ir, line_idx, depth + 1, reasons)
        if iv1 and iv2 and iv3:
            prod_lo, prod_hi = iv1.lo * iv2.lo, iv1.hi * iv2.hi
            if m.group(3) == '+':
                return ValueInterval(prod_lo + iv3.lo, prod_hi + iv3.hi)
            return ValueInterval(prod_lo - iv3.hi, prod_hi - iv3.lo)
    m = re.fullmatch(r'(\w+)\s*\*\s*((?:0x)?\d+)', rhs)
    if m:
        var, mult = m.group(1), int(m.group(2), 0)
        iv = _resolve_var(var, ir, line_idx, depth + 1, reasons)
        if iv:
            return ValueInterval(iv.lo * mult, iv.hi * mult)
    return None


# TODO: 非线性不变量 (i*j<N) 未解析, 值流域仅线性
def resolve_alloc_size(
    size_expr: str,
    ir: List[str],
    call_pc: int,
) -> SizeResolveResult:
    """解析分配大小表达式, 返回区间与解析轨迹."""
    reasons: List[str] = []
    expr = (size_expr or '').strip()
    if not expr:
        return SizeResolveResult(None, ['无大小表达式'], 'none')
    iv = _resolve_rhs(expr, ir, call_pc, 0, reasons)
    if iv is None:
        m = re.fullmatch(r'(\w+)(?:\s*\+\s*((?:0x)?\d+))?', expr)
        if m:
            var = m.group(1)
            add = int(m.group(2), 0) if m.group(2) else 0
            iv = _resolve_var(var, ir, call_pc, 0, reasons)
            if iv:
                iv = ValueInterval(iv.lo + add, iv.hi + add)
    if iv is None:
        return SizeResolveResult(None, reasons, 'unresolved')
    return SizeResolveResult(iv, reasons, 'vflow')
