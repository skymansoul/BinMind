"""
表达式求值器 — 将 C 表达式解析为值范围 [min, max]。

从 value_range.py 分离
独立于 ValueRangeEngine, 可在约束简化等模块中复用。
"""
import re
from typing import Dict
from analysis.value_range import Range, INF


# 外部输入来源 — 这些函数/模式产生不可控输入
_EXTERNAL_INPUT_RE = re.compile(
    r'(?:atoi|atol|atoll|strtol|strtoul)\s*\([^)]+\)'
    r'|argv\['
    r'|getenv\s*\([^)]+\)'
    r'|scanf\s*\([^)]+\)'
    r'|fgets\s*\([^)]+\)'
    r'|recv\s*\([^)]+\)',
)

# 变量名
_VAR_RE = re.compile(r'^[a-zA-Z_]\w*$')
_CONST_RE = re.compile(r'^\d+$')
_HEX_RE = re.compile(r'^0x[0-9a-fA-F]+$')


def eval_expr_impl(expr: str, ranges: Dict[str, Range],
                   external_vars: set) -> Range:
    """将 C 表达式求值为范围。

    支持:
      - 数字常量: 64 → [64,64]
      - sizeof(type) → [size, size]
      - 变量引用: name → ranges[name] 或 external → [0, INF]
      - 算术: a + b, a - b, a * b
      - 三元: c ? a : b → [min(a,b), max(a,b)]
      - 函数调用: atoi(), compute_size() → [0, INF] 或已知范围
    """
    expr = expr.strip().lstrip('(').rstrip(')').strip()

    # 纯数字常量
    if _CONST_RE.match(expr):
        v = int(expr)
        return Range(lo=v, hi=v)

    # 十六进制
    if _HEX_RE.match(expr):
        v = int(expr, 16)
        return Range(lo=v, hi=v)

    # sizeof(type)
    if expr.startswith('sizeof'):
        return _eval_sizeof(expr)

    # 外部输入
    if _EXTERNAL_INPUT_RE.search(expr):
        return Range(lo=0, hi=INF)

    # 已知变量
    var_match = _VAR_RE.match(expr)
    if var_match:
        name = var_match.group(0)
        if name in ranges:
            return ranges[name]
        if name in external_vars:
            return Range(lo=0, hi=INF)
        return Range(lo=0, hi=INF)

    # 算术表达式: 拆分为 left op right
    # 优先处理乘法和除法 (高优先级)
    for sep_op in ['*', '/']:
        idx = expr.find(sep_op, 1)  # 跳过可能的前导-
        if idx > 0:
            a = eval_expr_impl(expr[:idx].strip(), ranges, external_vars)
            b = eval_expr_impl(expr[idx+1:].strip(), ranges, external_vars)
            return _apply_op(a, sep_op, b)

    # 加减
    for sep_op in ['+', '-']:
        idx = expr.find(sep_op, 1)
        if idx > 0:
            a = eval_expr_impl(expr[:idx].strip(), ranges, external_vars)
            b = eval_expr_impl(expr[idx+1:].strip(), ranges, external_vars)
            return _apply_op(a, sep_op, b)

    # 三元表达式
    if '?' in expr and ':' in expr:
        q_idx = expr.index('?')
        colon_idx = expr.rindex(':')
        t = eval_expr_impl(expr[q_idx+1:colon_idx].strip(), ranges, external_vars)
        f = eval_expr_impl(expr[colon_idx+1:].strip(), ranges, external_vars)
        return Range(lo=min(t.lo, f.lo), hi=max(t.hi, f.hi))

    # 函数调用
    if '(' in expr and ')' in expr:
        func_name = re.match(r'(\w+)\s*\(', expr)
        if func_name and func_name.group(1) in ranges:
            return ranges[func_name.group(1)]
        return Range(lo=0, hi=INF)

    return Range(lo=0, hi=INF)


def _eval_sizeof(expr: str) -> Range:
    """求值 sizeof(T) / sizeof(expr)。"""
    inner = expr.replace('sizeof', '', 1).strip().lstrip('(').rstrip(')').strip()
    sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8,
             'float': 4, 'double': 8, 'size_t': 8, 'void': 1,
             'void*': 8, 'char*': 8, 'int*': 8, 'long*': 8}
    base = inner.split()[0].rstrip('*')
    base = base.replace('unsigned', '').strip() or inner
    size = sizes.get(base, 4)
    if inner.count('*') > 0:
        size = 8
    return Range(lo=size, hi=size)


def _apply_op(a: Range, op: str, b: Range) -> Range:
    """两个范围间的二元运算。"""
    if op == '+':
        lo, hi = a.lo + b.lo, a.hi + b.hi
    elif op == '-':
        lo, hi = max(0, a.lo - b.hi), a.hi - b.lo
    elif op == '*':
        cand = [a.lo * b.lo, a.lo * b.hi, a.hi * b.lo, a.hi * b.hi]
        lo, hi = min(cand), max(cand)
    elif op == '/':
        b_lo = b.lo if b.lo > 0 else 1
        lo, hi = min(a.lo // b_lo, a.hi // b_lo), max(a.lo // b_lo, a.hi // b_lo)
    else:
        return Range(lo=0, hi=INF)
    # 限制溢出
    if hi > INF:
        hi = INF
    if lo < 0:
        lo = 0
    return Range(lo=lo, hi=hi)
