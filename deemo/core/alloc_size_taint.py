"""
分配大小污点追踪: 判断 malloc/calloc/realloc 的 size 参数是否来自外部输入。
从调用点沿 def-use 链回溯: 来自常量则 NOT_TAINTED (溢出为确定 bug), 来自函数参数或含输入源的表达式则 TAINTED, 否则 INDETERMINATE。
"""

import re
from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

class TaintLevel(str, Enum):
    TAINTED = "tainted"            # 确认来自外部输入
    NOT_TAINTED = "not_tainted"    # 确认来自常量
    INDETERMINATE = "indeterminate"  # 无法确定

@dataclass
class AllocSite:
    addr: int = 0
    func_name: str = ""
    size_arg: str = ""             # size参数的表达式文本
    size_value: Optional[int] = None  # 若为常量, 记录值
    taint_level: TaintLevel = TaintLevel.INDETERMINATE
    trace_chain: List[str] = None

    def __post_init__(self):
        if self.trace_chain is None:
            self.trace_chain = []

# 外部输入源函数
_INPUT_SOURCES = {
    'read', 'fread', 'recv', 'recvfrom', 'recvmsg',
    'fgets', 'getline', 'scanf', '__isoc99_scanf',
    'getenv', 'atoi', 'strtol', 'strtoul',
    'argv', 'argc',
}

# malloc系列
_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'malloc_debug',
                 '_malloc_r', '__libc_malloc'}

_MALLOC_CALL = re.compile(
    r'(?:(\w+)\s*=\s*)?(' + '|'.join(_ALLOC_FUNCS) + r')\s*\(\s*(.+?)\s*\)',
)

def analyze_alloc_taint(
    code: str,
    func_name: str = "",
    max_depth: int = 4,
) -> List[AllocSite]:
    """分析函数中所有 malloc 调用点的 size 参数来源, 返回标记了 taint_level 的 AllocSite 列表。

    调用方据此抑制误报: NOT_TAINTED 时写超出常量 size 为确定溢出 (保留), TAINTED 时需进一步验证 size 是否被截断, INDETERMINATE 时保守保留。
    """
    sites: List[AllocSite] = []
    for m in _MALLOC_CALL.finditer(code):
        ret_var = m.group(1) or ""
        alloc_func = m.group(2)
        size_expr = m.group(3).strip()

        level, chain = _trace_size_source(code, size_expr, func_name, max_depth)
        const_val = _try_eval_constant(size_expr)

        sites.append(AllocSite(
            func_name=func_name,
            size_arg=size_expr,
            size_value=const_val,
            taint_level=level,
            trace_chain=chain,
        ))
    return sites

def _trace_size_source(
    code: str,
    expr: str,
    func_name: str,
    depth: int,
) -> Tuple[TaintLevel, List[str]]:
    chain = [expr]

    if _try_eval_constant(expr) is not None:
        return TaintLevel.NOT_TAINTED, chain

    # def-use 回溯 — 检查表达式中的变量名是否来自输入源
    vars_in_expr = set(re.findall(r'\b([a-zA-Z_]\w*)\b', expr))
    vars_in_expr -= {'sizeof', 'unsigned', 'int', 'char', 'long', 'void'}
    for v in vars_in_expr:
        if v in _INPUT_SOURCES:
            return TaintLevel.TAINTED, chain + [f'source:{v}']

    current_vars = vars_in_expr
    for _ in range(depth):
        next_vars = set()
        for var in current_vars:
            assign = re.search(
                rf'{re.escape(var)}\s*=\s*(.+?)\s*;', code)
            if assign:
                rhs = assign.group(1).strip()
                chain.append(f'{var}←{rhs[:30]}')
                rhs_vars = set(re.findall(r'\b([a-zA-Z_]\w*)\b', rhs))
                rhs_vars -= {'sizeof', 'unsigned', 'int', 'char', 'long'}
                for rv in rhs_vars:
                    if rv in _INPUT_SOURCES:
                        return TaintLevel.TAINTED, chain + [f'source:{rv}']
                next_vars |= rhs_vars
        if not next_vars:
            break
        current_vars = next_vars

    if func_name and any(
        kw in func_name.lower()
        for kw in ('parse', 'process', 'handler', 'decode', 'read')
    ):
        return TaintLevel.TAINTED, chain + ['func_name_hint']

    return TaintLevel.INDETERMINATE, chain

def _try_eval_constant(expr: str) -> Optional[int]:
    expr = expr.strip()
    try:
        return int(expr)
    except ValueError:
        pass
    try:
        return int(expr, 16)
    except ValueError:
        pass
    # sizeof(type) — 常见类型大小映射
    m = re.match(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
    if m:
        sizes = {'int': 4, 'long': 8, 'char': 1, 'short': 2,
                  'float': 4, 'double': 8, 'void': 1}
        return sizes.get(m.group(1).lower())
    return None
