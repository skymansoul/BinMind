"""
memcpy/memset 写入大小提取 + 元素大小推断 + glibc 分配器语义.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional

from analysis.c_source_patterns import parse_size, resolve_constant


# 参数分割 (处理嵌套括号)

def _split_args_simple(args_str: str) -> List[str]:
    """简单参数分割, 处理嵌套括号 (如 sizeof(int))."""
    args = []
    depth = 0
    current = []
    for ch in args_str:
        if ch == '(':
            depth += 1
            current.append(ch)
        elif ch == ')':
            depth -= 1
            current.append(ch)
        elif ch == ',' and depth == 0:
            args.append(''.join(current))
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current))
    return args


# memcpy/memset 写入大小提取

# strcpy 常量源字符串长度提取
_RE_STRCPY_CONST_SRC = re.compile(
    r'strcpy\s*\([^,]+,\s*"((?:[^"\\]|\\.)*)"\s*\)', re.IGNORECASE)
# strlen → 实际字符串长度 (不含 \\0)
_RE_STRLEN_CONST = re.compile(
    r'strlen\s*\(\s*"((?:[^"\\]|\\.)*)"\s*\)', re.IGNORECASE)

# snprintf: 第二个参数是大小限制 (不是第三参数)
_RE_SNPRINTF = re.compile(
    r'snprintf\s*\(([^)]+)\)', re.IGNORECASE)


def _strlen_constant(s: str) -> int:
    """计算C字符串字面量的实际字符数 (不含末尾\\0, 处理转义)."""
    # 去掉外层引号
    inner = s
    # 处理常见转义: \\n \\t \\r \\\\ \\\" \\0
    length = 0
    i = 0
    while i < len(inner):
        if inner[i] == '\\' and i + 1 < len(inner):
            i += 2  # 转义序列 = 1 字符
        else:
            i += 1
        length += 1
    return length


def extract_func_write_size(
    line: str, lines: Optional[List[str]] = None, line_idx: int = 0
) -> int:
    """提取函数调用的写入大小.

    strcpy: 尝试从源字符串字面量计算长度, 失败返回 -1.
    snprintf: 提取第二参数 (大小限制), 而非第三参数.
    """
    # strcpy 处理: 提取源字符串常量长度
    m_strcpy = _RE_STRCPY_CONST_SRC.search(line)
    if m_strcpy:
        return _strlen_constant(m_strcpy.group(1))

    # 不可解析的 strcpy → 返回 -1
    if re.search(r'strcpy\s*\(', line, re.IGNORECASE):
        return -1

    # snprintf: 大小在第二参数 (args[1]), 非第三参数
    m_sn = _RE_SNPRINTF.search(line)
    if m_sn:
        args = _split_args_simple(m_sn.group(1))
        if len(args) >= 2:
            size_str = args[1].strip()
            try:
                return int(size_str, 0)
            except ValueError:
                pass
            val, is_dyn = parse_size(size_str)
            if not is_dyn and val > 0:
                return val
        return -1

    # memcpy/memset/memmove/strncpy
    m_func = re.search(
        r'(?:memcpy|memset|memmove|strncpy)\s*\(([^)]+)\)',
        line, re.IGNORECASE,
    )
    if not m_func:
        return -1

    args_str = m_func.group(1)
    args = _split_args_simple(args_str)
    if len(args) < 3:
        return -1

    size_str = args[2].strip()

    try:
        return int(size_str, 0)
    except ValueError:
        pass

    val, is_dyn = parse_size(size_str)
    if not is_dyn and val > 0:
        return val

    if lines and line_idx > 0:
        resolved = _resolve_vars_in_expr(size_str, lines, line_idx)
        if resolved > 0:
            return resolved

    return -1


def _resolve_vars_in_expr(expr: str, lines: List[str], line_idx: int) -> int:
    """将表达式中的变量替换为常量后求值.

    例如: 'n + 16' → 查找 n=64 → eval('64 + 16') → 80.
    """
    vars_in_expr = set(re.findall(r'\b([a-zA-Z_]\w*)\b', expr))
    resolved_expr = expr
    for v in vars_in_expr:
        val = resolve_constant(v, lines, line_idx)
        if val > 0:
            resolved_expr = re.sub(r'\b' + v + r'\b', str(val), resolved_expr)
    try:
        if re.match(r'^[\d\s+*/\-()]+$', resolved_expr):
            result = eval(resolved_expr, {"__builtins__": {}}, {})
            if isinstance(result, (int, float)) and result == int(result):
                return int(result)
    except Exception:
        pass
    return -1


# 元素大小推断

_ELEM_SIZE_PAT = re.compile(
    r'(?:const\s+)?(?:unsigned\s+)?'
    r'(void|char|short|int|long|float|double|size_t|ssize_t|'
    r'uint8_t|uint32_t|uint64_t|int32_t|int64_t|\w+_t)'
    r'\s*\*+\s*',
    re.IGNORECASE,
)

_ELEM_SIZE_MAP: Dict[str, int] = {
    'char': 1, 'uint8_t': 1,
    'short': 2,
    'int': 4, 'int32_t': 4, 'uint32_t': 4,
    'long': 8, 'long long': 8, 'int64_t': 8, 'uint64_t': 8,
    'double': 8, 'float': 8, 'size_t': 8, 'ssize_t': 8, 'void': 8,
}


def infer_element_size(decl_line: str) -> int:
    """从指针声明行推断元素大小.

    例如: 'int *buf = calloc(16, sizeof(int))' → type=int → 4.
    """
    m = _ELEM_SIZE_PAT.search(decl_line)
    if not m:
        return 4
    t = m.group(1).lower()
    return _ELEM_SIZE_MAP.get(t, 4)


# glibc 分配器语义 (request2size / usable 计算)

def glibc_usable_size(requested: int) -> int:
    """计算 glibc ptmalloc2 对给定请求的实际可用大小.

    公式 (与 heap_layout_oracle 一致):
      header = 16 (prev_size + size, 64-bit)
      aligned = max(32, align_up(requested + header, 16))
      usable = aligned - header
    """
    HEADER = 16
    ALIGN = 16
    MIN_CHUNK = 32

    aligned = ((requested + HEADER + ALIGN - 1) // ALIGN) * ALIGN
    aligned = max(MIN_CHUNK, aligned)
    return aligned - HEADER
