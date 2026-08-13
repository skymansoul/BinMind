"""
HOVF 写入模式与通用解析辅助.

正则常量、类型宽度映射、常量表达式解析、块注释剥离等纯工具
函数集中于此, 供 hovf_write_extract 使用.
"""

import re
from typing import List, Optional, Tuple

from core.heap_overflow_detector import HeapOverflowCandidate

_CAST_DEREF_RE = re.compile(
    r'\*\s*\(\s*((?:un)?signed\s+)?[a-z_]\w*\s*\*+\s*\)\s*'
    r'\(\s*(\w+)\s*\+\s*([^)]+?)\s*\)\s*=')
_CAST_SIMPLE_RE = re.compile(
    r'\*\s*\(\s*((?:un)?signed\s+)?[a-z_]\w*\s*\*+\s*\)\s*(\w+)\s*=')
# 无类型解引用: *(buf + 72) = ... / *buf = ...
_PLAIN_OFF_RE = re.compile(r'\*\s*\(\s*(\w+)\s*\+\s*([^)]+?)\s*\)\s*=')
_PLAIN_SIMPLE_RE = re.compile(r'\*\s*(\w+)\s*=')
# 数组索引写入: buf[i] = / buf[i + 1] +=
_ARR_WRITE_RE = re.compile(
    r'(\w+)\s*\[\s*([^]]+?)\s*\]\s*(?:\+\+|\+=|-=|=)')
# 带偏移库写入: memcpy(buf + off, src, n)
_LIB_OFF_RE = re.compile(
    r'(memcpy|memmove|memset|strcpy|strcat|strncpy)\s*\(\s*'
    r'(\w+)\s*\+\s*([^,]+?)\s*(?:,|\))')

# C 类型到字节宽度映射, 用于推断 store_size (x86_64 Linux LP64)
_TYPE_WIDTH = {
    'char': 1, 'uchar': 1, 'unsigned char': 1, 'int8_t': 1,
    'short': 2, 'ushort': 2, 'unsigned short': 2, 'int16_t': 2,
    'int': 4, 'uint': 4, 'unsigned': 4, 'long': 8, 'ulong': 8,
    'float': 4, 'int32_t': 4, 'uint32_t': 4,
    'long long': 8, 'long long int': 8, 'unsigned long long': 8,
    'double': 8, 'int64_t': 8, 'uint64_t': 8,
    'size_t': 8, 'void': 8, 'unsigned long': 8,
}

# 声明行判定: `char *buf = malloc(...)` 中的 `*buf =` 不是解引用写
_DECL_RE = re.compile(
    r'\b(?:char|short|int|long|float|double|void|size_t|ssize_t|bool|'
    r'unsigned|signed|struct|const|static|uint\d+_t|int\d+_t)\b')


def _cast_width(cast_type: str) -> int:
    """由类型名推断元素宽度, 未知类型回退 4."""
    key = re.sub(r'\s+', ' ', cast_type or '').strip().lower()
    if key in _TYPE_WIDTH:
        return _TYPE_WIDTH[key]
    if key.startswith('long long'):
        return 8
    return 4


def _resolve_const(expr: str) -> Optional[int]:
    """解析纯常量偏移表达式, 支持 0x 前缀与基础加法."""
    expr = (expr or '').strip()
    m = re.fullmatch(
        r'(?:0x[0-9a-fA-F]+|\d+)(?:\s*\+\s*(?:0x[0-9a-fA-F]+|\d+))*', expr)
    if m:
        total = 0
        for tok in re.findall(r'0x[0-9a-fA-F]+|\d+', expr):
            total += int(tok, 0)
        return total
    if re.fullmatch(r'(\w+)\s*\+\s*((?:0x)?\d+)', expr):
        return None  # 变量 + 常量: 动态偏移, 交由值流模块处理
    return None


def _extract_var_offset(expr: str) -> Tuple[Optional[str], int]:
    """提取 (变量名, 常量偏移) 或 (None, 0)."""
    expr = (expr or '').strip()
    m = re.fullmatch(r'(\w+)\s*\+\s*((?:0x)?\d+)', expr)
    if m:
        return m.group(1), int(m.group(2), 0)
    m = re.fullmatch(r'((?:0x)?\d+)\s*\+\s*(\w+)', expr)
    if m:
        return m.group(2), int(m.group(1), 0)
    if re.fullmatch(r'\w+', expr):
        return expr, 0
    return None, 0


def _extract_stride(expr: str) -> Tuple[Optional[str], int, int]:
    """提取 (变量, 步长, 常量偏移). 支持 i*K / K*i / i*K+c 形态.

    数组索引按元素步长展开, 写范围上界 = (循环上界-1)*步长 + 偏移.
    """
    expr = (expr or '').strip()
    m = re.fullmatch(
        r'(\w+)\s*\*\s*((?:0x)?\d+)(?:\s*\+\s*((?:0x)?\d+))?', expr)
    if m:
        return m.group(1), int(m.group(2), 0), (
            int(m.group(3), 0) if m.group(3) else 0)
    m = re.fullmatch(r'((?:0x)?\d+)\s*\*\s*(\w+)', expr)
    if m:
        return m.group(2), int(m.group(1), 0), 0
    m = re.fullmatch(r'(\w+)\s*\+\s*((?:0x)?\d+)', expr)
    if m:
        return m.group(1), 1, int(m.group(2), 0)
    if re.fullmatch(r'\w+', expr):
        return expr, 1, 0
    return None, 1, 0


def _elem_width(base: str, ir: List[str], line_idx: int) -> int:
    """从 base 的声明推断数组元素宽度.

    形如 `int *buf = ...` 或 `char *buf = ...`; 默认 1 字节,
    避免高估写范围造成误报.
    """
    for i in range(max(0, line_idx - 25), line_idx + 1):
        if i >= len(ir):
            break
        line = ir[i]
        m = re.search(
            rf'\b([a-z_]\w*)\s*\*+\s*{re.escape(base)}\s*='
            rf'|\b{re.escape(base)}\s*=\s*\(\s*([a-z_]\w*)\s*\*+\)',
            line)
        if m:
            tname = (m.group(1) or m.group(2) or '').lower()
            if tname in ('char', 'signed char', 'unsigned char', 'uint8_t'):
                return 1
            if tname in ('short', 'int16_t'):
                return 2
            if tname in ('int', 'int32_t', 'float'):
                return 4
            if tname in ('long', 'long long', 'double', 'int64_t',
                         'size_t'):
                return 8
    return 1


def _attach_loop_extent(candidate: HeapOverflowCandidate, bound: int,
                        width: int) -> None:
    """把循环上界附着到候选, 供引擎计算写范围区间."""
    candidate._hovf_extent_lo = 0
    candidate._hovf_extent_hi = bound * width


def _strip_block_comments(lines: List[str]) -> List[str]:
    """移除块注释, 支持跨行注释, 保留行号对齐语义.

    块注释内容常内嵌 malloc/strcpy 等关键词, 不剔除会污染
    分配位点与写入通道.
    """
    out: List[str] = []
    in_comment = False
    for line in lines:
        if in_comment:
            end = line.find('*/')
            if end < 0:
                out.append('')
                continue
            line = line[end + 2:]
            in_comment = False
        while True:
            start = line.find('/*')
            if start < 0:
                break
            end = line.find('*/', start + 2)
            if end < 0:
                line = line[:start]
                in_comment = True
                break
            line = line[:start] + line[end + 2:]
        out.append(line)
    return out
