"""
堆溢出源级验证 — 正则模式 + 分配器模型 + 文本辅助。

包含: malloc/memcpy/strcpy 等正则、ptmalloc2 usable_size 模型、
     注释过滤、base_var 提取、size 表达式解析。
"""

from __future__ import annotations
import re
from typing import List, Tuple

# 正则模式

_MALLOC_RE = re.compile(
    r'(?:\(\s*\w[\w]*\s*\*?\s*\)\s*)?'
    r'(?:malloc|calloc|realloc)\s*\(([^)]+)\)')
_MALLOC_ASSIGN_RE = re.compile(
    r'(\w[\w]*(?:->\w[\w]*)?)\s*=\s*'
    r'(?:\(\s*\w[\w]*\s*\*?\s*\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(([^)]+)\)')
_MEMCPY_HEAP_RE = re.compile(
    r'memcpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,\s*([^)]+)\s*\)')
_MEMSET_HEAP_RE = re.compile(
    r'memset\s*\(\s*([^,]+)\s*,\s*[^,]+,\s*([^)]+)\s*\)')
_STRCPY_HEAP_RE = re.compile(
    r'strcpy\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)')
_STRCAT_HEAP_RE = re.compile(
    r'strcat\s*\(\s*([^,]+)\s*,\s*([^)]+)\s*\)')
_SPRINTF_HEAP_RE = re.compile(
    r'sprintf\s*\(\s*([^,]+)\s*,')
_READ_HEAP_RE = re.compile(
    r'\b(?:read|fread|recv)\s*\([^,]+,\s*([^,]+)\s*,\s*([^)]+)\s*\)')
_PTR_WRITE_RE = re.compile(
    r'\*\s*\(\s*(?:\w[\w]*\s*\*\s*\)?\s*)?\(?\s*(\w[\w]*)\s*\+\s*(\d+)\s*\)\s*=|'
    r'(\w[\w]*)\s*\[\s*(\d+)\s*\]\s*=')
_PTR_VAR_OFFSET_RE = re.compile(
    r'\*\s*\(\s*(?:\w[\w]*\s*\*\s*\)?)?\(?\s*(\w[\w]*)\s*\+\s*(\w[\w]*)\s*\)\s*=')
_STRUCT_ARRAY_WRITE_RE = re.compile(
    r'(\w[\w]*)\s*\[\s*(\d+)\s*\]\s*(?:->|\.)\s*\w[\w]*\s*=')
_LOOP_WRITE_RE = re.compile(
    r'\b(for|while)\s*\([^)]*\)\s*\{[^}]*'
    r'(?:memcpy|memset|strcpy|strcat)\s*\(')
_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*([><!=]=?)\s*(\d+)\s*\)')
_SIZE_CHECK_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*([><]=?)\s*(\w[\w]*)\s*\)')
_CLAMP_GUARD_RE = re.compile(
    r'if\s*\(\s*(\w[\w]*)\s*([><])\s*(\d+)\s*\)\s*\1\s*=\s*(\d+)\s*;')
_REALLOC_RE = re.compile(
    r'realloc\s*\(\s*(\w[\w]*)\s*,\s*([^)]+)\s*\)')
_FOR_LOOP_RE = re.compile(
    r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*;')
_WHILE_LOOP_RE = re.compile(
    r'while\s*\(\s*\*?(\w[\w]*)\s*\++\s*\)')

# 分配器模型: malloc(N) → ptmalloc2 usable_size
# glibc request2size — (N + 8 + 15) & ~15, max(MINSIZE=32, ...)
# 简化: 最小32B chunk, usable = chunk - 16 (保守)
def _ptmalloc2_usable(n: int) -> int:
    if n <= 0: return 0
    raw = n + 8      # SIZE_SZ overhead
    aligned = (raw + 15) & ~15
    chunk = max(32, aligned)
    return chunk - 8  # 仅减去size字段, prev_size可复用

_NON_VAR = frozenset({
    'if', 'else', 'while', 'for', 'return', 'int', 'char', 'void', 'long',
    'short', 'float', 'double', 'size_t', 'unsigned', 'signed', 'static',
    'const', 'sizeof', 'NULL', 'nullptr', 'malloc', 'calloc', 'realloc',
    'free', 'alloca', 'printf', 'main', 'include', 'struct', 'typedef',
    'switch', 'case', 'default', 'goto', 'break', 'continue', 'exit',
    'puts', 'strlen', 'memset', 'memcpy', 'strcmp', 'strncmp', 'strcat',
    'strcpy', 'sprintf', 'strncpy', 'snprintf', 'gets', 'scanf', 'read',
    'fgets', 'recv', 'atoi', 'exit', 'true', 'false', 'bool',
})


def _is_comment_or_empty(text: str) -> bool:
    """检查是否是注释行或空行."""
    t = text.strip()
    if not t: return True
    if t.startswith(('//', '/*', '*/', '#')): return True
    return False


def _skip_block_comments(lines: List[str]) -> List[Tuple[int, str]]:
    """过滤块注释内的行, 返回 [(line_no, stripped_text), ...].
    处理 /* */ 跨行注释, 注释内代码模式不予分析.
    单行内含完整 /* */ 的代码行保留 (行尾注释不影响分析).
    """
    result = []
    in_block = False
    for i, line in enumerate(lines, start=1):
        text = line.strip()
        if in_block:
            # 正在块注释内, 找结束
            if '*/' in text:
                in_block = False
                # 结束后的代码若剩余, 需重新分析; 保守跳过剩余
            continue
        if '/*' in text and '*/' in text:
            # 同一行内完整块注释 (含行尾注释) — 保留代码部分
            if _is_comment_or_empty(text):
                continue
            result.append((i, text))
            continue
        if '/*' in text:
            in_block = True
            continue
        if '*/' in text:
            in_block = False
            continue
        if _is_comment_or_empty(text):
            continue
        result.append((i, text))
    return result


def _base_var(expr: str) -> str:
    """从表达式中提取基本变量名 (去除 ->, ., +, [ ] 等)."""
    e = expr.strip()
    if e.startswith('*') and not e.startswith('*/'): e = e[1:].strip()
    if e.startswith('&'): e = e[1:].strip()
    if '->' in e: return e.split('->')[-1].strip()
    if '.' in e: return e.split('.')[-1].strip()
    if '+' in e: return e.split('+')[0].strip()
    if '[' in e: return e.split('[')[0].strip()
    return e


def parse_alloc_size(expr: str, lines: List[str], line: int) -> int:
    """解析分配大小表达式 → 常量值或标记 (-1=变量, -2=sizeof/复杂)."""
    e = expr.strip()
    try:
        return int(e, 0)
    except ValueError:
        pass
    # sizeof(TypeName) 或 sizeof(TypeName) — 解析typedef计算实际大小
    sm = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', e)
    if sm:
        sz = _resolve_sizeof(sm.group(1), lines, line)
        if sz > 0:
            # 检查是否有乘法: count * sizeof(T)
            mm = re.match(r'(\w+)\s*\*\s*sizeof', e)
            if mm:
                count = parse_alloc_size(mm.group(1), lines, line)
                if count > 0:
                    return count * sz
            return sz
        return -2
    mm = re.match(r'(\d+)\s*\*\s*(\d+)', e)
    if mm:
        return int(mm.group(1)) * int(mm.group(2))
    # count * sizeof(T) — 已由上面处理, 此处兜底
    mm = re.match(r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', e)
    if mm:
        count = parse_alloc_size(mm.group(1), lines, line)
        sz = _resolve_sizeof(mm.group(2), lines, line)
        if count > 0 and sz > 0:
            return count * sz
        return -2
    # 变量: 向前搜索最近赋值
    if re.match(r'^\w[\w]*$', e):
        for j in range(line - 2, -1, -1):
            t = lines[j].strip()
            if t.startswith(('//', '/*')): continue
            am = re.search(rf'\b{re.escape(e)}\s*=\s*(\d+)', t)
            if am:
                return int(am.group(1))
            am = re.search(rf'\b{re.escape(e)}\s*=\s*(\w[\w]*)', t)
            if am:
                inner = am.group(1)
                if inner not in _NON_VAR:
                    return parse_alloc_size(inner, lines, j + 1)
            if '{' in t or '}' in t:
                break
        dm = re.search(r'#define\s+' + re.escape(e) + r'\s+(\d+)', '',
                       re.MULTILINE)
        for t in lines:
            dm = re.search(r'#define\s+' + re.escape(e) + r'\s+(\d+)',
                           t.strip())
            if dm:
                return int(dm.group(1))
        return -1
    # struct->field 或 struct.field 引用: 全文件搜索赋值
    sm = re.match(r'^(\w[\w]*)\s*(?:->|\.)\s*(\w[\w]*)$', e)
    if sm:
        struct_var = sm.group(1)
        field = sm.group(2)
        for j in range(len(lines) - 1, -1, -1):
            t = lines[j].strip()
            if t.startswith(('//', '/*')): continue
            am = re.search(
                rf'{re.escape(struct_var)}\s*(?:\.|->)\s*{re.escape(field)}\s*=\s*(\w+)',
                t)
            if am:
                return parse_alloc_size(am.group(1), lines, j + 1)
        return -1
    # 算术表达式: var + const 或 const + var
    am = re.match(r'(\w+)\s*\+\s*(\d+)', e)
    if am:
        base = parse_alloc_size(am.group(1), lines, line)
        if base >= 0:
            return base + int(am.group(2))
    if 'sizeof' in e:
        return -2
    return -2


def _resolve_sizeof(typename: str, lines: List[str], line: int) -> int:
    """从源码typedef定义计算sizeof(TypeName)."""
    builtin = {
        'char': 1, 'int': 4, 'long': 8, 'short': 2,
        'float': 4, 'double': 8, 'size_t': 8,
        'void*': 8, 'char*': 8, 'int*': 8, 'long*': 8,
        'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4, 'uint64_t': 8,
        'int8_t': 1, 'int16_t': 2, 'int32_t': 4, 'int64_t': 8,
    }
    if typename in builtin:
        return builtin[typename]
    for i in range(line - 2, -1, -1):
        t = lines[i].strip()
        tm = re.match(r'typedef\s+struct\s*\{', t)
        if tm:
            total = 0
            field_sizes = {
                'char': 1, 'int': 4, 'long': 8, 'short': 2,
                'float': 4, 'double': 8, 'size_t': 8,
                'void*': 8, 'char*': 8, 'int*': 8,
            }
            for j in range(i + 1, min(len(lines), i + 50)):
                ft = lines[j].strip()
                if '}' in ft and typename in ft:
                    align = max((s for _, s in field_sizes.items()), default=1)
                    total = ((total + align - 1) // align) * align
                    return total
                fm = re.match(r'\s*(\w+)\s+(\w+)(\[\d+\])?;', ft)
                if fm:
                    base_type = fm.group(1)
                    arr = fm.group(3)
                    sz = field_sizes.get(base_type, 8)
                    if arr:
                        n = int(arr[1:-1])
                        sz *= n
                    total += sz
            break
    return -1


def _infer_struct_type(a, lines: List[str]) -> str:
    """从sizeof表达式或cast推断结构体类型名."""
    expr = a.size_expr.strip()
    m = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
    if m:
        return m.group(1)
    # cast推断: (TypeName *)malloc(...)
    if 0 < a.line <= len(lines):
        cm = re.search(r'\(\s*(\w[\w]*)\s*\*\s*\)\s*(?:malloc|calloc|realloc)', lines[a.line - 1])
        if cm:
            return cm.group(1)
    return ""
