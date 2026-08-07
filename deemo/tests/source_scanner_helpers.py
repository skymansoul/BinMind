"""
source_scanner 辅助函数 — 跨函数分配追踪 / 多行写入 / 循环聚合 / off-by-one检测。

保持单一职责
"""
import re
from typing import Any, Dict, List

from tests.source_matcher import (
    WRITE_RE, ARRAY_WRITE_RE,
    match_alloc, extract_base_ptr, extract_macros, find_nearest_alloc,
)

# 跨函数分配追踪 (return malloc / ptr = alloc_func(args))

# void/int*/char* func_name(...)  — 提取函数名
_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|size_t|long|short|float|double|uint\w+_t|int\w+_t'
    r'|unsigned(?:\s+(?:int|char|short|long))?)'
    r'\s*\*?\s*(\w+)\s*\([^)]*\)\s*\{?',
)

# ptr = func_name(args); — 跨函数分配调用
_CROSS_FUNC_CALL_RE = re.compile(
    r'(\w[\w\d_]*)\s*=\s*'
    r'(?:\(\s*\w+\s*\*?\s*\)\s*)?'
    r'(\w+)\s*\(([^;]*)\)\s*;',
)


def _find_return_alloc_funcs(source: str) -> dict:
    """预扫描: 找到 return (type*)malloc(...) 的函数, 返回 {func_name: {func, size_expr}}。"""
    from tests.source_matcher import _RETURN_ALLOC_RE
    funcs = {}
    lines = source.splitlines()
    current_func = None
    for i, raw_line in enumerate(lines):
        line = raw_line.strip()
        # 追踪当前函数上下文
        fm = _FUNC_DEF_RE.match(line)
        if fm and '{' in line:
            current_func = fm.group(1)
        elif re.match(r'\}\s*$', line):
            current_func = None
        # 检测 return malloc
        rm = _RETURN_ALLOC_RE.search(line)
        if rm and current_func:
            funcs[current_func] = {
                'func': rm.group(1).lower(),
                'size_expr': rm.group(2).strip(),
            }
    return funcs


def _extract_cross_func_allocs(source: str, alloc_list: List[Dict],
                                return_alloc_funcs: dict, macros: dict):
    """检测 ptr = func(args) 其中 func 是 return-malloc 函数, 加入分配列表。"""
    for m in _CROSS_FUNC_CALL_RE.finditer(source):
        ptr_var = m.group(1)
        func_name = m.group(2)
        if func_name in return_alloc_funcs:
            ra = return_alloc_funcs[func_name]
            line_no = source[:m.start()].count('\n') + 1
            alloc_list.append({
                'ptr_var': ptr_var,
                'base_ptr': extract_base_ptr(ptr_var),
                'func': ra['func'],
                'size_expr': ra['size_expr'],
                'line_no': line_no,
                'line': source.splitlines()[line_no - 1].strip() if line_no <= len(source.splitlines()) else '',
                'cross_func': func_name,
            })


# 多行写入 / 指针解引用 / 循环聚合

# 多行函数调用: memcpy(\n  buf,\n  data,\n  64\n);
_MULTILINE_WRITE_RE = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|'
    r'sprintf|snprintf|read|fread|recv|gets|scanf)'
    r'\s*\(\s*([^;]+?)\s*\)\s*;',
    re.IGNORECASE | re.DOTALL,
)

# 指针解引用赋值: *(type*)(ptr+offset) = value;
_DEREF_WRITE_RE = re.compile(
    r'\*\s*(?:\(\s*\w+(?:\s+\w+)?\s*\*?\s*\)\s*)?'
    r'\(\s*(\w+)\s*\+\s*(\d+)\s*\)'
    r'\s*=\s*[^;]+;',
)

# 简单指针偏移: buf + N
_PTR_OFFSET_RE = re.compile(r'(\w+)\s*\+\s*(\d+)')


def _extract_multiline_writes(source: str, findings: List[Dict],
                              macros: dict = None):
    """全源扫描跨行 memcpy/strcpy 等调用。"""
    for m in _MULTILINE_WRITE_RE.finditer(source):
        func = m.group(1).lower()
        args_str = m.group(2)
        line_no = source[:m.start()].count('\n') + 1
        line_text = source.splitlines()[line_no - 1] if line_no <= len(source.splitlines()) else ''
        args = _parse_args(args_str)
        _extract_write_finding(line_text, line_no, func, args, findings, macros)


def _parse_args(args_str: str) -> List[str]:
    """逗号分隔参数解析 (处理嵌套括号和引号)。"""
    args = []
    depth = 0
    in_str = False
    current = []
    for ch in args_str:
        if ch == '"' and (not current or current[-1] != '\\'):
            in_str = not in_str
        if not in_str:
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
        if ch == ',' and depth == 0 and not in_str:
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current).strip())
    return args


def _extract_deref_writes(source: str, findings: List[Dict],
                          macros: dict = None):
    """提取 *(type*)(ptr+offset) = value 指针解引用写入。"""
    lines = source.splitlines()
    for m in re.finditer(
            r'\*\s*(?:\(\s*\w+(?:\s+\w+)?\s*\*?\s*\)\s*)?'
            r'\(\s*(\w+)\s*\+\s*(\d+)\s*\)\s*=\s*',
            source):
        ptr = m.group(1)
        try:
            offset = int(m.group(2))
        except ValueError:
            offset = 0
        line_no = source[:m.start()].count('\n') + 1
        line_text = lines[line_no - 1].strip() if line_no <= len(lines) else ''
        type_size = 4  # 默认 int/pointer
        type_m = re.search(r'\*\s*\(\s*(\w+(?:\s+\w+)?)\s*\*?\s*\)', m.group(0))
        if type_m:
            type_name = type_m.group(1).split()[-1]
            type_sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8,
                          'float': 4, 'double': 8, 'size_t': 8}
            type_size = type_sizes.get(type_name, 4)
        findings.append({
            'type': 'write', 'func': 'deref_store',
            'ptr': ptr, 'ptr_full': m.group(0).rstrip(' ='),
            'write_size': offset + type_size, 'size_expr': str(offset + type_size),
            'line_no': line_no, 'line': line_text,
        })

# ── 内联辅助: 为 _extract_multiline_writes 提供 write finding 构造 ──
def _extract_write_finding(line: str, line_no: int, func: str,
                           args: List[str], findings: List[Dict],
                           macros: dict = None):
    """从 WRITE_RE 匹配结果构造 finding entry (source_scanner 中同名函数的副本)。"""
    if func not in ('memcpy', 'memmove', 'memset', 'strcpy', 'strncpy',
                    'strcat', 'strncat', 'sprintf', 'snprintf'):
        return
    if len(args) < 1:
        return
    ptr_expr = args[0].strip()
    base_ptr = extract_base_ptr(ptr_expr)

    for existing in findings:
        if (existing.get('line_no') == line_no
                and existing.get('ptr') == base_ptr
                and existing.get('func') == func):
            return

    write_size = 0
    size_expr = ''
    if func in ('memcpy', 'memmove', 'strncpy', 'strncat', 'snprintf'):
        if len(args) >= 3:
            size_expr = args[2].strip()
            from tests.source_classifier import eval_size
            write_size = eval_size(size_expr, macros)
    elif func == 'memset':
        if len(args) >= 3:
            size_expr = args[2].strip()
            from tests.source_classifier import eval_size
            write_size = eval_size(size_expr, macros)
    elif func in ('strcpy', 'strcat', 'sprintf'):
        write_size = 999999

    findings.append({
        'type': 'write', 'func': func,
        'ptr': base_ptr, 'ptr_full': ptr_expr,
        'write_size': write_size, 'size_expr': size_expr,
        'line_no': line_no, 'line': line,
    })
