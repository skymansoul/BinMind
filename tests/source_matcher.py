"""
堆操作模式匹配器 —— C源码中的 malloc/calloc/realloc/memcpy/array_store 模式提取。
为 source_scanner.py 提供正则引擎和通用参数解析
"""
import re
from typing import Any, Dict, List, Optional


# 分配模式: 处理 C 源码中的各种 malloc 形式
# 组: ptr_var, func, size_args
# 支持结构体成员: op->data = malloc(...) / obj.field = malloc(...)
_ALLOC_RE = re.compile(
    r'(\w[\w\d_]*(?:\s*->\s*\w[\w\d_]*|\s*\.\s*\w[\w\d_]*)?)\s*=\s*'  # ptr_var or ptr->field =
    r'(?:\(\s*[\w\s\*]+\)\s*)?'                  # 可选类型转换 (char*) / (HostentBuf *)
    r'(malloc|calloc|realloc)\s*\(\s*'               # alloc_func(
    r'(.+?)\s*\)'                                    # size_args)  非贪婪
    r'\s*;',                                         # ;
    re.IGNORECASE,
)

# 回退: 处理嵌套括号中的 size 表达式
_ALLOC_RE_V2 = re.compile(
    r'(\w[\w\d_]*(?:\s*->\s*\w[\w\d_]*|\s*\.\s*\w[\w\d_]*)?)\s*=\s*'
    r'(?:\(\s*[\w\s\*]+\)\s*)?'
    r'(malloc|calloc|realloc)\s*\(([^;]+)\)\s*;',
    re.IGNORECASE,
)

# return (type *)malloc(size); — 跨函数分配
_RETURN_ALLOC_RE = re.compile(
    r'return\s+'
    r'(?:\(\s*\w+(?:\s+\w+)?\s*\*?\s*\)\s*)?'      # 可选类型转换
    r'(malloc|calloc|realloc)\s*\(\s*'               # alloc_func(
    r'(.+?)\s*\)'                                    # size_args)
    r'\s*;',
    re.IGNORECASE,
)

# arr[idx] = (type *)malloc(size); — 数组元素分配
_ARRAY_ALLOC_RE = re.compile(
    r'(\w[\w\d_]*)\s*\[\s*\w[\w\d_]*\s*\]\s*=\s*'  # arr[idx] =
    r'(?:\(\s*\w+\s*\*?\s*\)\s*)?'                  # 可选类型转换
    r'(malloc|calloc|realloc)\s*\(([^;]+)\)\s*;',
    re.IGNORECASE,
)

# 写入/危险函数模式
# 支持目标为结构体成员: memset(op->data, ...) / memcpy(rf->regs+offset, ...)
_WRITE_RE = re.compile(
    r'(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat|'
    r'sprintf|snprintf|read|fread|recv|gets|scanf)\s*\(([^;]+)\)\s*;',
    re.IGNORECASE,
)

# 数组索引写入模式 (含结构体成员)
# 支持: buf[i] = ... / op->data[i] = ... / obj.field[i] = ...
_ARRAY_WRITE_RE = re.compile(
    r'(\w[\w\d_]*(?:\s*->\s*\w[\w\d_]*|\s*\.\s*\w[\w\d_]*)?)\s*\[\s*(\w[\w\d_]*)\s*\]\s*=\s*',
)

# 循环边界模式
_LOOP_BOUND_RE = re.compile(
    r'for\s*\(\s*\w+\s*=\s*\d+\s*;\s*\w+\s*[<]\s*(\w+)\s*;\s*\w+\+\+\s*\)',
)

# 守卫条件
_GUARD_CHECK_RE = re.compile(
    r'if\s*\(\s*(\w+)\s*(<=?|>=?)\s*(\d+|\w+)\s*\)',
)

# define 常量模式
_DEFINE_RE = re.compile(
    r'#define\s+(\w+)\s+(\d+(?:\.\d+)?)\s*',
)

# 导出正则对象 (供 source_scanner 使用)
ALLOC_RE = _ALLOC_RE
ALLOC_RE_V2 = _ALLOC_RE_V2
RETURN_ALLOC_RE = _RETURN_ALLOC_RE
ARRAY_ALLOC_RE = _ARRAY_ALLOC_RE
WRITE_RE = _WRITE_RE
ARRAY_WRITE_RE = _ARRAY_WRITE_RE
LOOP_BOUND_RE = _LOOP_BOUND_RE
GUARD_CHECK_RE = _GUARD_CHECK_RE
DEFINE_RE = _DEFINE_RE


def match_alloc(line: str) -> Optional[Dict]:
    """匹配堆分配语句, 返回 {ptr_var, func, size_expr}。

    支持的 C 模式:
      - var = malloc(size);
      - var = (type*)malloc(size);
      - arr[i] = (type*)malloc(size);  → ptr_var='arr' (数组元素)
      - return (type*)malloc(size);    → ptr_var=None (跨函数, 需调用方追踪)
    """
    # return (type *)malloc(size);
    rm = _RETURN_ALLOC_RE.search(line)
    if rm:
        return {
            'ptr_var': None,  # 返回分配, ptr_var 由调用方决定
            'func': rm.group(1).lower(),
            'size_expr': _clean_size_expr(rm.group(2)),
            'alloc_type': 'return_alloc',
        }

    # arr[idx] = (type *)malloc(size);
    am = _ARRAY_ALLOC_RE.search(line)
    if am:
        size_raw = am.group(3).strip()
        size_expr = _clean_size_expr(size_raw)
        return {
            'ptr_var': am.group(1),  # 数组名 (不含索引)
            'func': am.group(2).lower(),
            'size_expr': size_expr,
            'alloc_type': 'array_element',
        }

    # var = malloc(size); / var = (type*)malloc(size);
    # 先尝试简单版本 (无嵌套)
    m = _ALLOC_RE.search(line)
    if m:
        func = m.group(2).lower()
        size_raw = m.group(3).strip()
        size_expr = _clean_size_expr(size_raw)
        # realloc(ptr, size) → 需要提取第二个参数
        if func == 'realloc':
            parts = _parse_args(size_raw)
            if len(parts) >= 2:
                size_expr = _clean_size_expr(parts[1])
        return {
            'ptr_var': m.group(1),
            'func': func,
            'size_expr': size_expr,
            'alloc_type': 'simple',
        }
    # 回退: V2 (宽松匹配, 手动提取到闭合括号)
    m2 = _ALLOC_RE_V2.search(line)
    if m2:
        size_raw = m2.group(3).strip()
        size_expr = _clean_size_expr(size_raw)
        if m2.group(2).lower() == 'realloc':
            parts = _parse_args(size_raw)
            if len(parts) >= 2:
                size_expr = _clean_size_expr(parts[1])
        return {
            'ptr_var': m2.group(1),
            'func': m2.group(2).lower(),
            'size_expr': size_expr,
            'alloc_type': 'simple',
        }
    return None


def _clean_size_expr(expr: str) -> str:
    """清理 size 表达式: 去掉类型转换和多余空格。"""
    expr = expr.strip()
    expr = re.sub(r'\(\s*(?:size_t|unsigned(?:\s+int)?|int|long|uint\w+_t)\s*\)\s*', '', expr)
    while expr.startswith('(') and expr.endswith(')'):
        depth = 0
        ok = True
        for i, ch in enumerate(expr):
            if ch == '(': depth += 1
            elif ch == ')': depth -= 1
            if depth == 0 and i < len(expr) - 1:
                ok = False
                break
        if ok:
            expr = expr[1:-1].strip()
        else:
            break
    return expr


def _parse_args(args_str: str) -> List[str]:
    """简易逗号分隔参数解析, 处理嵌套括号。"""
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
            args.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        args.append(''.join(current).strip())
    return args


def extract_base_ptr(ptr_expr: str) -> str:
    """从 ptr+offset / ptr[idx] / ptr->field 提取基指针名称。"""
    # ptr+offset / ptr-offset
    m = re.match(r'(\w[\w\d_]*)\s*[+\-]', ptr_expr)
    if m:
        return m.group(1)
    # ptr[idx] / ptr[i]
    m = re.match(r'(\w[\w\d_]*)\s*\[', ptr_expr)
    if m:
        return m.group(1)
    # ptr->field
    m = re.match(r'(\w[\w\d_]*)\s*->', ptr_expr)
    if m:
        return m.group(1)
    return ptr_expr.strip()


def extract_macros(source: str) -> Dict[str, int]:
    """提取 #define 常量映射。"""
    macros = {}
    for line in source.splitlines():
        m = _DEFINE_RE.match(line.strip())
        if m:
            try:
                macros[m.group(1)] = int(m.group(2))
            except ValueError:
                pass
    return macros


def find_nearest_alloc(alloc_list: List[Dict], ptr_var: str, write_line: int) -> Optional[Dict]:
    """在 write_line 之前, 找 ptr_var 的最近分配 (按行号降序)。

    支持结构体成员的双向匹配:
      - 分配 op->data, 写入 op->data → 精确匹配
      - 分配 op->data, 写入 op → 基指针回退
      - 分配 op, 写入 op->data → 基指针回退
    """
    best = None
    # 1. 精确匹配 ptr_var
    for a in alloc_list:
        if a['ptr_var'] == ptr_var and a['line_no'] < write_line:
            if best is None or a['line_no'] > best['line_no']:
                best = a
    if best is not None:
        return best
    # 2. 基指针匹配: 写入 op->data → 找分配 ptr_var=op 或 base_ptr=op
    base = extract_base_ptr(ptr_var)
    if base != ptr_var:
        for a in alloc_list:
            if a['line_no'] >= write_line:
                continue
            if a.get('base_ptr') == base or a['ptr_var'] == base:
                if best is None or a['line_no'] > best['line_no']:
                    best = a
    return best
