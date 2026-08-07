"""
堆分配点提取器 — 从IR行中识别 malloc/calloc/realloc 调用点.

2026-08-07: 新增表达式参数支持 (malloc(n*4+8), malloc(len+1))
            新增 kmalloc/grub_malloc/OPENSSL_malloc 等变体支持
"""
import re

from core.heap_overflow_detector import HeapAllocSite


def _resolve_sizeof(expr: str) -> int:
    """解析 sizeof 表达式为具体字节数.

    支持: sizeof(int)=4, sizeof(char)=1, sizeof(long)=8 (LP64),
          sizeof(void*)=8, sizeof(uint16_t)=2 等.
    返回 0 表示无法解析.
    """
    _SIZEOF_MAP = {
        'char': 1, 'unsigned char': 1, 'signed char': 1,
        'short': 2, 'unsigned short': 2, 'uint16_t': 2, 'int16_t': 2,
        'int': 4, 'unsigned int': 4, 'uint32_t': 4, 'int32_t': 4,
        'float': 4,
        'long': 8, 'unsigned long': 8, 'uint64_t': 8, 'int64_t': 8,
        'long long': 8, 'unsigned long long': 8,
        'double': 8,
        'void*': 8, 'void *': 8, 'size_t': 8, 'ssize_t': 8,
        'intptr_t': 8, 'uintptr_t': 8,
    }
    m = re.search(r'sizeof\s*\(\s*(.+?)\s*\)', expr, re.IGNORECASE)
    if not m:
        return 0
    type_name = m.group(1).strip().lower()
    type_name = re.sub(r'\bconst\b\s*', '', type_name).strip()
    return _SIZEOF_MAP.get(type_name, 0)


def _parse_alloc_size(size_str: str) -> tuple[int, bool, str]:
    """解析分配大小: 常量→变量→表达式.
    返回 (size, is_dynamic, size_expr)."""
    try:
        return (int(size_str, 0), False, size_str)
    except (ValueError, TypeError):
        pass
    expr = size_str.strip()
    # 纯变量引用
    var_m = re.match(r'^(\w+)$', expr)
    if var_m:
        return (0, True, var_m.group(1))
    # 算术表达式: n*4+8, payload_sz+16, len+1
    if re.search(r'[+\-*/]', expr):
        return (0, True, expr)
    return (0, True, expr)


# 支持的分配函数名 (标准库 + 内核 + 常见封装)
_ALLOC_FUNCS = (
    r'malloc|calloc|realloc'
    r'|kmalloc|kcalloc|krealloc'
    r'|grub_malloc|grub_calloc|grub_realloc'
    r'|OPENSSL_malloc|OPENSSL_zalloc'
)


def extract_heap_allocations(ir_lines: list[str]) -> list[HeapAllocSite]:
    """Extract heap allocation sites from IR lines.

    支持 struct 字段 LHS: field->value = malloc(n)
    支持表达式参数: malloc(n*4+8), malloc(len+1)
    两遍扫描: 主regex (简单参数) + 回退regex (表达式参数).
    """
    allocs = []
    lhs = r'(?:(\w+(?:->\w+)?(?:\s*\[\s*\w+\s*\])?)\s*=\s*)?'
    func_grp = rf'({_ALLOC_FUNCS})'

    # 主模式: 简单参数 (数字/变量/sizeof)
    alloc_pattern = re.compile(
        lhs + func_grp + r'\s*\(\s*(\d+|\w+(?:->\w+)?)\s*'
        r'(?:,\s*(\d+|\w+|sizeof\s*\([^)]+\)))?\s*\)',
        re.IGNORECASE,
    )
    # 回退模式: 参数含算术表达式 (payload_sz+16, n*4+8, len-1)
    expr_pattern = re.compile(
        lhs + func_grp + r'\s*\(\s*'
        r'([^,)]+(?:\s*[+\-*/]\s*[^,)]+)+)\s*'
        r'(?:,\s*([^,)]+))?\s*\)',
        re.IGNORECASE,
    )

    for i, line in enumerate(ir_lines):
        m = alloc_pattern.search(line)
        if not m:
            m = expr_pattern.search(line)
            if not m:
                continue
        result_var = m.group(1) or ''
        func = m.group(2).lower()
        arg1 = m.group(3)
        arg2 = m.group(4) or ''

        if func in ('realloc', 'krealloc', 'grub_realloc'):
            size_str = arg2 or arg1
        elif func in ('calloc', 'kcalloc'):
            size_str = arg1
        else:
            size_str = arg1

        size, is_dynamic, size_expr = _parse_alloc_size(size_str)

        elem_size = 0
        if func in ('calloc', 'kcalloc') and arg2:
            elem_size = _resolve_sizeof(arg2)
            if elem_size == 0:
                try:
                    elem_size = int(arg2, 0)
                except (ValueError, TypeError):
                    pass
            if elem_size > 0 and size > 0:
                new_size = size * elem_size
                overflow_detected = False
                if new_size < max(size, elem_size) and size > 0 and elem_size > 0:
                    overflow_detected = True
                if new_size > 2_000_000_000:
                    overflow_detected = True
                size = new_size
                if overflow_detected:
                    is_dynamic = True
                    size = min(size, 2**31 - 1)

        allocs.append(HeapAllocSite(
            pc=i, alloc_func=func, size_arg=size,
            size_is_dynamic=is_dynamic, result_var=result_var,
            elem_size=elem_size, size_expr=size_expr,
        ))

        # struct 字段分配: field->value = malloc(n)
        if '->' in result_var:
            field_name = result_var.rsplit('->', 1)[-1]
            allocs.append(HeapAllocSite(
                pc=i, alloc_func=func, size_arg=size,
                size_is_dynamic=is_dynamic, result_var=field_name,
                elem_size=elem_size, size_expr=size_expr,
            ))

    return allocs
