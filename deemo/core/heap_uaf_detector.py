"""
基于反编译伪代码与模式匹配+轻量数据流的堆漏洞与UAF静态检测。
覆盖: UAF(free后解引用)、双重释放、堆溢出(写入超过malloc分配大小)。
纯静态分析, 不依赖angr符号执行, 作为快速扫描层。
"""


import logging
import re
from typing import Any, Dict, List, Optional, Tuple

_log = logging.getLogger(__name__)

# 内存分配/释放函数
_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', 'memalign', 'aligned_alloc'}
_FREE_FUNCS = {'free', 'realloc'}
# 可能写入堆缓冲区的危险函数
_HEAP_WRITE_FUNCS = {
    'memcpy', 'memmove', 'strcpy', 'strncpy', 'strcat', 'strncat',
    'gets', 'fgets', 'read', 'fread', 'recv', 'sprintf', 'snprintf',
}


def _find_allocations(pseudocode: str) -> List[Dict[str, Any]]:
    """从伪代码中提取所有分配点, 返回 [{var, func, size, line}, ...]。"""
    allocs = []
    for m in re.finditer(
        r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\))?\s*(malloc|calloc|realloc|memalign|aligned_alloc)\s*\(([^)]+)\)',
        pseudocode,
    ):
        var = m.group(1)
        func = m.group(2)
        size_expr = m.group(3).strip()
        size = _parse_size(size_expr)
        allocs.append({
            'variable': var, 'function': func,
            'size_expression': size_expr[:60],
            'estimated_size': size, 'line': m.group(0)[:120],
        })
    return allocs


def _find_frees(pseudocode: str) -> List[Dict[str, Any]]:
    """提取所有释放点, 返回 [{var, func, line}, ...]。"""
    frees = []
    for m in re.finditer(
        r'(free)\s*\(\s*(\w+)\s*\)',
        pseudocode,
    ):
        frees.append({
            'function': m.group(1),
            'variable': m.group(2),
            'line': m.group(0)[:120],
        })
    return frees


def _find_pointer_uses(pseudocode: str, ptr_var: str) -> List[str]:
    """查找伪代码中的指针解引用点, 匹配 *ptr / ptr->field / ptr[expr] / ptr+offset。"""
    refs = []
    for m in re.finditer(
        rf'(\*{ptr_var}\b|{ptr_var}\s*->|{ptr_var}\s*\[|{ptr_var}\s*\+)',
        pseudocode,
    ):
        refs.append(m.group(0))
    return refs


def _parse_size(expr: str) -> int:
    """尝试解析大小表达式中的字节数, 失败返回 -1。"""
    expr = expr.strip()
    # 纯整数字面量
    try:
        return int(expr)
    except ValueError:
        pass
    # sizeof(类型) 或 sizeof(*ptr)
    sizeof_match = re.match(r'sizeof\s*\(\s*(\w+)\s*\)', expr)
    if sizeof_match:
        type_name = sizeof_match.group(1)
        sizes = {'int': 4, 'long': 8, 'char': 1, 'short': 2,
                 'float': 4, 'double': 8, 'void': 1, 'size_t': 8,
                 'uint32_t': 4, 'uint64_t': 8, 'int32_t': 4, 'int64_t': 8}
        return sizes.get(type_name, -1)
    # 乘法: n * sizeof(类型)
    mul_match = re.match(r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', expr)
    if mul_match:
        sizes = {'int': 4, 'long': 8, 'char': 1}
        ts = sizes.get(mul_match.group(2), 4)
        try:
            return int(mul_match.group(1)) * ts
        except ValueError:
            pass
    return -1


def detect_uaf(
    pseudocode: str,
    func_name: str = "",
) -> List[Dict[str, Any]]:
    """检测 UAF: 对每对 (free(p), p解引用) 检查时序, 解引用出现在 free 之后 → 候选。"""
    findings = []
    frees = _find_frees(pseudocode)
    if not frees:
        return findings

    lines = pseudocode.split('\n')

    for fr in frees:
        ptr = fr['variable']
        # 查找 free 之后的指针使用行
        free_pos = -1
        for i, line in enumerate(lines):
            if ptr in line and 'free' in line:
                free_pos = i
                break

        if free_pos < 0:
            continue

        # 查找 free 之后的指针使用
        uses_after = []
        for i in range(free_pos + 1, min(len(lines), free_pos + 50)):
            if re.search(rf'\*{ptr}\b|{ptr}\s*->|{ptr}\s*\[', lines[i]):
                uses_after.append(lines[i].strip()[:120])

        if uses_after:
            findings.append({
                'vuln_type': 'use-after-free',
                'function': func_name,
                'freed_variable': ptr,
                'free_location': fr['line'][:120],
                'use_after': uses_after[:3],
                'confidence': 0.70,
                'description': (
                    f'Pointer {ptr} freed then dereferenced in {func_name}'
                ),
                'exploitation': (
                    'Heap spray to reclaim freed chunk → control dangling pointer '
                    '→ vtable/function pointer overwrite / data-only attack'
                ),
            })

    return findings


def detect_double_free(
    pseudocode: str,
    func_name: str = "",
) -> List[Dict[str, Any]]:
    """检测双重释放: 同一变量传入 free() 两次以上。"""
    findings = []
    freed_vars: Dict[str, int] = {}

    for m in re.finditer(r'free\s*\(\s*(\w+)\s*\)', pseudocode):
        var = m.group(1)
        freed_vars[var] = freed_vars.get(var, 0) + 1

    for var, count in freed_vars.items():
        if count >= 2:
            findings.append({
                'vuln_type': 'double-free',
                'function': func_name,
                'freed_variable': var,
                'free_count': count,
                'confidence': 0.80 if count >= 2 else 0.50,
                'description': (
                    f'Variable {var} passed to free() {count} times in {func_name}'
                ),
                'exploitation': (
                    'First free → chunk in tcache/fastbin → second free → '
                    'corrupt free list → arbitrary alloc → write primitive'
                ),
            })

    return findings


def detect_heap_overflow(
    pseudocode: str,
    func_name: str = "",
) -> List[Dict[str, Any]]:
    """检测堆溢出: 写入大小超过 malloc 分配大小。"""
    findings = []
    allocs = _find_allocations(pseudocode)

    for alloc in allocs:
        if alloc['estimated_size'] <= 0:
            continue

        var = alloc['variable']
        alloc_size = alloc['estimated_size']

        # 查找写入该变量的调用
        for write_func in _HEAP_WRITE_FUNCS:
            for m in re.finditer(
                rf'{write_func}\s*\(\s*{re.escape(var)}\s*,[^,)]*,\s*(\d+)\s*\)',
                pseudocode,
            ):
                write_size = int(m.group(1))
                if write_size > alloc_size:
                    findings.append({
                        'vuln_type': 'heap-overflow',
                        'function': func_name,
                        'buffer_variable': var,
                        'allocation_size': alloc_size,
                        'write_function': write_func,
                        'write_size': write_size,
                        'overflow_bytes': write_size - alloc_size,
                        'confidence': 0.75,
                        'description': (
                            f'{write_func}({var}, src, {write_size}) writes '
                            f'{write_size - alloc_size} bytes past {alloc_size}B '
                            f'buffer allocated by {alloc["function"]}()'
                        ),
                        'exploitation': (
                            'Overwrite adjacent heap chunk metadata → '
                            'corrupt free list / unsorted bin → '
                            'arbitrary write primitive / house-of-force'
                        ),
                    })

    return findings


def analyze_heap_vulnerabilities(
    binary_path: str,
    func_name: Optional[str] = None,
    pseudocode: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """综合堆漏洞检测: UAF、双重释放与堆溢出, 按置信度降序返回结果。"""
    findings: List[Dict[str, Any]] = []

    if pseudocode:
        all_pseudocode = {func_name or 'unknown': pseudocode}
    elif func_name:
        try:
            from core.decompiler import decompile_function
            decomp = decompile_function(binary_path, func_name)
            all_pseudocode = {func_name: decomp.get('pseudocode', '')}
        except Exception:
            return findings
    else:
        # 全量扫描所有用户函数 — 开销大, 需显式调用
        return findings

    for fname, pcode in all_pseudocode.items():
        if not pcode:
            continue
        findings.extend(detect_uaf(pcode, fname))
        findings.extend(detect_double_free(pcode, fname))
        findings.extend(detect_heap_overflow(pcode, fname))

    findings.sort(key=lambda f: (-f['confidence'], f.get('vuln_type', '')))
    return findings
