"""
C源码堆操作扫描器辅助函数集 — write finding构造 / free检测 / 配对 / 用户输入追踪。

保持单一职责
"""
import re
from typing import Any, Dict, List, Optional

from tests.source_matcher import (
    WRITE_RE, ARRAY_WRITE_RE,
    match_alloc, extract_base_ptr, extract_macros, find_nearest_alloc,
)
from tests.source_classifier import (
    eval_size as _eval_size,
    compute_glibc_effective as _compute_glibc_effective,
    classify_finding,
)
from tests.source_scanner_helpers import (
    _find_return_alloc_funcs,
    _extract_cross_func_allocs,
    _extract_multiline_writes,
    _extract_deref_writes,
)
from tests.loop_analyzer import (
    _aggregate_loop_writes,
    _detect_off_by_one,
)


def _extract_write_finding(line: str, line_no: int, func: str,
                           args: List[str], findings: List[Dict],
                           macros: dict = None):
    """从 WRITE_RE 匹配结果构造 finding entry。"""
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
            write_size = _eval_size(size_expr, macros)
    elif func == 'memset':
        if len(args) >= 3:
            size_expr = args[2].strip()
            write_size = _eval_size(size_expr, macros)
    elif func in ('strcpy', 'strcat', 'sprintf'):
        write_size = 999999

    findings.append({
        'type': 'write', 'func': func,
        'ptr': base_ptr, 'ptr_full': ptr_expr,
        'write_size': write_size, 'size_expr': size_expr,
        'line_no': line_no, 'line': line,
    })


def _extract_free_finding(line: str, line_no: int,
                          alloc_list: List[Dict], findings: List[Dict]):
    """匹配 free(ptr) 并构造 UAF entry (如果已分配)。"""
    free_m = re.search(r'free\s*\(\s*(\w[\w\d_]*)\s*\)\s*;', line)
    if free_m:
        ptr = free_m.group(1)
        if find_nearest_alloc(alloc_list, ptr, line_no):
            findings.append({
                'type': 'free', 'func': 'free',
                'ptr': ptr, 'line_no': line_no, 'line': line,
            })


def _pair_ops(findings: List[Dict], alloc_list: List[Dict],
              macros: Dict[str, int], source: str = '',
              alias_map: Dict[str, str] = None) -> List[Dict]:
    """将写入/free 配对到最近分配, 计算溢出判定。

    配对策略 (按优先级):
      1. 完整表达式精确匹配: ptr_full (op->data) == alloc ptr_var (op->data)
      2. 基指针匹配: ptr (op) 匹配 alloc ptr_var (op->data) 或 base_ptr (op)
      3. 简单名匹配: ptr (op) == alloc ptr_var (op)
      4. 别名链追踪: ptr (dangling) → alias_map[dangling] (reg->buf) → 递归 1-3
    """
    paired = []
    alias_map = alias_map or {}
    for f in findings:
        if f['type'] in ('write', 'array_write'):
            ptr_full = f.get('ptr_full', '')
            ptr = f['ptr']
            alloc = None
            if ptr_full:
                alloc = find_nearest_alloc(alloc_list, ptr_full, f['line_no'])
            if alloc is None:
                alloc = find_nearest_alloc(alloc_list, ptr, f['line_no'])
            if alloc is None and ptr in alias_map:
                alias_target = alias_map[ptr]
                for _ in range(3):
                    alloc = find_nearest_alloc(alloc_list, alias_target, f['line_no'])
                    if alloc is not None:
                        break
                    if alias_target in alias_map:
                        alias_target = alias_map[alias_target]
                    else:
                        break
            if alloc:
                candidate = {
                    'ptr_var': ptr,
                    'alloc_func': alloc['func'],
                    'alloc_size_expr': alloc['size_expr'],
                    'alloc_line': alloc['line_no'],
                    'alloc_line_text': alloc['line'],
                    'write_func': f['func'],
                    'write_size': f['write_size'],
                    'write_size_expr': f['size_expr'],
                    'write_line': f['line_no'],
                    'write_line_text': f['line'],
                    'type': f['type'],
                    'idx_var': f.get('idx_var', ''),
                    'user_controlled': f.get('user_controlled', False),
                }
                req_size = _eval_size(alloc['size_expr'], macros)
                eff_size = _compute_glibc_effective(req_size) if req_size > 0 else 0
                candidate['alloc_requested'] = req_size
                candidate['alloc_effective'] = eff_size
                if eff_size > 0 and f['write_size'] > 0:
                    candidate['is_overflow'] = f['write_size'] > eff_size
                else:
                    candidate['is_overflow'] = True
                paired.append(candidate)

    for f in findings:
        if f['type'] == 'free':
            ptr = f['ptr']
            alloc = find_nearest_alloc(alloc_list, ptr, f['line_no'])
            if alloc:
                paired.append({
                    'ptr_var': ptr,
                    'alloc_func': alloc['func'],
                    'alloc_size_expr': alloc['size_expr'],
                    'alloc_line': alloc['line_no'],
                    'alloc_line_text': alloc['line'],
                    'write_func': 'use-after-free',
                    'write_size': 0, 'write_line': f['line_no'],
                    'write_line_text': f['line'],
                    'type': 'uaf', 'is_overflow': False,
                    'alloc_effective': 0,
                })
    paired = _aggregate_loop_writes(paired, source)
    paired = _detect_off_by_one(paired, source)
    return paired


_USER_INPUT_SRC_RE = re.compile(
    r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\('
    r'|(\w+)\s*=\s*argv\['
    r'|(\w+)\s*=\s*getenv\s*\('
    r'|(?:f?scanf)\s*\([^)]*"[^"]*"[^)]*&(\w+)'
    r'|fgets\s*\(\s*(\w+)\s*,'
    r'|recv\s*\([^,]+,\s*(\w+)\s*,',
)


def _find_user_input_vars(source: str) -> set:
    """追踪用户/外部输入变量名 (来自 atoi/argv/scanf/getenv/fgets/recv)。"""
    uv = set()
    for m in re.finditer(
            r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\(',
            source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*argv\[', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*getenv\s*\(', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(?:f?scanf)\s*\([^)]*"[^"]*"[^)]*&(\w+)', source):
        uv.add(m.group(1))
    for m in re.finditer(r'fgets\s*\(\s*(\w+)\s*,', source):
        uv.add(m.group(1))
    for m in re.finditer(r'recv\s*\([^,]+,\s*(\w+)\s*,', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*[^?]+\?\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(?:atoi|atol|strtol)\s*\(\s*argv\[', source):
        uv.add(m.group(1))
    for m in re.finditer(r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)\s*\(', source):
        uv.add(m.group(1))
    return uv
