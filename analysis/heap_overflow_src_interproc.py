"""
堆溢出源级跨函数分析 — 解析工厂函数分配和跨函数写入.

模式1 (工厂函数): buf = make_buf(64); make_buf内 return malloc(sz)
模式2 (跨函数写入): copy_data(buf, data, 128); copy_data内 memcpy(dst, src, len)
"""

import re
from typing import Dict, List, Optional, Tuple

from analysis.heap_overflow_types import HeapAllocSite, HeapWriteSite
from analysis.heap_overflow_src_patterns import (
    _MALLOC_ASSIGN_RE, _MEMCPY_HEAP_RE, _MEMSET_HEAP_RE,
    _STRCPY_HEAP_RE, _READ_HEAP_RE, _is_comment_or_empty,
    _base_var, parse_alloc_size,
)
from analysis.heap_overflow_src_interproc_helpers import (
    callee_guard_bounds as _callee_guard_bounds,
    resolve_callee_loop_bound as _resolve_callee_loop_bound,
)


_FUNC_DEF_RE = re.compile(
    r'\b(?:\w[\w]*\s+\*?\s*|\*\s*)?(\w[\w]*)\s*\(([^)]*)\)\s*\{')


def _split_functions(lines: List[str]) -> Dict[str, Tuple[List[str], List[str]]]:
    """将源码拆分为 {func_name: (params, body_lines)}."""
    funcs: Dict[str, Tuple[List[str], List[str]]] = {}
    i = 0
    while i < len(lines):
        text = lines[i].strip()
        if _is_comment_or_empty(text):
            i += 1
            continue
        m = _FUNC_DEF_RE.search(text)
        if m and not text.startswith(('if', 'for', 'while', 'switch')):
            name = m.group(1)
            params_str = m.group(2).strip()
            params = _parse_params(params_str)
            body = []
            depth = text.count('{') - text.count('}')
            j = i + 1
            while j < len(lines) and depth > 0:
                body.append(lines[j])
                depth += lines[j].count('{') - lines[j].count('}')
                j += 1
            if name not in ('if', 'for', 'while', 'switch', 'main') or body:
                funcs[name] = (params, body)
            i = j
        else:
            i += 1
    return funcs


def _parse_params(params_str: str) -> List[str]:
    """从参数列表中提取参数名."""
    if not params_str or params_str == 'void':
        return []
    result = []
    for part in params_str.split(','):
        part = part.strip()
        m = re.search(r'\b(\w+)\s*$', part)
        if m:
            result.append(m.group(1))
        else:
            pm = re.search(r'\*\s*(\w+)', part)
            if pm:
                result.append(pm.group(1))
    return result


def resolve_factory_allocs(
        lines: List[str],
        allocs: List[HeapAllocSite]) -> List[HeapAllocSite]:
    """识别 buf = factory(args) 形式的间接分配.

    若factory函数内 return malloc(param), 则添加一个HeapAllocSite.
    """
    funcs = _split_functions(lines)
    new_allocs = []
    for i, line in enumerate(lines, start=1):
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        m = re.search(
            r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*\(([^)]*)\)\s*;', text)
        if not m:
            continue
        var = m.group(1)
        callee = m.group(2)
        args_str = m.group(3).strip()
        if callee in ('malloc', 'calloc', 'realloc', 'free'):
            continue
        if callee not in funcs:
            continue
        params, body = funcs[callee]
        ret_alloc = _find_return_malloc(body, params)
        if ret_alloc is None:
            continue
        sz_param, alloc_func = ret_alloc
        args = [a.strip() for a in args_str.split(',') if a.strip()]
        param_idx = params.index(sz_param) if sz_param in params else -1
        if param_idx >= 0 and param_idx < len(args):
            sz_expr = args[param_idx]
            size_const = parse_alloc_size(sz_expr, lines, i)
        else:
            sz_expr = ret_alloc[0]
            size_const = parse_alloc_size(sz_expr, lines, i)
        bv = _base_var(var)
        new_allocs.append(HeapAllocSite(
            line=i, func=alloc_func, var=bv,
            size_expr=sz_expr, size_const=size_const,
            kind='malloc'))
    return new_allocs


def _find_return_malloc(body: List[str],
                         params: List[str]) -> Optional[Tuple[str, str]]:
    """在函数体内查找 return malloc(param) 或 return (T*)malloc(param)."""
    for line in body:
        text = line.strip()
        m = re.search(
            r'return\s+(?:\(\s*\w[\w]*\s*\*\s*\)\s*)?'
            r'(malloc|calloc|realloc)\s*\(([^)]+)\)', text)
        if m:
            func = m.group(1)
            args_str = m.group(2).strip()
            if func == 'realloc':
                parts = args_str.split(',', 1)
                if len(parts) == 2:
                    args_str = parts[1].strip()
            first_arg = args_str.split(',')[0].strip()
            if first_arg in params:
                return first_arg, func
            try:
                int(first_arg, 0)
                return first_arg, func
            except ValueError:
                pass
    return None


def resolve_cross_func_writes(
        lines: List[str],
        allocs: List[HeapAllocSite],
        writes: List[HeapWriteSite]) -> List[HeapWriteSite]:
    """识别 caller_var = callee(buf, ...) 形式的跨函数写入.

    若callee内 memcpy(dst, src, len) 且 dst=param[0],
    则在调用点创建一个HeapWriteSite.
    """
    funcs = _split_functions(lines)
    alloc_vars = {a.var for a in allocs}
    new_writes = []
    for i, line in enumerate(lines, start=1):
        text = line.strip()
        if _is_comment_or_empty(text):
            continue
        m = re.search(r'(\w[\w]*)\s*\(([^)]*)\)\s*;', text)
        if not m:
            continue
        callee = m.group(1)
        args_str = m.group(2).strip()
        if callee in ('malloc', 'calloc', 'realloc', 'free', 'printf',
                       'memset', 'memcpy', 'atoi', 'exit', 'puts'):
            continue
        if callee not in funcs:
            continue
        params, body = funcs[callee]
        args = [a.strip() for a in args_str.split(',') if a.strip()]
        if not args:
            continue
        for w in _extract_callee_writes(body, params, args, i, lines):
            if w.target not in alloc_vars:
                continue
            # loop_write去重: 仅当find_writes已在调用点检测到相同写入时跳过
            # callee体内的写入(line < call_line)不应阻止调用点写入的创建
            if w.kind == 'loop_write' and any(
                    ew.target == w.target and ew.kind == 'loop_write'
                    and ew.line >= i
                    for ew in writes):
                continue
            new_writes.append(w)
    return new_writes


def _extract_callee_writes(body: List[str], params: List[str],
                            args: List[str],
                            call_line: int,
                            caller_lines: List[str] = None) -> List[HeapWriteSite]:
    """从callee体内提取写入, 将param映射到caller的实参."""
    from analysis.heap_overflow_src_checks import is_tainted_input
    writes = []
    param_map = dict(zip(params, args))
    cl = caller_lines or body
    cguards = _callee_guard_bounds(body, params)
    for line in body:
        text = line.strip()
        for m in _MEMCPY_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            dst = param_map.get(dst, dst)
            sz_raw = m.group(3).strip()
            ws = cguards.get(sz_raw, -999)
            if ws == -999:
                sz_expr = param_map.get(sz_raw, sz_raw)
                ws = parse_alloc_size(sz_expr, cl, call_line)
                if ws >= 0 and is_tainted_input(sz_expr, cl, call_line):
                    ws = -1
            writes.append(HeapWriteSite(
                line=call_line, target=dst, kind='memcpy',
                write_size=ws))
        for m in _MEMSET_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            dst = param_map.get(dst, dst)
            sz_expr = m.group(2).strip()
            sz_expr = param_map.get(sz_expr, sz_expr)
            ws = parse_alloc_size(sz_expr, cl, call_line)
            writes.append(HeapWriteSite(
                line=call_line, target=dst, kind='memset',
                write_size=ws))
        for m in _STRCPY_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            dst = param_map.get(dst, dst)
            writes.append(HeapWriteSite(
                line=call_line, target=dst, kind='strcpy',
                write_size=-1))
        for m in _READ_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            dst = param_map.get(dst, dst)
            sz_expr = m.group(2).strip()
            sz_expr = param_map.get(sz_expr, sz_expr)
            ws = parse_alloc_size(sz_expr, cl, call_line)
            writes.append(HeapWriteSite(
                line=call_line, target=dst, kind='read',
                write_size=ws))
        # buf[var] = val — loop_write in callee, mapped to call site
        vm = re.search(r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=', text)
        if vm:
            arr = vm.group(1)
            idx_var = vm.group(2)
            arr = param_map.get(arr, arr)
            idx_var = param_map.get(idx_var, idx_var)
            # 解析callee内循环边界, 通过param_map映射变量
            lb = _resolve_callee_loop_bound(body, param_map, caller_lines, call_line)
            writes.append(HeapWriteSite(
                line=call_line, target=arr, kind='loop_write',
                write_size=-1, src_var=idx_var, loop_bound=lb))
    return writes


__all__ = [
    'resolve_factory_allocs', 'resolve_cross_func_writes',
    '_split_functions', '_callee_guard_bounds',
]
