"""
堆溢出源级验证 — Phase 1+2: 分配点识别 + 写入检测。

Phase 1: 识别 malloc/calloc/realloc 分配点, 提取大小参数
Phase 2: 检测对堆缓冲区的写入操作 (memcpy/strcpy/loop/ptr_arith等)
"""

import re
from typing import List

from analysis.heap_overflow_types import HeapAllocSite, HeapWriteSite
from analysis.heap_overflow_src_patterns import (
    _MALLOC_ASSIGN_RE, _MEMCPY_HEAP_RE, _MEMSET_HEAP_RE,
    _STRCPY_HEAP_RE, _STRCAT_HEAP_RE, _SPRINTF_HEAP_RE, _READ_HEAP_RE,
    _PTR_WRITE_RE, _PTR_VAR_OFFSET_RE, _STRUCT_ARRAY_WRITE_RE,
    _NON_VAR, _is_comment_or_empty, _base_var, parse_alloc_size,
)


def find_allocs(lines: List[str], valid_lines: set = None) -> List[HeapAllocSite]:
    """Phase 1: 识别所有堆分配点."""
    allocs = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines: continue
        text = line.strip()
        if _is_comment_or_empty(text): continue
        for m in _MALLOC_ASSIGN_RE.finditer(text):
            var = m.group(1).strip()
            func = m.group(2)
            args = m.group(3).strip()
            bv = _base_var(var)
            if not bv or bv in _NON_VAR: continue
            # 嵌套括号修正: 手动提取平衡的括号参数
            call_start = text.find(func + '(')
            if call_start >= 0:
                depth = 0
                start = call_start + len(func) + 1
                end = start
                for ci, ch in enumerate(text[start:], start):
                    if ch == '(':
                        depth += 1
                    elif ch == ')':
                        if depth == 0:
                            end = ci
                            break
                        depth -= 1
                args = text[start:end].strip()
            if func == 'calloc':
                parts = args.split(',', 1)
                if len(parts) == 2:
                    nmemb = parse_alloc_size(parts[0].strip(), lines, i)
                    esize = parse_alloc_size(parts[1].strip(), lines, i)
                    if nmemb > 0 and esize > 0:
                        size_const = nmemb * esize
                    elif nmemb > 0 or esize > 0:
                        size_const = max(nmemb, esize)
                    else:
                        size_const = -2
                else:
                    size_const = parse_alloc_size(args, lines, i)
            elif func == 'realloc':
                parts = args.split(',', 1)
                if len(parts) == 2:
                    size_const = parse_alloc_size(parts[1].strip(), lines, i)
                else:
                    size_const = parse_alloc_size(args, lines, i)
            else:
                size_const = parse_alloc_size(args, lines, i)
            allocs.append(HeapAllocSite(
                line=i, func=func, var=bv,
                size_expr=args, size_const=size_const, kind=func))
    return allocs


def find_writes(lines: List[str],
                allocs: List[HeapAllocSite],
                valid_lines: set = None) -> List[HeapWriteSite]:
    """Phase 2: 检测对堆缓冲区的写入操作."""
    alloc_vars = {a.var for a in allocs}
    writes = []
    for i, line in enumerate(lines, start=1):
        if valid_lines and i not in valid_lines: continue
        text = line.strip()
        if _is_comment_or_empty(text): continue

        # memcpy(dst, src, n)
        for m in _MEMCPY_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst not in alloc_vars: continue
            ws = parse_alloc_size(m.group(3).strip(), lines, i)
            writes.append(HeapWriteSite(
                line=i, target=dst, kind='memcpy', write_size=ws))

        # memset(dst, val, n)
        for m in _MEMSET_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst not in alloc_vars: continue
            ws = parse_alloc_size(m.group(2).strip(), lines, i)
            writes.append(HeapWriteSite(
                line=i, target=dst, kind='memset', write_size=ws))

        # strcpy(dst, src)
        for m in _STRCPY_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst not in alloc_vars: continue
            writes.append(HeapWriteSite(
                line=i, target=dst, kind='strcpy', write_size=-1))

        # strcat(dst, src)
        for m in _STRCAT_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst not in alloc_vars: continue
            writes.append(HeapWriteSite(
                line=i, target=dst, kind='strcat', write_size=-1))

        # sprintf(dst, fmt, ...)
        for m in _SPRINTF_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst not in alloc_vars: continue
            writes.append(HeapWriteSite(
                line=i, target=dst, kind='sprintf', write_size=-1))

        # read/fread/recv
        for m in _READ_HEAP_RE.finditer(text):
            dst = _base_var(m.group(1).strip())
            if dst not in alloc_vars: continue
            ws = parse_alloc_size(m.group(2).strip(), lines, i)
            writes.append(HeapWriteSite(
                line=i, target=dst, kind='read', write_size=ws))

        # buf[var] = val — 变量索引 (循环内写入)
        vm = re.search(r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=', text)
        if vm:
            arr = vm.group(1)
            idx_var = vm.group(2)
            if arr in alloc_vars and not idx_var.isdigit() and idx_var not in _NON_VAR:
                writes.append(HeapWriteSite(
                    line=i, target=arr, kind='loop_write',
                    write_size=-1, src_var=idx_var))

        # buf[expr] = val — 表达式索引 (如 buf[i * 10 + j] = ...)
        vm_expr = re.search(r'(\w[\w]*)\s*\[\s*([^\]]+)\s*\]\s*=', text)
        if vm_expr:
            arr = vm_expr.group(1)
            idx_expr = vm_expr.group(2).strip()
            if arr in alloc_vars and not idx_expr.isdigit():
                # 只在简单索引未匹配时处理表达式索引
                already = any(w.line == i and w.target == arr and w.kind == 'loop_write'
                              for w in writes)
                if not already and arr in alloc_vars:
                    writes.append(HeapWriteSite(
                        line=i, target=arr, kind='loop_write',
                        write_size=-1, src_var=idx_expr))

# (ptr + offset) = val / ptr[offset] = val
        for m in _PTR_WRITE_RE.finditer(text):
            ptr = m.group(1) or m.group(3)
            offset = int(m.group(2) or m.group(4) or 0)
            ptr_base = _base_var(ptr.strip()) if ptr else ""
            if ptr_base not in alloc_vars: continue
            writes.append(HeapWriteSite(
                line=i, target=ptr_base, kind='ptr_write',
                write_size=8, offset=offset))

# (ptr + var_offset) = val — 变量偏移指针写入
        for m in _PTR_VAR_OFFSET_RE.finditer(text):
            ptr = m.group(1)
            var_off = m.group(2)
            ptr_base = _base_var(ptr.strip()) if ptr else ""
            if ptr_base not in alloc_vars: continue
            writes.append(HeapWriteSite(
                line=i, target=ptr_base, kind='ptr_write',
                write_size=8, offset=-1, src_var=var_off))

        # struct array OOB: arr[8].val = 42 → 常量索引越界检查
        sa = _STRUCT_ARRAY_WRITE_RE.search(text)
        if sa:
            arr = _base_var(sa.group(1).strip())
            idx = int(sa.group(2))
            if arr in alloc_vars:
                writes.append(HeapWriteSite(
                    line=i, target=arr, kind='struct_array',
                    write_size=-1, offset=idx, src_var='idx_const'))

        # struct field write: s->field = ... / s.field = ...
        sf = re.search(r'(\w[\w]*)\s*(?:->|\.)\s*\w[\w]*\s*=', text)
        if sf:
            sbase = _base_var(sf.group(1).strip())
            if sbase in alloc_vars:
                writes.append(HeapWriteSite(
                    line=i, target=sbase, kind='struct_write',
                    write_size=-1, offset=0))

    return writes
