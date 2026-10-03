"""
源码级候选提取器写入模式 — 分配位点提取 + 4种写入模式候选构建.

批量提取函数集中存放, 避免单文件超标.
"""

import re

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)
from core.source_level_candidate_extractor_patterns import (
    _mvar_re, _cvar_re, _rvar_re,
    _lib_write_re, _sprintf_re,
    _array_write_re, _ptr_deref_re,
    _estimate_sizeof,
    _parse_size_expr,
    _try_eval_const_expr,
    _extract_var_from_decl,
    _is_heap_var,
    _match_alloc_write,
    _split_args,
    _parse_dst,
)


def _extract_alloc_sites(ir: list, struct_defs: dict) -> list:
    """提取所有堆分配位点(malloc/calloc/realloc)."""
    alloc_sites = []

    for i, line in enumerate(ir):
        if line.startswith('#') or line.startswith('/*') or \
           line.startswith('//'):
            continue

        m = _mvar_re.search(line)
        if m:
            size_str = m.group(1).strip()
            size_arg = _try_eval_const_expr(size_str)
            is_dyn = size_arg < 0
            if 'sizeof' in size_str:
                size_arg = _estimate_sizeof(size_str, struct_defs)
                is_dyn = False
            var_name = _extract_var_from_decl(line, 'malloc')
            size_var, size_const_offset = '', 0
            if is_dyn and size_str:
                size_var, size_const_offset = _parse_size_expr(size_str)
                if size_var:
                    for prev_line in ir[:i]:
                        vm = re.match(
                            rf'\w+\s+{re.escape(size_var)}\s*=\s*(\d+)',
                            prev_line.strip())
                        if vm:
                            base_val = int(vm.group(1))
                            size_arg = base_val + max(0, size_const_offset)
                            is_dyn = False
                            break
            alloc_sites.append({
                'pc': i, 'func': 'malloc',
                'size_str': size_var if is_dyn else str(size_arg),
                'is_dyn': is_dyn, 'size_arg': size_arg,
                'var': var_name, 'active': True,
                'size_var': size_var,
                'size_const_offset': size_const_offset if is_dyn else 0,
            })

        m = _cvar_re.search(line)
        if m:
            args = [a.strip() for a in m.group(1).split(',')]
            if len(args) == 2:
                nm, sz = args[0], args[1]
                combined = f"{nm}*{sz}"
                size_arg = _try_eval_const_expr(combined)
                is_dyn = size_arg < 0
                var_name = _extract_var_from_decl(line, 'calloc')
                alloc_sites.append({
                    'pc': i, 'func': 'calloc',
                    'size_str': combined if is_dyn else str(size_arg),
                    'is_dyn': is_dyn, 'size_arg': size_arg,
                    'var': var_name, 'active': True,
                })

        m = _rvar_re.search(line)
        if m:
            rvar, rsize = m.group(1), m.group(2).strip()
            size_arg = _try_eval_const_expr(rsize)
            is_dyn = size_arg < 0
            if 'sizeof' in rsize:
                size_arg = _estimate_sizeof(rsize, struct_defs)
                is_dyn = False
            for a in alloc_sites:
                if a.get('var') == rvar and a['active']:
                    a['size_arg'] = size_arg
                    a['size_str'] = rsize
                    a['is_dyn'] = is_dyn
                    break

    return alloc_sites


def _extract_lib_writes(line: str, line_idx: int, alloc_sites: list,
                        ir: list, candidates: list) -> None:
    """提取库函数写入候选（原有5种: memcpy/strcpy/strncpy/memset/memmove）."""
    m = _lib_write_re.search(line)
    if not m:
        return
    mnemonic = m.group(1).lower()
    args = [a.strip() for a in _split_args(m.group(2))]
    if len(args) < 2:
        return

    raw_dst = args[0].strip()
    base_var, offset, offset_is_dynamic = _parse_dst(raw_dst, ir)

    store_size = 0
    if mnemonic in ('memcpy', 'memmove', 'strncpy', 'memset'):
        if len(args) >= 3:
            try:
                store_size = int(args[2].strip())
            except ValueError:
                store_size = 0

    matched_allocs = _match_alloc_write(base_var, alloc_sites)
    for alloc in matched_allocs:
        store = HeapStore(
            pc=line_idx, base_var=base_var, offset=offset,
            offset_is_dynamic=offset_is_dynamic,
            store_size=store_size, mnemonic=mnemonic)
        alloc_site = HeapAllocSite(
            pc=alloc['pc'], alloc_func=alloc['func'],
            size_arg=alloc['size_arg'],
            size_is_dynamic=alloc['is_dyn'],
            size_expr=alloc['size_str'] if alloc['is_dyn'] else '',
            result_var=alloc.get('var', '') or '')
        candidates.append(HeapOverflowCandidate(
            alloc_site=alloc_site, overflow_store=store,
            confidence=0.50, description='lib_write'))


def _extract_sprintf_writes(line: str, line_idx: int, alloc_sites: list,
                            ir: list, candidates: list) -> None:
    """提取sprintf/snprintf写入候选（新增模式8）."""
    m = _sprintf_re.search(line)
    if not m:
        return
    mnemonic = m.group(1).lower()
    args = [a.strip() for a in _split_args(m.group(2))]
    if len(args) < 2:
        return

    raw_dst = args[0].strip()
    base_var, offset, offset_is_dynamic = _parse_dst(raw_dst, ir)

    store_size = 0
    if mnemonic == 'snprintf' and len(args) >= 3:
        try:
            store_size = int(args[1].strip())
        except ValueError:
            store_size = 0
    elif mnemonic == 'sprintf':
        store_size = -1

    matched_allocs = _match_alloc_write(base_var, alloc_sites)
    for alloc in matched_allocs:
        store = HeapStore(
            pc=line_idx, base_var=base_var, offset=offset,
            offset_is_dynamic=offset_is_dynamic,
            store_size=store_size, mnemonic=mnemonic)
        alloc_site = HeapAllocSite(
            pc=alloc['pc'], alloc_func=alloc['func'],
            size_arg=alloc['size_arg'],
            size_is_dynamic=alloc['is_dyn'],
            size_expr=alloc['size_str'] if alloc['is_dyn'] else '',
            result_var=alloc.get('var', '') or '')
        candidates.append(HeapOverflowCandidate(
            alloc_site=alloc_site, overflow_store=store,
            confidence=0.45, description='sprintf_write'))


def _extract_array_index_writes(line: str, line_idx: int,
                                 alloc_sites: list, candidates: list) -> None:
    """提取数组索引写入候选（新增模式6: buf[i]=val）."""
    for m in _array_write_re.finditer(line):
        base_var = m.group(1)
        idx_var = m.group(2)

        if not _is_heap_var(base_var, alloc_sites):
            continue

        for alloc in alloc_sites:
            if not alloc.get('active', True):
                continue
            if alloc.get('var') != base_var:
                continue
            store = HeapStore(
                pc=line_idx, base_var=base_var, offset=0,
                offset_is_dynamic=True,
                store_size=1, mnemonic='array_index')
            alloc_site = HeapAllocSite(
                pc=alloc['pc'], alloc_func=alloc['func'],
                size_arg=alloc['size_arg'],
                size_is_dynamic=alloc['is_dyn'],
                size_expr=alloc['size_str'] if alloc['is_dyn'] else '',
                result_var=alloc.get('var', '') or '')
            candidates.append(HeapOverflowCandidate(
                alloc_site=alloc_site, overflow_store=store,
                confidence=0.40, description='array_index_write'))


def _extract_ptr_deref_writes(line: str, line_idx: int,
                               alloc_sites: list, candidates: list) -> None:
    """提取指针算术写入候选（新增模式7: *(ptr+off)=val）."""
    for m in _ptr_deref_re.finditer(line):
        base_var = m.group(1)
        off_expr = m.group(2)

        if not _is_heap_var(base_var, alloc_sites):
            continue

        try:
            offset = int(off_expr, 0)
            offset_is_dynamic = False
        except ValueError:
            offset = 0
            offset_is_dynamic = True

        for alloc in alloc_sites:
            if not alloc.get('active', True):
                continue
            if alloc.get('var') != base_var:
                continue
            store = HeapStore(
                pc=line_idx, base_var=base_var, offset=offset,
                offset_is_dynamic=offset_is_dynamic,
                store_size=1, mnemonic='ptr_deref')
            alloc_site = HeapAllocSite(
                pc=alloc['pc'], alloc_func=alloc['func'],
                size_arg=alloc['size_arg'],
                size_is_dynamic=alloc['is_dyn'],
                size_expr=alloc['size_str'] if alloc['is_dyn'] else '',
                result_var=alloc.get('var', '') or '')
            candidates.append(HeapOverflowCandidate(
                alloc_site=alloc_site, overflow_store=store,
                confidence=0.40, description='ptr_deref_write'))
