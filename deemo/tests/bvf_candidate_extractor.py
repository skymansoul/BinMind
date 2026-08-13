#!/usr/bin/env python3
"""
BVF候选提取器 — 从C源码提取(alloc, write)候选对.

提供候选提取和辅助函数.
"""
import re
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)

_mvar_re = re.compile(r'malloc\s*\(([^()]+(?:\([^()]*\)[^()]*)*)\)')
_cvar_re = re.compile(r'calloc\s*\(([^()]+(?:\([^()]*\)[^()]*)*)\)')
_rvar_re = re.compile(r'realloc\s*\(\s*(\w+)\s*,\s*([^()]+(?:\([^()]*\)[^()]*)*)\)')
_memcpy_re = re.compile(
    r'(memcpy|strcpy|strncpy|memset|memmove)\s*\(([^()]+(?:\([^()]*\)[^()]*)*)\)')
_offset_re = re.compile(r'(\w+)\s*\+\s*(\d+)')
_sizeof_re = re.compile(r'sizeof\s*\(\s*(\w+)\s*\)')
_struct_def_re = re.compile(
    r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)')


def _estimate_sizeof(expr: str, struct_defs: dict) -> int:
    """估算sizeof(struct)的值."""
    m = _sizeof_re.search(expr)
    if not m:
        return 0
    sname = m.group(1)
    fields_text = struct_defs.get(sname, '')
    if not fields_text:
        return 64
    total = 0
    for field in fields_text.split(';'):
        field = field.strip()
        if not field:
            continue
        if 'char' in field:
            arr_m = re.search(r'\[(\d+)\]', field)
            total += int(arr_m.group(1)) if arr_m else 1
        elif 'int' in field or 'long' in field or 'void' in field:
            arr_m = re.search(r'\[(\d+)\]', field)
            total += int(arr_m.group(1)) * 4 if arr_m else 4
        elif 'short' in field:
            total += 2
        else:
            total += 4
    return total if total > 0 else 64


def _try_eval_const_expr(s: str) -> int:
    """尝试求值常量表达式如 n*4, 32, 128."""
    s = s.strip()
    if s.isdigit():
        return int(s)
    m = re.match(r'(\d+)\s*\*\s*(\d+)', s)
    if m:
        return int(m.group(1)) * int(m.group(2))
    m = re.match(r'(\d+)\s*\+\s*(\d+)', s)
    if m:
        return int(m.group(1)) + int(m.group(2))
    return -1


def _split_args(s: str) -> list:
    parts, d, cur = [], 0, []
    for ch in s:
        if ch == '(':
            d += 1; cur.append(ch)
        elif ch == ')':
            d -= 1; cur.append(ch)
        elif ch == ',' and d == 0:
            parts.append(''.join(cur)); cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur))
    return parts


def extract_candidates_from_code(code: str) -> list:
    """从C源码提取(alloc, write)候选对."""
    code = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code = re.sub(r'//[^\n]*', '', code)
    lines = code.strip().split('\n')
    ir = [l.strip() for l in lines if l.strip()]

    code_joined = ' '.join(ir)
    struct_defs = {}
    for sm in re.finditer(
        r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)', code_joined):
        struct_defs[sm.group(2)] = sm.group(1)

    alloc_sites = []

    for i, line in enumerate(ir):
        if line.startswith('#') or line.startswith('/*') or \
           line.startswith('*') or line.startswith('//'):
            continue

        m = _mvar_re.search(line)
        if m:
            size_str = m.group(1).strip()
            size_arg = _try_eval_const_expr(size_str)
            is_dyn = size_arg < 0
            if 'sizeof' in size_str:
                size_arg = _estimate_sizeof(size_str, struct_defs)
                is_dyn = False
            var_m = re.match(r'\w+\s+\*?\s*(\w+)\s*=\s*malloc', line)
            var_name = var_m.group(1) if var_m else None
            alloc_sites.append({
                'pc': i, 'func': 'malloc',
                'size_str': size_str, 'is_dyn': is_dyn,
                'size_arg': size_arg,
                'var': var_name, 'active': True,
            })

        m = _cvar_re.search(line)
        if m:
            args = [a.strip() for a in m.group(1).split(',')]
            if len(args) == 2:
                nm, sz = args[0], args[1]
                combined = f"{nm}*{sz}"
                size_arg = _try_eval_const_expr(combined)
                is_dyn = size_arg < 0
                var_m = re.match(r'\w+\s+\*?\s*(\w+)\s*=\s*calloc', line)
                var_name = var_m.group(1) if var_m else None
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

    candidates = []
    for i, line in enumerate(ir):
        if line.startswith('#') or line.startswith('/*') or \
           line.startswith('*') or line.startswith('//'):
            continue

        m = _memcpy_re.search(line)
        if not m:
            continue
        mnemonic = m.group(1).lower()
        args = [a.strip() for a in _split_args(m.group(2))]
        if len(args) < 2:
            continue

        raw_dst = args[0].strip()
        base_var, offset, offset_is_dynamic = _parse_dst(raw_dst, ir)

        store_size = 0
        if mnemonic in ('memcpy', 'memmove', 'strncpy', 'memset'):
            if len(args) >= 3:
                try:
                    store_size = int(args[2].strip())
                except ValueError:
                    store_size = 0

        for alloc in alloc_sites:
            if not alloc.get('active', True):
                continue
            store = HeapStore(
                pc=i, base_var=base_var, offset=offset,
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
                confidence=0.50, description='bvf_test'))

    return candidates, ir


def _parse_dst(raw_dst: str, ir: list):
    """解析memcpy目标操作数, 返回(base_var, offset, offset_is_dynamic)."""
    base_var = raw_dst
    offset = 0
    offset_is_dynamic = False

    om = re.match(r'(\w+)\s*\+\s*(\d+)\s*$', raw_dst)
    if om:
        return om.group(1), int(om.group(2)), False

    om2 = re.match(r'(\w+)\s*\+\s*(\w+)\s*\*\s*(\d+)\s*$', raw_dst)
    if om2:
        return om2.group(1), 0, True

    fm = re.match(r'(\w+)->(\w+)', raw_dst)
    if fm:
        sname = _find_struct_for_var(ir, fm.group(1))
        off = _compute_field_offset_by_name(ir, sname, fm.group(2)) \
            if sname else 0
        return fm.group(1), off, False

    fm2 = re.match(r'(\w+)\.(\w+)', raw_dst)
    if fm2:
        return fm2.group(1), 0, False

    return base_var, offset, offset_is_dynamic


def _find_struct_for_var(ir: list, var: str) -> str:
    """通过变量声明推断结构体类型名."""
    for line in ir:
        m = re.match(rf'(\w+_t)\s+\*?\s*{re.escape(var)}\b', line)
        if m:
            return m.group(1)
        m = re.match(rf'struct\s+(\w+)\s+\*?\s*{re.escape(var)}\b', line)
        if m:
            return m.group(1)
    return ""


def _compute_field_offset_by_name(
    ir: list, sname: str, field_name: str,
) -> int:
    """通过结构体类型名和字段名计算偏移."""
    code_joined = ' '.join(ir)
    for sm in re.finditer(
        r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)', code_joined):
        if sm.group(2) == sname:
            return _compute_field_offset(sm.group(1), field_name)
    return 0


def _compute_field_offset(struct_body: str, field_name: str) -> int:
    """计算结构体字段的字节偏移."""
    fields = [f.strip() for f in struct_body.split(';') if f.strip()]
    offset = 0
    for f in fields:
        fm = re.search(r'(\w+)\s*(?:\[(\d+)\])?\s*$', f)
        fname = fm.group(1) if fm else ""
        if 'char' in f:
            size = int(fm.group(2)) if fm and fm.group(2) else 1
        elif 'int' in f or 'long' in f or 'void' in f:
            size = int(fm.group(2)) * 4 if fm and fm.group(2) else 4
        elif 'short' in f:
            size = 2
        else:
            size = 4
        if fname == field_name:
            return offset
        offset += size
    return offset
