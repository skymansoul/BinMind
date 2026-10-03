"""
源码级候选提取器辅助函数 — 正则常量 + 通用解析工具.

批量提取函数见 source_level_candidate_extractor_writes.py
"""

import re

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)

# 分配函数正则 — 避免循环导入, 定义唯一源
_mvar_re = re.compile(r'malloc\s*\(([^()]+(?:\([^()]*\)[^()]*)*)\)')
_cvar_re = re.compile(r'calloc\s*\(([^()]+(?:\([^()]*\)[^()]*)*)\)')
_rvar_re = re.compile(
    r'realloc\s*\(\s*(\w+)\s*,\s*([^()]+(?:\([^()]*\)[^()]*)*)\)')

# 库函数写入正则（原有5种）
_lib_write_re = re.compile(
    r'(memcpy|strcpy|strncpy|memset|memmove)\s*\('
    r'([^()]+(?:\([^()]*\)[^()]*)*)\)')

# sprintf/snprintf写入正则
_sprintf_re = re.compile(
    r'(sprintf|snprintf)\s*\(([^()]+(?:\([^()]*\)[^()]*)*)\)')

# 数组索引写入正则
_array_write_re = re.compile(
    r'(\w+)\s*\[\s*(\w+)(?:\s*\+\s*(\d+))?\s*\]\s*=')

# 指针算术写入正则
_ptr_deref_re = re.compile(
    r'\*\s*\(\s*(\w+)\s*\+\s*(\w+|\d+)\s*\)\s*=')

# 辅助正则
_sizeof_re = re.compile(r'sizeof\s*\(\s*(\w+)\s*\)')


def _estimate_sizeof(expr: str, struct_defs: dict) -> int:
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
            total += int(arr_m.group(2)) * 4 if arr_m and arr_m.group(2) else 4
        elif 'short' in field:
            total += 2
        else:
            total += 4
    return total if total > 0 else 64


def _parse_size_expr(size_str: str) -> tuple:
    """解析动态分配大小表达式为(变量部分, 常量偏移)元组."""
    size_str = size_str.strip()
    m = re.match(r'(\w+)\s*\+\s*(\d+)$', size_str)
    if m:
        return m.group(1), int(m.group(2))
    m = re.match(r'(\d+)\s*\+\s*(\w+)$', size_str)
    if m:
        return m.group(2), int(m.group(1))
    m = re.match(r'(\d+)\s*\*\s*(\w+)$', size_str)
    if m:
        return m.group(2), -1
    m = re.match(r'(\w+)\s*\*\s*(\d+)$', size_str)
    if m:
        return m.group(1), -1
    if re.match(r'^\w+$', size_str):
        return size_str, 0
    return '', -1


def _try_eval_const_expr(s: str) -> int:
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


def _parse_dst(raw_dst: str, ir: list):
    """解析目标操作数, 返回(base_var, offset, offset_is_dynamic)."""
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
    for line in ir:
        m = re.match(rf'(\w+_t)\s+\*?\s*{re.escape(var)}\b', line)
        if m:
            return m.group(1)
        m = re.match(rf'struct\s+(\w+)\s+\*?\s*{re.escape(var)}\b', line)
        if m:
            return m.group(1)
    return ""


def _compute_field_offset_by_name(ir: list, sname: str, field_name: str) -> int:
    code_joined = ' '.join(ir)
    for sm in re.finditer(
        r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)', code_joined):
        if sm.group(2) == sname:
            return _compute_field_offset(sm.group(1), field_name)
    return 0


def _compute_field_offset(struct_body: str, field_name: str) -> int:
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


def _extract_var_from_decl(line: str, func_name: str) -> str:
    """从赋值声明行提取变量名 — 兼容复杂类型转换."""
    eq_pos = line.find('=')
    if eq_pos < 0:
        return ''
    lhs = line[:eq_pos].rstrip()
    lhs = lhs.rstrip('* \t')
    m = re.search(r'(\w+)\s*$', lhs)
    if m:
        var = m.group(1)
        type_kw = {'unsigned', 'signed', 'const', 'volatile', 'struct',
                   'enum', 'void', 'char', 'int', 'long', 'short',
                   'float', 'double', 'static', 'extern', 'register'}
        if var not in type_kw:
            return var
    return ''


def _is_heap_var(var_name: str, alloc_sites: list) -> bool:
    """判断变量是否来自堆分配 — 支持后缀匹配."""
    if not var_name:
        return False
    for a in alloc_sites:
        avar = a.get('var', '') or ''
        if avar and (var_name == avar or var_name.endswith(avar)):
            return True
        if '->' in var_name:
            parts = var_name.split('->')
            if len(parts) == 2 and parts[1] == avar:
                return True
        if '.' in var_name:
            parts = var_name.split('.')
            if len(parts) == 2 and parts[1] == avar:
                return True
    return False


def _match_alloc_write(base_var: str, alloc_sites: list) -> list:
    """匹配写入目标与分配位点 — 支持完全/后缀/全局三种策略."""
    matched = []
    for alloc in alloc_sites:
        if not alloc.get('active', True):
            continue
        avar = alloc.get('var', '') or ''
        if base_var and avar and base_var == avar:
            matched.append(alloc)
            continue
        if base_var and avar:
            if base_var.endswith(avar) or avar.endswith(base_var):
                matched.append(alloc)
                continue
        if base_var and '->' in base_var:
            parts = base_var.split('->')
            if len(parts) == 2 and parts[1] == avar:
                matched.append(alloc)
                continue
        if base_var and '.' in base_var:
            parts = base_var.split('.')
            if len(parts) == 2 and parts[1] == avar:
                matched.append(alloc)
                continue
    if not matched and alloc_sites:
        matched = [a for a in alloc_sites if a.get('active', True)]
    return matched


def _make_candidate(alloc: dict, store: HeapStore,
                     confidence: float, description: str) -> HeapOverflowCandidate:
    """从alloc和store构建HeapOverflowCandidate."""
    alloc_site = HeapAllocSite(
        pc=alloc['pc'], alloc_func=alloc['func'],
        size_arg=alloc['size_arg'],
        size_is_dynamic=alloc['is_dyn'],
        size_expr=alloc['size_str'] if alloc['is_dyn'] else '',
        result_var=alloc.get('var', '') or '')
    return HeapOverflowCandidate(
        alloc_site=alloc_site, overflow_store=store,
        confidence=confidence, description=description)
