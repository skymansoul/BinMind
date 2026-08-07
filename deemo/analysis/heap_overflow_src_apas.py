"""
堆溢出源级验证 — APAS (Alias Propagation & Offset Solver).

HOSV第5阶段增强: 解决4类检测器盲区:
  1. 多跳别名链: buf→ptr→alias 传递闭包
  2. 复合算术偏移: base*stride+extra guard约束下worst-case求解
  3. 结构体字段偏移: typedef字段布局计算
  4. 工厂函数常量: return malloc(CONST) 的常量解析
"""
import re
from typing import Dict, List, Optional, Set, Tuple

from analysis.heap_overflow_types import HeapAllocSite, HeapWriteSite
from analysis.heap_overflow_src_patterns import (
    _is_comment_or_empty, _base_var, parse_alloc_size, _resolve_sizeof,
    _MEMCPY_HEAP_RE,
)
from analysis.heap_overflow_src_apas_writes import find_alias_writes


def build_alias_closure(lines: List[str],
                        alloc_vars: Set[str]) -> Dict[str, str]:
    """构建多跳别名闭包: var → root_alloc_var.

    追踪 var = other_var; 和 var = (cast*)other_var; 形式的赋值,
    直到找到 alloc_vars 中的根分配变量.
    """
    alias_map: Dict[str, str] = {}
    for var in alloc_vars:
        alias_map[var] = var

    changed = True
    while changed:
        changed = False
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if _is_comment_or_empty(text):
                continue
            m = re.search(
                r'(\w[\w]*)\s*=\s*(?:\(\s*\w[\w]*\s*\*\s*\)\s*)?'
                r'(\w[\w]*)\s*;', text)
            if not m:
                continue
            lhs = m.group(1)
            rhs = m.group(2)
            if lhs in alloc_vars or lhs in alias_map:
                continue
            if rhs in alias_map:
                alias_map[lhs] = alias_map[rhs]
                changed = True
    return alias_map


def resolve_alias(target: str, alias_map: Dict[str, str]) -> str:
    """将写入目标通过别名映射解析到根分配变量."""
    t = target.strip()
    if t in alias_map:
        return alias_map[t]
    bv = _base_var(t)
    return alias_map.get(bv, bv)


def eval_compound_offset(expr: str, lines: List[str],
                         write_line: int) -> Optional[int]:
    """求解复合算术偏移表达式的worst-case值.

    支持: var * var, var * const, var + var, var * var + var
    通过guard约束提取各变量的上界, 计算最大可能值.
    """
    from analysis.heap_overflow_src_guards import find_guard_bounds

    expr = expr.strip()
    if not expr:
        return 0
    try:
        return int(expr, 0)
    except ValueError:
        pass

    # 纯变量: 用guard上界, 或递归解析赋值表达式
    if re.match(r'^\w[\w]*$', expr):
        _, hi = find_guard_bounds(expr, lines, write_line)
        if hi is not None:
            return hi
        # 常量赋值搜索
        for j in range(write_line - 2, -1, -1):
            t = lines[j].strip()
            if _is_comment_or_empty(t):
                continue
            m = re.search(rf'\b{re.escape(expr)}\s*=\s*(\d+)\s*;', t)
            if m:
                return int(m.group(1))
            # 递归: var = compound_expr → 评估compound_expr
            m = re.search(rf'\b{re.escape(expr)}\s*=\s*(.+?)\s*;', t)
            if m:
                inner = m.group(1).strip()
                if inner != expr and not _is_comment_or_empty(inner):
                    result = eval_compound_offset(inner, lines, j + 1)
                    if result is not None:
                        return result
        return None

    # var * const 或 const * var
    m = re.match(r'(\w[\w]*)\s*\*\s*(\d+)', expr)
    if m:
        var, const = m.group(1), int(m.group(2))
        _, hi = find_guard_bounds(var, lines, write_line)
        if hi is not None:
            return hi * const
    m = re.match(r'(\d+)\s*\*\s*(\w[\w]*)', expr)
    if m:
        const, var = int(m.group(1)), m.group(2)
        _, hi = find_guard_bounds(var, lines, write_line)
        if hi is not None:
            return const * hi

    # var * var
    m = re.match(r'(\w[\w]*)\s*\*\s*(\w[\w]*)$', expr)
    if m:
        v1, v2 = m.group(1), m.group(2)
        _, hi1 = find_guard_bounds(v1, lines, write_line)
        _, hi2 = find_guard_bounds(v2, lines, write_line)
        if hi1 is not None and hi2 is not None:
            return hi1 * hi2

    # var * var + var
    m = re.match(r'(\w[\w]*)\s*\*\s*(\w[\w]*)\s*\+\s*(\w[\w]*)$', expr)
    if m:
        v1, v2, v3 = m.group(1), m.group(2), m.group(3)
        _, hi1 = find_guard_bounds(v1, lines, write_line)
        _, hi2 = find_guard_bounds(v2, lines, write_line)
        _, hi3 = find_guard_bounds(v3, lines, write_line)
        if hi1 is not None and hi2 is not None and hi3 is not None:
            return hi1 * hi2 + hi3

    # var + const
    m = re.match(r'(\w[\w]*)\s*\+\s*(\d+)', expr)
    if m:
        var, const = m.group(1), int(m.group(2))
        _, hi = find_guard_bounds(var, lines, write_line)
        if hi is not None:
            return hi + const

    return None


def compute_struct_field_info(struct_type: str, field: str,
                              lines: List[str],
                              alloc_line: int) -> Tuple[int, int]:
    """返回结构体字段的 (offset, size). 无法解析时 (-1, -1)."""
    if not struct_type or not field:
        return -1, -1
    for i in range(alloc_line - 1, -1, -1):
        t = lines[i].strip()
        tm = re.match(r'typedef\s+struct\s*\{', t)
        if tm:
            offset = 0
            field_sizes = {
                'char': 1, 'int': 4, 'long': 8, 'short': 2,
                'float': 4, 'double': 8, 'size_t': 8,
                'void*': 8, 'char*': 8, 'int*': 8, 'long*': 8,
                'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4, 'uint64_t': 8,
            }
            for j in range(i + 1, min(len(lines), i + 50)):
                ft = lines[j].strip()
                if '}' in ft and struct_type in ft:
                    return -1, -1
                fm = re.match(r'\s*(\w+)\s+(\w+)(\[\d+\])?\s*;', ft)
                if fm:
                    base_type = fm.group(1)
                    fname = fm.group(2)
                    arr = fm.group(3)
                    sz = field_sizes.get(base_type, 8)
                    if arr:
                        n = int(arr[1:-1])
                        sz *= n
                    if fname == field:
                        return offset, sz
                    offset += sz
            break
    return -1, -1


def extract_field_access(target: str) -> Optional[Tuple[str, str]]:
    """从 buf->field 或 buf.field 中提取 (base_var, field_name)."""
    m = re.match(r'^(\w[\w]*)\s*(?:->|\.)\s*(\w[\w]*)\s*$', target.strip())
    if m:
        return m.group(1), m.group(2)
    return None


def resolve_write_offset(w: HeapWriteSite,
                          lines: List[str]) -> int:
    """APAS: 解析memcpy/memset的变量+算术偏移."""
    for i in range(w.line - 1, w.line):
        if i >= len(lines):
            break
        text = lines[i]
        for m in _MEMCPY_HEAP_RE.finditer(text):
            dst_full = m.group(1).strip()
            pm = re.match(r'(\w[\w]*)\s*\+\s*(.+?)$', dst_full)
            if pm:
                off_expr = pm.group(2).strip().rstrip(')')
                off = eval_compound_offset(off_expr, lines, w.line)
                if off is not None:
                    return off
    return 0


def struct_write_check(a, w, lines, sc):
    """APAS: struct field写入检查 — 计算字段偏移+写入大小."""
    from analysis.heap_overflow_types import HoVerdict, HoResult
    from analysis.heap_overflow_src_patterns import (
        _ptmalloc2_usable, _infer_struct_type, _resolve_sizeof)
    if sc < 0:
        return HoResult(
            verdict=HoVerdict.UNCERTAIN, alloc_line=a.line,
            write_line=w.line, var_name=a.var, confidence=0.50,
            reason=f"'{a.var}': struct_write variable alloc"
                   f"@L{w.line} — needs further analysis")
    usable = _ptmalloc2_usable(sc)
    text = lines[w.line - 1].strip() if w.line <= len(lines) else ""
    # 优先从src_var提取字段名 (find_struct_field_writes设置)
    field = ""
    if hasattr(w, 'src_var') and w.src_var and w.src_var.startswith("field:"):
        field = w.src_var.split(":", 1)[1]
    if not field:
        sm = re.search(r'(\w[\w]*)\s*(?:->|\.)\s*(\w[\w]*)\s*=', text)
        fa = extract_field_access(sm.group(0)) if sm else None
        if fa:
            _, field = fa
    if not field:
        # memcpy到struct field: 提取dst中的字段名
        fm = re.search(r'(?:->|\.)\s*(\w[\w]*)', text)
        if fm:
            field = fm.group(1)
    if not field:
        return HoResult(
            verdict=HoVerdict.SAFE, alloc_line=a.line,
            write_line=w.line, var_name=a.var, alloc_size=sc,
            confidence=0.90,
            reason=f"'{a.var}': malloc({sc}) + sizeof={sc} — safe")
    struct_type = _infer_struct_type(a, lines)
    field_off, field_sz = compute_struct_field_info(
        struct_type, field, lines, a.line)
    if field_off < 0:
        return HoResult(
            verdict=HoVerdict.UNCERTAIN, alloc_line=a.line,
            write_line=w.line, var_name=a.var, alloc_size=sc,
            confidence=0.50,
            reason=f"'{a.var}': struct field offset unknown"
                   f"@L{w.line} — needs further analysis")
    # 字段直接赋值: field_off + field_size vs usable
    if field_sz > 0 and field_off + field_sz > usable:
        return HoResult(
            verdict=HoVerdict.VULN, alloc_line=a.line,
            write_line=w.line, var_name=a.var, alloc_size=sc,
            write_size=field_sz,
            overflow_bytes=field_off + field_sz - usable,
            confidence=0.85,
            reason=f"'{a.var}': malloc({sc}) usable={usable}, "
                   f"field '{field}' at offset {field_off} "
                   f"+ {field_sz}B@L{w.line} — struct field OOB")
    # memcpy到结构体字段: field_off + memcpy_size vs usable
    if w.write_size >= 0:
        if field_off + w.write_size > usable:
            return HoResult(
                verdict=HoVerdict.VULN, alloc_line=a.line,
                write_line=w.line, var_name=a.var, alloc_size=sc,
                write_size=w.write_size,
                overflow_bytes=field_off + w.write_size - usable,
                confidence=0.85,
                reason=f"'{a.var}': malloc({sc}) usable={usable}, "
                       f"memcpy to field '{field}'@{field_off} "
                       f"size {w.write_size}B@L{w.line} — OOB")
        return HoResult(
            verdict=HoVerdict.SAFE, alloc_line=a.line,
            write_line=w.line, var_name=a.var, alloc_size=sc,
            write_size=w.write_size, confidence=0.90,
            reason=f"'{a.var}': malloc({sc}) + field '{field}'@{field_off}"
                   f" + {w.write_size}B — safe")
    return HoResult(
        verdict=HoVerdict.SAFE, alloc_line=a.line,
        write_line=w.line, var_name=a.var, alloc_size=sc,
        confidence=0.90,
        reason=f"'{a.var}': malloc({sc}) + field '{field}'@{field_off}"
               f" sizeof={sc} — safe")


__all__ = [
    'build_alias_closure', 'resolve_alias', 'eval_compound_offset',
    'compute_struct_field_info', 'extract_field_access',
    'find_alias_writes', 'resolve_write_offset', 'struct_write_check',
]
