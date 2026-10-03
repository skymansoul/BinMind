"""
堆溢出源级验证 — 循环边界与guard约束提取.

  - find_loop_bound_const: 常量循环上界 + clamp guard变量上界
  - find_guard_bounds: 变量的guard约束区间 [lo, hi]
"""

import re
from typing import List, Optional, Tuple


def find_loop_bound_const(lines: List[str], write_line: int,
                           target_var: str = "") -> Optional[int]:
    """从源码中找到循环边界常量.

    搜索 write_line 上方的 for/while 循环, 提取循环上界.
    支持: for(i=0; i<N; ...), for(i=0; i<=N; ...),
          复合条件: for(i=0; i<N && ...; ...),
          clamp guard: if(n>N) n=N; → hi=N
          嵌套循环: 外层×内层乘积
    返回循环上界常量, 或None.
    """
    # 收集所有包围 write_line 的循环边界
    bounds = _collect_loop_bounds(lines, write_line, target_var)
    if not bounds:
        return None
    # 嵌套循环: 边界乘积
    product = 1
    for b in bounds:
        product *= b
    return product


def _collect_loop_bounds(lines: List[str], write_line: int,
                         target_var: str = "") -> List[int]:
    """收集所有包围 write_line 的 for 循环的边界常量."""
    bounds = []
    seen_for = False
    for i in range(write_line - 2, max(-1, write_line - 30), -1):
        text = lines[i].strip()
        if re.match(r'\w[\w]*\s+\*?\s*\w+\s*\([^)]*\)\s*\{', text):
            break
        # 常量上界
        _const_pats = [
            (r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\d+)\s*;', False),
            (r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\d+)\s*&&', False),
            (r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<=\s*(\d+)\s*;', True),
        ]
        found = False
        for pat, plus_one in _const_pats:
            m = re.search(pat, text)
            if m:
                bounds.append(int(m.group(1)) + (1 if plus_one else 0))
                found = True
                seen_for = True
                break
        if found:
            continue
        # 变量上界
        m = re.search(
            r'for\s*\(\s*(?:\w+\s+)?\w+\s*=\s*0\s*;\s*\w+\s*<\s*(\w+)\s*[;]',
            text)
        if m:
            var = m.group(1)
            if var == target_var or var in ('i', 'j', 'k'):
                continue
            cb = _find_clamp_bound(lines, i, var)
            if cb is not None:
                bounds.append(cb)
                seen_for = True
            else:
                ca = _find_const_assignment(lines, i, var)
                if ca is not None:
                    bounds.append(ca)
                    seen_for = True
    return bounds


def _find_clamp_bound(lines: List[str], loop_line: int,
                       var: str) -> Optional[int]:
    """搜索clamp guard: if(var > N) var = N; → N. 不跨函数边界."""
    import re as _re
    for j in range(loop_line - 1, max(-1, loop_line - 20), -1):
        t2 = lines[j].strip()
        if _re.match(r'\w[\w]*\s+\*?\s*\w+\s*\([^)]*\)\s*\{', t2):
            break
        gm = _re.search(
            rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)\s*'
            rf'{re.escape(var)}\s*=\s*(\d+)', t2)
        if gm:
            return int(gm.group(2))
        gm = _re.search(
            rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)', t2)
        if gm:
            return int(gm.group(1))
    return None


def _find_const_assignment(lines: List[str], loop_line: int,
                           var: str) -> Optional[int]:
    """搜索变量最近的常量赋值: var = N; → N. 不跨函数边界."""
    for j in range(loop_line - 1, max(-1, loop_line - 20), -1):
        t2 = lines[j].strip()
        if re.match(r'\w[\w]*\s+\*?\s*\w+\s*\([^)]*\)\s*\{', t2):
            break
        m = re.search(
            rf'\b{re.escape(var)}\s*=\s*(\d+)\s*;', t2)
        if m:
            return int(m.group(1))
    return None


def find_guard_bounds(var_name: str, lines: List[str],
                       write_line: int) -> Tuple[Optional[int], Optional[int]]:
    """从源码中提取变量的guard约束区间 [lo, hi].

    搜索 clamp guard 和条件 guard, 返回 (lo, hi).
    None表示该方向无约束.
    """
    lo = None
    hi = None
    for i, line in enumerate(lines, start=1):
        if i > write_line:
            break
        text = line.strip()
        if text.startswith(('//', '/*', '#')):
            continue
        hi, lo = _scan_clamp_guards(text, var_name, hi, lo)
        hi, lo = _scan_cond_guards(text, var_name, hi, lo)
    return lo, hi


def _scan_clamp_guards(text: str, var: str, hi, lo):
    """扫描clamp: if(var > N) var = N; 和 if(var < N) var = N;"""
    m = re.search(
        rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)\s*'
        rf'{re.escape(var)}\s*=\s*(\d+)', text)
    if m:
        return int(m.group(2)), lo
    m = re.search(
        rf'if\s*\(\s*{re.escape(var)}\s*<\s*(\d+)\s*\)\s*'
        rf'{re.escape(var)}\s*=\s*(\d+)', text)
    if m:
        return hi, int(m.group(2))
    return hi, lo


def _scan_cond_guards(text: str, var: str, hi, lo):
    """扫描条件guard: if(var >= N), if(var > N), if(var <= N), if(var < N)."""
    if re.search(rf'if\s*\(\s*{re.escape(var)}\s*>=\s*(\d+)\s*\)', text):
        m = re.search(rf'if\s*\(\s*{re.escape(var)}\s*>=\s*(\d+)\s*\)', text)
        return hi, int(m.group(1))
    if re.search(rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)', text):
        m = re.search(rf'if\s*\(\s*{re.escape(var)}\s*>\s*(\d+)\s*\)', text)
        return hi, int(m.group(1)) + 1
    if re.search(rf'if\s*\(\s*{re.escape(var)}\s*<=\s*(\d+)\s*\)', text):
        m = re.search(rf'if\s*\(\s*{re.escape(var)}\s*<=\s*(\d+)\s*\)', text)
        return int(m.group(1)), lo
    if re.search(rf'if\s*\(\s*{re.escape(var)}\s*<\s*(\d+)\s*\)', text):
        m = re.search(rf'if\s*\(\s*{re.escape(var)}\s*<\s*(\d+)\s*\)', text)
        return int(m.group(1)) - 1, lo
    return hi, lo


_BUILTIN_SIZES = {
    'char': 1, 'int': 4, 'long': 8, 'short': 2,
    'float': 4, 'double': 8, 'size_t': 8,
}


def infer_stride(a, lines: List[str]) -> int:
    """推断数组元素步长(字节). 从sizeof表达式或变量声明类型推断."""
    m = re.search(r'sizeof\s*\(\s*(\w+)\s*\)', a.size_expr)
    if m:
        tn = m.group(1)
        if tn in _BUILTIN_SIZES:
            return _BUILTIN_SIZES[tn]
        from analysis.heap_overflow_src_patterns import _resolve_sizeof
        sz = _resolve_sizeof(tn, lines, a.line)
        if sz > 0:
            return sz
    for i in range(a.line - 1, max(-1, a.line - 10), -1):
        if i >= len(lines):
            continue
        text = lines[i].strip()
        m = re.search(r'\b(int|char|long|short|float|double)\s+\*?\s*'
                     + re.escape(a.var), text)
        if m:
            return _BUILTIN_SIZES.get(m.group(1), 4)
    return 4


__all__ = ['find_loop_bound_const', 'find_guard_bounds', 'infer_stride']
