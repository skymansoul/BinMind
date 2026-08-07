"""守卫条件匹配 — 利用关系约束证明动态alloc下的写入安全.

覆盖: 偏移守卫(G1), 循环守卫(G2), calloc展开(G3), 受控拷贝(G4).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple


class GuardVerdict(Enum):
    SAFE = "SAFE"           # 守卫条件可证明写入安全
    UNCERTAIN = "UNCERTAIN"  # 无法通过守卫证明
    NONE = "NONE"           # 不存在相关守卫


@dataclass
class GuardResult:
    """单次守卫分析结果."""
    verdict: GuardVerdict = GuardVerdict.NONE
    pattern: str = ""       # 'offset_guard'|'loop_guard'|'calloc_expand'|'bound_copy'
    alloc_var: str = ""
    alloc_size: int = 0     # 解析后的实际分配大小 (0=动态/未知)
    write_upper_bound: int = 0  # 写入上界 (最大偏移+最大大小)
    reason: str = ""


# 常量sizeof映射 (常见类型)
_SIZEOF_MAP: Dict[str, int] = {
    'int': 4, 'long': 8, 'long long': 8, 'short': 2, 'char': 1,
    'float': 4, 'double': 8, 'void*': 8, 'char*': 8, 'int*': 4,
    'size_t': 8, 'ssize_t': 8, 'uint32_t': 4, 'uint64_t': 8,
    'struct': -1,  # 无法确定, 保守处理
}


def _parse_sizeof(expr: str) -> int:
    """解析 sizeof(type) 表达式, 返回字节数. 无法解析返回 -1."""
    m = re.search(r'sizeof\s*\(\s*([\w\s*]+)\s*\)', expr)
    if m:
        type_name = m.group(1).strip()
        return _SIZEOF_MAP.get(type_name, -1)
    return -1


def _parse_calloc_nmemb_size(line: str) -> Tuple[int, int]:
    """解析 calloc(nmemb, size) → (nmemb, elem_size)."""
    m = re.search(r'calloc\s*\(\s*(\d+)\s*,\s*(.+?)\s*\)', line)
    if m:
        nmemb = int(m.group(1))
        size_expr = m.group(2).strip()
        # 尝试 sizeof
        elem_size = _parse_sizeof(size_expr)
        if elem_size > 0:
            return nmemb, elem_size
        # 尝试纯数字
        try:
            elem_size = int(size_expr)
            return nmemb, elem_size
        except ValueError:
            pass
    return 0, 0


def _find_offset_guard(lines: List[str], write_line: int,
                       buf_var: str, sz_var: str) -> Optional[GuardResult]:
    """G1: 搜索if(off<sz)守卫, sz=malloc参数 → buf[off]安全. 向上搜索最多15行."""
    guard_re = re.compile(
        r'if\s*\(\s*(\w[\w]*)\s*(<|<=)\s*(\w[\w]*)(?!\s*[+\-*/])')
    # 也匹配 if (sz > off) 的否定形式
    alt_re = re.compile(
        r'if\s*\(\s*(\w[\w]*)\s*(>|>=)\s*(\w[\w]*)(?!\s*[+\-*/])')

    search_start = max(0, write_line - 15)
    for i in range(write_line - 1, search_start - 1, -1):
        line = lines[i]
        m = guard_re.search(line)
        if m:
            v1, op, v2 = m.group(1), m.group(2), m.group(3)
            # 匹配 off < sz pattern
            if op == '<' and v1 != sz_var and v2 == sz_var:
                # v1 < sz → buf[v1] 安全 (如果v1是偏移变量)
                return GuardResult(
                    verdict=GuardVerdict.SAFE,
                    pattern='offset_guard',
                    alloc_var=buf_var,
                    write_upper_bound=-1,  # -1表示由守卫保证
                    reason=f'guard at L{i+1}: {v1} < {sz_var} proves offset within alloc')
            # 匹配 off <= sz-1 pattern
            if op == '<=' and v1 != sz_var and v2 == sz_var:
                return GuardResult(
                    verdict=GuardVerdict.SAFE,
                    pattern='offset_guard_le',
                    alloc_var=buf_var,
                    write_upper_bound=-1,
                    reason=f'guard at L{i+1}: {v1} <= {sz_var} proves offset within alloc')
        m2 = alt_re.search(line)
        if m2:
            v1, op, v2 = m2.group(1), m2.group(2), m2.group(3)
            # sz > off → off < sz
            if op == '>' and v1 == sz_var and v2 != sz_var:
                return GuardResult(
                    verdict=GuardVerdict.SAFE,
                    pattern='offset_guard_gt',
                    alloc_var=buf_var,
                    write_upper_bound=-1,
                    reason=f'guard at L{i+1}: {sz_var} > {v2} proves offset within alloc')
    return None


def _find_loop_guard(lines: List[str], write_line: int,
                     buf_var: str, sz_var: str) -> Optional[GuardResult]:
    """G2: for(i<sz)且sz=malloc参数 → buf[i]安全. 负向预查拒绝i<sz+N."""
    loop_re = re.compile(
        r'for\s*\(\s*(?:\w[\w]*\s+)?\w[\w]*\s*=\s*\d+\s*;\s*'
        r'(\w[\w]*)\s*<\s*(\w[\w]*)(?!\s*[+\-*/])')
    # 也匹配 i <= sz - 1 (减法只在 -1 时允许)
    loop_le_re = re.compile(
        r'for\s*\(\s*(?:\w[\w]*\s+)?\w[\w]*\s*=\s*\d+\s*;\s*'
        r'(\w[\w]*)\s*<=\s*(\w[\w]*)\s*-\s*1(?!\s*[+\-*/])')

    search_start = max(0, write_line - 10)
    for i in range(max(0, write_line - 10), min(write_line + 5, len(lines))):
        line = lines[i]
        m = loop_re.search(line)
        if m:
            idx_var, bound_var = m.group(1), m.group(2)
            if bound_var == sz_var:
                return GuardResult(
                    verdict=GuardVerdict.SAFE,
                    pattern='loop_guard',
                    alloc_var=buf_var,
                    write_upper_bound=-1,
                    reason=f'loop guard at L{i+1}: {idx_var} < {sz_var} proves loops within alloc')
        m2 = loop_le_re.search(line)
        if m2:
            idx_var, bound_var = m2.group(1), m2.group(2)
            if bound_var == sz_var:
                return GuardResult(
                    verdict=GuardVerdict.SAFE,
                    pattern='loop_guard_le',
                    alloc_var=buf_var,
                    write_upper_bound=-1,
                    reason=f'loop guard at L{i+1}: {idx_var} <= {sz_var}-1')
    return None


def _find_bound_copy(lines: List[str], write_line: int,
                     alloc_size: int) -> Optional[GuardResult]:
    """G4: strncpy/memcpy/snprintf第三参数 ≤ alloc_size → 安全."""
    copy_re = re.compile(
        r'(strncpy|memcpy|snprintf)\s*\([^,]+,\s*[^,]+,\s*(\d+)')
    line = lines[write_line]
    m = copy_re.search(line)
    if m:
        copy_size = int(m.group(2))
        if copy_size < alloc_size:
            return GuardResult(
                verdict=GuardVerdict.SAFE,
                pattern='bound_copy',
                write_upper_bound=copy_size,
                alloc_size=alloc_size,
                reason=f'{m.group(1)} bound={copy_size} < alloc={alloc_size}')
        elif copy_size <= alloc_size:
            # strncpy会复制最多N个字符+手动null终止
            # 如果 N == alloc_size, 仍安全 (最后一个字节留给null)
            return GuardResult(
                verdict=GuardVerdict.SAFE,
                pattern='bound_copy_exact',
                write_upper_bound=copy_size,
                alloc_size=alloc_size,
                reason=f'{m.group(1)} bound={copy_size} == alloc={alloc_size}')
    return None


def analyze_guard(source: str, func_name: str = "") -> List[GuardResult]:
    """对C源码执行守卫关系分析: 扫描malloc→write对, 尝试通过守卫条件证明安全."""
    lines = source.splitlines()
    if not lines:
        return []

    results: List[GuardResult] = []

    # 提取所有分配点
    alloc_re = re.compile(
        r'(\w[\w]*)\s*=\s*\(?\s*\w*\s*\*?\s*\)?\s*(malloc|calloc|realloc)\s*\(',
        re.IGNORECASE)
    allocs: List[Tuple[int, str, str, str, int]] = []
    # (line_no, var, func, size_var, size_const)

    for i, line in enumerate(lines):
        m = alloc_re.search(line)
        if not m:
            continue
        var, func = m.group(1), m.group(2).lower()

        # calloc常量展开
        if func == 'calloc':
            nmemb, esize = _parse_calloc_nmemb_size(line)
            if nmemb > 0 and esize > 0:
                allocs.append((i, var, func, '', nmemb * esize))
                continue

        # 提取size参数
        sz_var = ""
        sz_const = 0
        sm = re.search(rf'{func}\s*\(\s*(\d+|\w[\w]*)', line)
        if sm:
            try:
                sz_const = int(sm.group(1))
            except ValueError:
                sz_var = sm.group(1)
        allocs.append((i, var, func, sz_var, sz_const))

    # 提取所有写入点
    write_re = re.compile(
        r'(?:memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf'
        r'|scanf|fread|recv|read)\s*\(\s*(\w[\w]*)',
        re.IGNORECASE)
    arr_store_re = re.compile(r'(\w[\w]*)\s*\[\s*(\w[\w]*|\d+)\s*\]\s*=')

    writes: List[Tuple[int, str, str, int, int]] = []
    # (line_no, buf_var, idx_var, offset_const, write_size)

    for i, line in enumerate(lines):
        wm = write_re.search(line)
        if wm:
            buf_var = wm.group(1)
            writes.append((i, buf_var, '', 0, -1))  # -1 = 拷贝类, 大小未知
            continue
        am = arr_store_re.search(line)
        if am:
            buf_var = am.group(1)
            idx_val = am.group(2)
            try:
                off = int(idx_val)
                writes.append((i, buf_var, '', off, 1))
            except ValueError:
                writes.append((i, buf_var, idx_val, 0, 1))

    # 对每对 (alloc, write) 尝试守卫证明
    for ai_line, ai_var, ai_func, ai_sz_var, ai_sz_const in allocs:
        for wi_line, wi_var, wi_idx_var, wi_off, wi_sz in writes:
            if wi_var != ai_var:
                continue

            gr = GuardResult(verdict=GuardVerdict.UNCERTAIN,
                             alloc_var=ai_var, alloc_size=ai_sz_const)

            # 常量分配 + 常量偏移: 交给LPVRA处理, 不做守卫分析
            if ai_sz_const > 0 and wi_off >= 0 and wi_sz > 0:
                continue

            # G3: calloc常量展开 (已在提取阶段处理, 此处做二次确认)
            if ai_func == 'calloc' and ai_sz_const > 0:
                nmemb, esize = _parse_calloc_nmemb_size(lines[ai_line])
                if nmemb > 0 and esize > 0:
                    actual_sz = nmemb * esize
                    if wi_off >= 0 and wi_sz > 0 and wi_off + wi_sz <= actual_sz:
                        gr.verdict = GuardVerdict.SAFE
                        gr.pattern = 'calloc_expand'
                        gr.alloc_size = actual_sz
                        gr.reason = f'calloc({nmemb},{esize})={actual_sz}B >= write {wi_off + wi_sz}B'
                        results.append(gr)
                        continue

            # G4: 受控拷贝 (常量分配 + strncpy等有界操作)
            if ai_sz_const > 0:
                g4 = _find_bound_copy(lines, wi_line, ai_sz_const)
                if g4:
                    results.append(g4)
                    continue

            # G1: 偏移守卫 (需要动态size变量名)
            if ai_sz_var:
                g1 = _find_offset_guard(lines, wi_line, wi_var, ai_sz_var)
                if g1:
                    results.append(g1)
                    continue

            # G2: 循环守卫
            if ai_sz_var:
                g2 = _find_loop_guard(lines, wi_line, wi_var, ai_sz_var)
                if g2:
                    results.append(g2)
                    continue

    return results


__all__ = ['GuardVerdict', 'GuardResult', 'analyze_guard',
           '_parse_calloc_nmemb_size', '_parse_sizeof']
