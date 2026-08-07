"""
保守C源码分析器 — 将所有 (malloc, write) 对标记为候选, 不过滤.

与 c_source_analyzer 的关系:
  - c_source_analyzer: 精确分析, 仅产生有溢出证据的候选 (高精度)
  - 本模块: 保守分析, 产生所有堆分配+写入对作为候选 (高召回 → 供FP削减管线消费)

策略: 提取真实偏移/大小信息, 但不基于比较结果过滤.
      GAPSBV阶段负责全部过滤决策.
"""


import re
from typing import List

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)
from analysis.c_source_patterns import (
    parse_alloc_call, _STORE_PAT_DIRECT, _STORE_PAT_ARROW,
    _STORE_PAT_DEREF, _STORE_PAT_PTR_ARITH,
    parse_size, resolve_constant,
)

# realloc 追踪: buf = realloc(buf, newsize) — 更新分配大小
_RE_REALLOC_UPDATE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w+\s*\*\s*\)\s*)?realloc\s*\(\s*\1\s*,\s*(.+?)\)\s*;?',
    re.IGNORECASE,
)


def _is_comment_or_empty(line: str) -> bool:
    stripped = line.strip()
    return (not stripped or stripped.startswith('//') or
            stripped.startswith('/*') or stripped.startswith('*') or
            stripped.startswith('#'))


def _extract_offset_int(m, group_idx: int = 2) -> int:
    """从正则匹配组提取整数偏移, 失败返回-1."""
    try:
        return int(m.group(group_idx), 0)
    except (ValueError, IndexError):
        return -1


def _extract_stores_conservative(
    lines: List[str], alloc: HeapAllocSite, resolver=None,
) -> List[HeapStore]:
    """保守提取: 所有对alloc变量的写入都视为潜在溢出store.

    提取真实偏移/大小信息 (供阶段使用), 但不过滤.
    v2: 使用 resolver 解析 memcpy/memset 的变量大小.
    """
    buf_var = alloc.result_var
    if not buf_var:
        return []
    stores = []
    start = alloc.pc + 1
    end = min(len(lines), alloc.pc + 80)

    for i in range(start, end):
        line = lines[i]
        if _is_comment_or_empty(line):
            continue

        # memcpy/memset/strcpy/snprintf(buf, ...) — 提取写入大小
        m = _STORE_PAT_DIRECT.search(line)
        if m and m.group(1) == buf_var:
            from analysis.c_source_write_utils import extract_func_write_size
            # 提取实际函数名作为 mnemonic
            func_m = re.search(
                r'(memcpy|memset|memmove|strcpy|strncpy|sprintf|snprintf)\s*\(',
                line, re.IGNORECASE)
            mnemonic = func_m.group(1).lower() if func_m else 'memcpy'
            write_size = extract_func_write_size(line, lines, i)
            # v2: 若 extract_func_write_size 返回 -1, 尝试变量解析
            if write_size <= 0 and resolver:
                write_size = resolver.resolve_store_size(i)
            stores.append(HeapStore(
                pc=i, base_var=buf_var,
                offset=0, offset_is_dynamic=False,
                store_size=write_size if write_size > 0 else -1,
                mnemonic=mnemonic,
            ))
            continue

        # strcpy(buf, ...)
        if f'strcpy({buf_var},' in line or f'strcpy({buf_var},' in line:
            stores.append(HeapStore(
                pc=i, base_var=buf_var,
                offset=0, offset_is_dynamic=False,
                store_size=-1, mnemonic='strcpy',
            ))
            continue

        # buf[idx] = val — 提取偏移
        for sm in _STORE_PAT_ARROW.finditer(line):
            if sm.group(1) == buf_var:
                off = _extract_offset_int(sm, 2)
                if off >= 0:
                    stores.append(HeapStore(
                        pc=i, base_var=buf_var, offset=off,
                        offset_is_dynamic=False, store_size=4,
                        mnemonic='mov',
                    ))
                else:
                    # 动态索引 buf[i] — 仍标记为候选 (保守)
                    stores.append(HeapStore(
                        pc=i, base_var=buf_var, offset=0,
                        offset_is_dynamic=True, store_size=4,
                        mnemonic='mov',
                    ))

# (type*)(buf + N) = val
        m3 = _STORE_PAT_DEREF.search(line)
        if m3 and m3.group(1) == buf_var:
            off = _extract_offset_int(m3, 2)
            stores.append(HeapStore(
                pc=i, base_var=buf_var,
                offset=off if off >= 0 else 0,
                offset_is_dynamic=(off < 0),
                store_size=8, mnemonic='mov',
            ))
            continue

# (buf + N) = val
        m4 = _STORE_PAT_PTR_ARITH.search(line)
        if m4 and m4.group(1) == buf_var:
            off = _extract_offset_int(m4, 2)
            stores.append(HeapStore(
                pc=i, base_var=buf_var,
                offset=off if off >= 0 else 0,
                offset_is_dynamic=(off < 0),
                store_size=8, mnemonic='mov',
            ))

    return stores


def analyze_c_source_conservative(source: str) -> List[HeapOverflowCandidate]:
    """保守分析C源码 — 所有 malloc+write 对都是候选.

    提取真实偏移/大小信息供阶段使用, 但不做任何过滤.
    返回的候选 confidence=0.50 (中性), 由 GAPSBV 阶段调整.

    v2: 使用 CSourceVarResolver 解析变量大小, 使 malloc(sz) 和
    memcpy(buf, src, len) 能提取实际常量值, 提升 S1 过滤能力.
    """
    from analysis.c_source_var_resolver import CSourceVarResolver

    lines = source.splitlines()
    allocs: List[HeapAllocSite] = []

    # 变量解析器: 一次性收集所有定义, 供后续查询
    resolver = CSourceVarResolver(lines)

    for i, line in enumerate(lines):
        if _is_comment_or_empty(line):
            continue
        result = parse_alloc_call(line, is_decl=True)
        if result:
            var, func, size, is_dyn, size_expr = result
            # v2: 若 parse_alloc_call 返回 size=0 (动态), 尝试变量解析
            if size <= 0 and size_expr:
                resolved = resolver.resolve(size_expr)
                if resolved > 0:
                    size = resolved
                    is_dyn = False
                    size_expr = ""
            allocs.append(HeapAllocSite(
                pc=i, alloc_func=func, size_arg=size,
                size_is_dynamic=is_dyn, result_var=var,
                size_expr=size_expr,
            ))

    for i, line in enumerate(lines):
        if _is_comment_or_empty(line):
            continue
        result = parse_alloc_call(line, is_decl=False)
        if result:
            var, func, size, is_dyn, size_expr = result
            # v2: 变量解析
            if size <= 0 and size_expr:
                resolved = resolver.resolve(size_expr)
                if resolved > 0:
                    size = resolved
                    is_dyn = False
                    size_expr = ""
            if not any(a.result_var == var for a in allocs):
                allocs.append(HeapAllocSite(
                    pc=i, alloc_func=func, size_arg=size,
                    size_is_dynamic=is_dyn, result_var=var,
                    size_expr=size_expr,
                ))

    # v3: realloc 追踪 — 更新最新 alloc 的大小
    for i, line in enumerate(lines):
        if _is_comment_or_empty(line):
            continue
        m = _RE_REALLOC_UPDATE.search(line)
        if m:
            var, size_str = m.group(1), m.group(2).strip().rstrip(';').strip()
            new_size, is_dyn = parse_size(size_str)
            if new_size <= 0 and resolver:
                resolved = resolver.resolve(size_str)
                if resolved > 0:
                    new_size = resolved
                    is_dyn = False
            # 更新该变量最近的 alloc_site
            for a in reversed(allocs):
                if a.result_var == var:
                    a.size_arg = new_size
                    a.size_is_dynamic = is_dyn
                    a.size_expr = size_str if is_dyn else ""
                    break

    candidates: List[HeapOverflowCandidate] = []
    for alloc in allocs:
        stores = _extract_stores_conservative(lines, alloc, resolver=resolver)
        for store in stores:
            overflow = 1  # 保守: 总有溢出风险
            if store.offset >= 0 and store.store_size > 0 and alloc.size_arg > 0:
                end = store.offset + store.store_size
                if end > alloc.size_arg:
                    overflow = end - alloc.size_arg
                else:
                    overflow = 0

            candidates.append(HeapOverflowCandidate(
                alloc_site=alloc,
                overflow_store=store,
                overflow_bytes=max(0, overflow),
                confidence=0.50,
                description=(
                    f'{alloc.alloc_func}({alloc.size_arg})→'
                    f'{store.base_var}[{store.offset}] '
                    f'sz={store.store_size}'
                ),
            ))

    candidates.sort(key=lambda c: -c.confidence)
    return candidates
