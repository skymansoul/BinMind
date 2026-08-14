"""
HOVF 指针算术写入通道 — 补齐强类型解引用写入、数组索引写入与带偏移库拷贝的候选提取。
只负责提取 (alloc, write) 候选对, 不做溢出判定; 判定由 hovf_engine 完成。
"""

import re
from typing import List, Optional, Tuple

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)
_CAST_DEREF_RE = re.compile(
    r'\*\s*\(\s*((?:un)?signed\s+)?[a-z_]\w*\s*\*+\s*\)\s*'
    r'\(\s*(\w+)\s*\+\s*([^)]+?)\s*\)\s*=')
_CAST_SIMPLE_RE = re.compile(
    r'\*\s*\(\s*((?:un)?signed\s+)?[a-z_]\w*\s*\*+\s*\)\s*(\w+)\s*=')
# 无类型解引用: *(buf + 72) = ... / *buf = ...
_PLAIN_OFF_RE = re.compile(r'\*\s*\(\s*(\w+)\s*\+\s*([^)]+?)\s*\)\s*=')
_PLAIN_SIMPLE_RE = re.compile(r'\*\s*(\w+)\s*=')
# 数组索引写入: buf[i] = / buf[i + 1] +=
_ARR_WRITE_RE = re.compile(
    r'(\w+)\s*\[\s*([^]]+?)\s*\]\s*(?:\+\+|\+=|-=|=)')
# 带偏移库写入: memcpy(buf + off, src, n)
_LIB_OFF_RE = re.compile(
    r'(memcpy|memmove|memset|strcpy|strcat|strncpy)\s*\(\s*'
    r'(\w+)\s*\+\s*([^,]+?)\s*(?:,|\))')

from core.hovf_write_patterns import (
    _CAST_DEREF_RE, _CAST_SIMPLE_RE, _PLAIN_OFF_RE, _PLAIN_SIMPLE_RE,
    _ARR_WRITE_RE, _LIB_OFF_RE, _DECL_RE,
    _cast_width, _resolve_const, _extract_var_offset, _extract_stride,
    _elem_width, _attach_loop_extent, _strip_block_comments,
)

def _loop_bound_for(ir_lines: List[str], line_idx: int, var: str) -> Tuple[int, bool]:
    """向上搜索含 var 的 for 循环, 提取终止上界.

    终止条件为常量时直接返回; 为变量时经值流解析其钳位上界.
    返回 (上界, 是否来自守卫钳位). 上界缺失返回 (-1, False).
    守卫钳位来源的上界可作宽松过滤证据, 普通常量上界不可,
    否则会吞掉 off-by-one 类边界漏洞.
    """
    for i in range(max(0, line_idx - 12), line_idx + 1):
        line = ir_lines[i] if 0 <= i < len(ir_lines) else ''
        if 'for' not in line or '(' not in line:
            continue
        if var not in line and var not in ir_lines[max(0, i):line_idx + 1][:4]:
            continue
        m = re.search(r'for\s*\([^;]*;\s*\w+\s*[<>]=?\s*(0x[0-9a-fA-F]+|\d+)',
                      line)
        if m:
            try:
                bound = int(m.group(1), 0)
                if 0 < bound < 1_000_000:
                    return bound, False
            except ValueError:
                pass
        # 变量终止条件路径: i < n 形式, n 经值流钳位求上界
        m2 = re.search(r'for\s*\([^;]*;\s*\w+\s*[<>]=?\s*(\w+)\s*;', line)
        if m2:
            from core.hovf_size_vflow import resolve_alloc_size
            res = resolve_alloc_size(m2.group(1), ir_lines, i)
            if res.interval is not None:
                hi = res.interval.hi
                if 0 < hi < 1_000_000:
                    guard = any('钳位' in r for r in res.reasons)
                    return hi, guard
    return -1, False


def _match_alloc(base_var: str,
                 alloc_sites: List[HeapAllocSite]) -> Optional[HeapAllocSite]:
    """按变量名匹配分配位点, 返回最近一次分配."""
    for site in reversed(alloc_sites):
        if site.result_var == base_var:
            return site
    return None


def _deref_write(ir: List[str], line_idx: int, line: str,
                 alloc_sites: List[HeapAllocSite],
                 candidates: List[HeapOverflowCandidate],
                 provenance: str) -> None:
    """处理解引用写入: 强类型/无类型, 常量或变量偏移."""
    if _DECL_RE.search(line) and '=' in line and \
            re.search(r'\*(\w+)\s*=', line):
        head = re.sub(r'^.*?\*\s*(\w+)\s*=.*$', r'\1', line)
        if head.isidentifier() and _match_alloc(head, alloc_sites) is not None:
            return  # 声明初始化 `*buf = malloc(...)`, 非写入
    base = None
    off_expr = None
    width = 4
    m = _CAST_DEREF_RE.search(line)
    if m:
        width = _cast_width(m.group(1) or '')
        base, off_expr = m.group(2), m.group(3)
    if not m:
        m = _CAST_SIMPLE_RE.search(line)
        if m:
            width = _cast_width(m.group(1) or '')
            base, off_expr = m.group(2), '0'
    if not m:
        m = _PLAIN_OFF_RE.search(line)
        if m:
            base, off_expr = m.group(1), m.group(2)
    if not m:
        m = _PLAIN_SIMPLE_RE.search(line)
        if m:
            base, off_expr = m.group(1), '0'
    if not m or not base:
        return
    alloc = _match_alloc(base, alloc_sites)
    if alloc is None:
        return
    offset = _resolve_const(off_expr)
    if offset is None:
        var, c_off = _extract_var_offset(off_expr)
        bound, bound_guard = (
            _loop_bound_for(ir, line_idx, var) if var else (-1, False))
        store = HeapStore(pc=line_idx, base_var=base, offset=c_off,
                          offset_is_dynamic=True, store_size=width,
                          mnemonic='hovf_deref')
        desc = (f'{alloc.alloc_func}({alloc.size_arg}) 动态偏移写入 '
                f'(循环上界={bound})')
        candidates.append(HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=-1, confidence=0.55, description=desc))
        candidates[-1]._hovf_offset_var = var or ''
        candidates[-1]._hovf_guard_applied = bound_guard
        if bound > 0:
            _attach_loop_extent(candidates[-1], bound, width)
        return
    store = HeapStore(pc=line_idx, base_var=base, offset=offset,
                      offset_is_dynamic=False, store_size=width,
                      mnemonic='hovf_deref')
    candidates.append(HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        overflow_bytes=0, confidence=0.65,
        description=f'{alloc.alloc_func}({alloc.size_arg}) 解引用写入 '
                    f'offset={offset} size={width} {provenance}'))





def _array_write(ir: List[str], line_idx: int, line: str,
                 alloc_sites: List[HeapAllocSite],
                 candidates: List[HeapOverflowCandidate]) -> None:
    """处理数组索引写入: buf[i] = / buf[i+c] = / buf[i*K] =."""
    m = _ARR_WRITE_RE.search(line)
    if not m:
        return
    base, idx = m.group(1), m.group(2).strip()
    alloc = _match_alloc(base, alloc_sites)
    if alloc is None:
        return
    width = _elem_width(base, ir, line_idx)
    const_off = _resolve_const(idx)
    if const_off is not None:
        store = HeapStore(pc=line_idx, base_var=base, offset=const_off,
                          offset_is_dynamic=False, store_size=width,
                          mnemonic='hovf_array')
        candidates.append(HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=0, confidence=0.60,
            description=f'{alloc.alloc_func}({alloc.size_arg}) 数组写入 '
                        f'index={const_off}'))
        return
    var, stride, c_off = _extract_stride(idx)
    bound, bound_guard = (
        _loop_bound_for(ir, line_idx, var) if var else (-1, False))
    store = HeapStore(pc=line_idx, base_var=base, offset=c_off,
                      offset_is_dynamic=True, store_size=width,
                      mnemonic='hovf_array')
    candidates.append(HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        overflow_bytes=-1, confidence=0.50,
        description=f'{alloc.alloc_func}({alloc.size_arg}) 循环数组写入 '
                    f'(上界={bound})'))
    candidates[-1]._hovf_offset_var = var or ''
    candidates[-1]._hovf_guard_applied = bound_guard
    if bound > 0:
        _attach_loop_extent(candidates[-1], (bound - 1) * stride + c_off + 1,
                            width)


def _lib_write(ir: List[str], line: str, line_idx: int,
               alloc_sites: List[HeapAllocSite],
               candidates: List[HeapOverflowCandidate]) -> None:
    """处理库写入: 无界拷贝与带/不带偏移的有界拷贝.

    无界拷贝 (strcpy/strcat/gets/sprintf) 在任何偏移上都是潜在溢出,
    交由引擎按无界规则确认, 不参与宽松过滤. 有界拷贝
    (memcpy/memmove/memset/strncpy) 提取目标偏移与拷贝大小, 参与
    宽松判定, 落在分配器可用空间内的为误报.
    """
    m = _LIB_OFF_RE.search(line)
    if not m:
        m = re.search(
            r'(memcpy|memmove|memset|strcpy|strcat|strncpy|gets|scanf|'
            r'sprintf)\s*\(\s*(\w+)(?:\s*\+\s*([^,)]+))?\s*(?:,|\))',
            line)
    if not m:
        return
    mnemonic = m.group(1).lower()
    base = m.group(2)
    off_expr = m.group(3) or '0'
    alloc = _match_alloc(base, alloc_sites)
    if alloc is None:
        return
    unbounded = mnemonic in ('strcpy', 'strcat', 'gets', 'scanf',
                             'sprintf')
    offset = _resolve_const(off_expr)
    store_size = -1
    if not unbounded:
        mm = re.search(r',\s*(0x[0-9a-fA-F]+|\d+)\s*\)', line)
        if mm:
            store_size = int(mm.group(1), 0)
        else:
            mm = re.search(r',\s*([a-z_]\w*)\s*\)', line)
            if mm:
                from core.hovf_size_vflow import resolve_macro
                macro_val = resolve_macro(mm.group(1), ir)
                if macro_val is not None:
                    store_size = macro_val
    if offset is None:
        var, c_off = _extract_var_offset(off_expr)
        store = HeapStore(pc=line_idx, base_var=base, offset=c_off,
                          offset_is_dynamic=True, store_size=store_size,
                          mnemonic=mnemonic)
        candidates.append(HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=-1, confidence=0.55,
            description=f'{alloc.alloc_func}({alloc.size_arg}) {mnemonic} '
                        f'动态偏移写入'))
        candidates[-1]._hovf_offset_var = var or ''
        return
    store = HeapStore(pc=line_idx, base_var=base, offset=offset,
                      offset_is_dynamic=False, store_size=store_size,
                      mnemonic=mnemonic)
    candidates.append(HeapOverflowCandidate(
        alloc_site=alloc, overflow_store=store,
        overflow_bytes=0, confidence=0.60,
        description=f'{alloc.alloc_func}({alloc.size_arg}) {mnemonic} '
                    f'offset={offset}'))


def extract_hovf_candidates(
    ir: List[str],
    alloc_sites: List[HeapAllocSite],
) -> List[HeapOverflowCandidate]:
    """提取全部指针算术写入候选, 与既有通道并行, 不修改既有结果."""
    candidates: List[HeapOverflowCandidate] = []
    ir = _strip_block_comments(ir)
    for i, line in enumerate(ir):
        if not line or line.lstrip().startswith(('#', '//', '/*')):
            continue
        _deref_write(ir, i, line, alloc_sites, candidates, 'hovf_chan')
        _array_write(ir, i, line, alloc_sites, candidates)
        _lib_write(ir, line, i, alloc_sites, candidates)
    return candidates


def extract_hovf_alloc_sites(ir: List[str]) -> List[HeapAllocSite]:
    """从源码级提取器生成 HOVF 分配位点, 兼容带类型转换的声明.

    基础提取器要求 `var = malloc(...)` 紧邻形式, 对
    `char *buf = (char *)malloc(64)` 无法取到变量名; 源码级提取器
    的声明解析可处理类型转换前缀, 转换其输出为 HeapAllocSite.
    """
    try:
        from core.source_level_candidate_extractor_writes import (
            _extract_alloc_sites,
        )
    except ImportError:
        return []
    # 剔除块注释后再提取, 注释内嵌的 malloc(64) 会被源码级提取器
    # 误判为分配位点.
    clean_ir = _strip_block_comments(list(ir))
    raw = _extract_alloc_sites(clean_ir, {})
    sites: List[HeapAllocSite] = []
    for d in raw:
        var = d.get('var') or ''
        if not var:
            continue
        sites.append(HeapAllocSite(
            pc=d['pc'], alloc_func=d['func'],
            size_arg=d.get('size_arg', 0) if not d.get('is_dyn') else 0,
            size_is_dynamic=bool(d.get('is_dyn')),
            result_var=var,
            size_expr=d.get('size_str', '') if d.get('is_dyn') else '',
        ))
    return sites
