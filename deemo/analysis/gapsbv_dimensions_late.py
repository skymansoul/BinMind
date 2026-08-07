"""
GAPSBV 后期维度分析函数 — StridedInterval 分析 + 分配器语义建模。

这两个维度依赖更重的分析基础设施 (StridedInterval, AllocatorChunkModel),

"""

from __future__ import annotations
import re

from analysis.gapsbv_dimensions import DimensionResult

def dim3_strided_interval(pseudocode: str) -> DimensionResult:
    """维度3: StridedInterval 分析 — 使用 s[lo,hi] 域进行边界检查. (权重 0.25)

    对比 malloc 分配大小和 memcpy 写入大小 (含指针偏移),
    在 strided interval 域中检查最坏情况溢出.
    若 hi_write + max_offset <= lo_alloc → SAFE.
    """
    try:
        from analysis.strided_interval import StridedInterval, si_singleton
    except ImportError:
        return DimensionResult("StridedInterval", 0.25, "UNCERTAIN", 0.0,
                               "strided interval module not available")

    alloc_si = _extract_size_interval(pseudocode,
        r'(?:malloc|calloc)\s*\(\s*([^)]+)\s*\)')

    # 提取 memcpy/memmove 写入大小, 同时追踪 dest 指针中的偏移量
    write_si = None
    max_offset = 0
    memcpy_pat = re.compile(
        r'(?:memcpy|memmove)\s*\(\s*([^,]+?)\s*,\s*[^,]*,\s*([^)]+)\s*\)',
        re.IGNORECASE)
    for m in memcpy_pat.finditer(pseudocode):
        dest_str = m.group(1).strip()
        size_str = m.group(2).strip()
        w_si = _extract_size_interval_from_str(size_str)
        # 提取指针偏移: buf + 32 → 32
        off_match = re.match(r'\w+\s*\+\s*(\d+)', dest_str)
        offset = int(off_match.group(1)) if off_match else 0
        max_offset = max(max_offset, offset)
        if write_si is None:
            write_si = w_si
        elif w_si is not None:
            write_si = write_si.widen(w_si)

    # strcpy/gets 等无界写入 → 不适合 strided interval 建模
    if re.search(r'\b(?:strcpy|strcat|gets|sprintf)\s*\(', pseudocode):
        return DimensionResult("StridedInterval", 0.25, "UNCERTAIN", 0.20,
                               "unbounded write (strcpy/gets) — stride interval inapplicable")

    if alloc_si is None or write_si is None:
        return DimensionResult("StridedInterval", 0.25, "UNCERTAIN", 0.15,
                               "cannot extract size intervals from pseudocode")

    # 将偏移量纳入写入区间: write_effective = [lo+offset, hi+offset]
    effective_write_lo = write_si.lo + max_offset
    effective_write_hi = write_si.hi + max_offset if write_si.hi >= 0 else -1

    if not write_si.is_unbounded() and not alloc_si.is_unbounded():
        if effective_write_hi <= alloc_si.lo:
            offset_note = f" + offset {max_offset}" if max_offset > 0 else ""
            return DimensionResult("StridedInterval", 0.25, "SAFE", 0.80,
                                   f"write max {effective_write_hi} <= alloc min {alloc_si.lo}"
                                   f"{offset_note} "
                                   f"(stride {alloc_si.stride}/{write_si.stride})")
        elif effective_write_lo > alloc_si.hi:
            offset_note = f" + offset {max_offset}" if max_offset > 0 else ""
            return DimensionResult("StridedInterval", 0.25, "OVERFLOW", 0.75,
                                   f"write min {effective_write_lo} > alloc max {alloc_si.hi}"
                                   f"{offset_note}")
        return DimensionResult("StridedInterval", 0.25, "CONDITIONAL", 0.35,
                               f"interval overlap (offset={max_offset}): alloc "
                               f"[{alloc_si.lo},{alloc_si.hi}] "
                               f"vs write [{effective_write_lo},{effective_write_hi}]")

    return DimensionResult("StridedInterval", 0.25, "UNCERTAIN", 0.20,
                           "unbounded interval — insufficient bounds")

def dim4_allocator_semantics(pseudocode: str) -> DimensionResult:
    """维度4: 分配器语义 — 应用 glibc/ptmalloc2 request2size 和 alignment. (权重 0.20)

    利用 chunk 对齐松弛空间消除误报:
    malloc(20) → ptmalloc2 实际可用 32B (MALLOC_ALIGNMENT=16, MINSIZE=32).
    若写入 ≤ 32B → SAFE (对齐松弛空间吸收).
    """
    MALLOC_ALIGNMENT = 16
    MINSIZE = 32
    SIZE_SZ = 8  # 64-bit

    def request2size(req: int) -> int:
        nb = req + SIZE_SZ
        if nb <= MINSIZE:
            return MINSIZE
        return (nb + MALLOC_ALIGNMENT - 1) & ~(MALLOC_ALIGNMENT - 1)

    def usable_size(req: int) -> int:
        return request2size(req) - SIZE_SZ

    alloc_pattern = re.compile(r'(?:malloc|calloc)\s*\(\s*([^)]+)\s*\)', re.IGNORECASE)
    # 捕获 dest (含偏移) + size
    write_pattern = re.compile(
        r'(?:memcpy|memmove)\s*\(\s*([^,]+?)\s*,\s*[^,]*,\s*([^)]+)\s*\)', re.IGNORECASE)

    alloc_sizes = alloc_pattern.findall(pseudocode)
    write_matches = write_pattern.findall(pseudocode)

    if not alloc_sizes:
        return DimensionResult("AllocatorSemantics", 0.20, "UNCERTAIN", 0.0,
                               "no allocation sites found")

    safe_sites = []
    overflow_sites = []
    for alloc_str in alloc_sizes:
        alloc_str = alloc_str.strip()
        try:
            req = int(alloc_str, 0)
            usable = usable_size(req)
            for dest_str, write_str in write_matches:
                write_str = write_str.strip()
                off_match = re.match(r'\w+\s*\+\s*(\d+)', dest_str.strip())
                offset = int(off_match.group(1)) if off_match else 0
                try:
                    wsize = int(write_str, 0)
                    effective = wsize + offset
                    if effective <= usable:
                        safe_sites.append(
                            f"malloc({req})→{usable}B usable >= "
                            f"write {wsize}B+offset{offset}={effective}B")
                    elif effective > req:
                        # 即使考虑slack, 写入仍超出请求大小 → 潜在溢出
                        overflow_sites.append(
                            f"malloc({req})→{usable}B usable < "
                            f"write {wsize}B+offset{offset}={effective}B")
                except ValueError:
                    pass
        except ValueError:
            pass

    # 溢出优先: 任一对overflow则不可判安全
    if overflow_sites:
        overflow_summary = "; ".join(overflow_sites[:2])
        if safe_sites:
            return DimensionResult("AllocatorSemantics", 0.20, "OVERFLOW", 0.75,
                                   f"{len(overflow_sites)} overflow, {len(safe_sites)} safe: {overflow_summary}")
        return DimensionResult("AllocatorSemantics", 0.20, "OVERFLOW", 0.80,
                               f"{len(overflow_sites)} overflow site(s): {overflow_summary}")
    elif safe_sites:
        return DimensionResult("AllocatorSemantics", 0.20, "SAFE", 0.70,
                               f"{len(safe_sites)} site(s) safe under ptmalloc2: "
                               + "; ".join(safe_sites[:2]))
    elif alloc_sizes:
        return DimensionResult("AllocatorSemantics", 0.20, "UNCERTAIN", 0.15,
                               f"{len(alloc_sizes)} alloc(s), "
                               f"{len(write_matches)} write(s) — no constant pair to verify")
    else:
        return DimensionResult("AllocatorSemantics", 0.20, "UNCERTAIN", 0.0,
                               "no analysable alloc-write pairs")

# 辅助函数

def _extract_size_interval_from_str(size_str: str):
    """从单个 size 字符串建模 strided interval. (从 _extract_size_interval 中提取)"""
    from analysis.strided_interval import StridedInterval, si_singleton

    size_str = size_str.strip()
    try:
        val = int(size_str, 0)
        return si_singleton(val)
    except ValueError:
        pass

    # sizeof(T) * n → stride = sizeof(T), unbounded hi
    sm = re.match(r'sizeof\s*\(\s*(\w+)\s*\)\s*\*\s*(\w+)', size_str, re.IGNORECASE)
    if sm:
        try:
            type_size = _estimate_sizeof(sm.group(1))
            return StridedInterval(lo=type_size, hi=-1, stride=type_size)
        except Exception:
            pass

    # n * sizeof(T)
    sm2 = re.match(r'(\w+)\s*\*\s*sizeof\s*\(\s*(\w+)\s*\)', size_str, re.IGNORECASE)
    if sm2:
        try:
            type_size = _estimate_sizeof(sm2.group(2))
            return StridedInterval(lo=type_size, hi=-1, stride=type_size)
        except Exception:
            pass

    # 变量或无法解析的表达式 → 保守: [0, inf)
    return StridedInterval(lo=0, hi=-1, stride=1)

def _extract_size_interval(code: str, pattern: str):
    """从代码中提取 size 表达式并建模为 strided interval."""
    matches = re.findall(pattern, code, re.IGNORECASE)
    if not matches:
        return None
    intervals = [si for size_str in matches
                 if (si := _extract_size_interval_from_str(size_str)) is not None]
    if not intervals:
        return None
    result = intervals[0]
    for si in intervals[1:]:
        result = result.widen(si)
    return result

def _estimate_sizeof(type_name: str) -> int:
    """估算 C 类型大小 (保守, 取常见值)."""
    sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8, 'float': 4,
             'double': 8, 'void': 1, 'size_t': 8, 'unsigned': 4,
             'uint8_t': 1, 'uint16_t': 2, 'uint32_t': 4, 'uint64_t': 8,
             'int8_t': 1, 'int16_t': 2, 'int32_t': 4, 'int64_t': 8}
    return sizes.get(type_name, 4)

__all__ = [
    'dim3_strided_interval', 'dim4_allocator_semantics',
    '_extract_size_interval', '_extract_size_interval_from_str',
    '_estimate_sizeof',
]
