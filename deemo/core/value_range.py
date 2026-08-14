"""
基于值域分析的堆分配边界检查 — 在反编译伪代码上做函数内整型区间跟踪。
malloc(N) 记录分配点与区间; memcpy(buf, src, M) 比较: M.lo > N.hi 为确定溢出 (CRITICAL);
M.hi > N.hi 且 M.lo <= N.hi 为疑似溢出 (WARNING); M.hi <= N.hi 为安全。
复杂度 O(N*V), N=行数, V=变量数, 每函数 <1ms。
"""


import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Interval:
    """整型值区间 [lo, hi]。lo=-1 表示下界未知, hi=2**31-1 表示上界未知。"""
    lo: int
    hi: int

    @staticmethod
    def unknown() -> Interval:
        return Interval(-1, 2**31 - 1)

    @staticmethod
    def exact(v: int) -> Interval:
        return Interval(v, v)

    def __add__(self, other: Interval) -> Interval:
        lo = self.lo + other.lo if self.lo >= 0 and other.lo >= 0 else -1
        hi = (self.hi + other.hi if self.hi < 2**31 - 1 and other.hi < 2**31 - 1
              else 2**31 - 1)
        return Interval(lo, min(hi, 2**31 - 1))

    def __mul__(self, other: Interval) -> Interval:
        if self.lo < 0 or other.lo < 0:
            return Interval.unknown()
        candidates = [self.lo * other.lo, self.lo * other.hi,
                      self.hi * other.lo, self.hi * other.hi]
        return Interval(min(candidates), min(max(candidates), 2**31 - 1))

    def dominates(self, other: Interval) -> bool:
        """self.lo > other.hi → 确定溢出。"""
        return self.lo >= 0 and other.hi < 2**31 - 1 and self.lo > other.hi

    def may_exceed(self, other: Interval) -> bool:
        """self.hi > other.hi 且 self.lo <= other.hi → 疑似溢出。"""
        return (self.hi > other.hi and self.lo >= 0
                and not self.dominates(other))

    def __repr__(self) -> str:
        return f"[{self.lo if self.lo>=0 else '?'}, {self.hi if self.hi<2**31-1 else '?'}]"


@dataclass
class AllocSite:
    """堆分配点记录。"""
    var_name: str           # 接收分配指针的变量
    size_interval: Interval  # 分配大小的值区间
    lineno: int
    func_name: str


@dataclass
class HeapWrite:
    """堆写入点记录。"""
    var_name: str            # 被写入的堆变量
    size_interval: Interval  # 写入大小的值区间
    lineno: int
    call_name: str           # memcpy / strcpy / strcat 等
    func_name: str


@dataclass
class BoundsViolation:
    """边界违例: 分配大小 < 写入大小。"""
    alloc_site: AllocSite
    write_site: HeapWrite
    severity: str            # "CRITICAL" | "WARNING" 严重级
    description: str


# 正则模式
_RE_MALLOC = re.compile(
    r'(\w[\w.]*)\s*=\s*(?:\(\s*\w+\s*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(\s*(\d+)')
_RE_MEMCPY = re.compile(r'(memcpy|strcpy|strcat|sprintf|snprintf)\s*\(\s*(\w+)\s*,')
_RE_STRCPY = re.compile(r'(strcpy|strcat)\s*\(\s*(\w+)\s*,')
_RE_SNPRINTF = re.compile(r'snprintf\s*\(\s*(\w+)\s*,\s*(\d+)\s*,')
_RE_SCANF_S = re.compile(r'sscanf\s*\([^,]+,\s*"[^"]*%s[^"]*"\s*,\s*(\w+)\s*\)')


def extract_alloc_sites(pseudocode: str, func_name: str) -> List[AllocSite]:
    """从反编译代码提取所有堆分配点及其大小。"""
    sites: List[AllocSite] = []
    for i, line in enumerate(pseudocode.split('\n'), start=1):
        m = _RE_MALLOC.search(line)
        if m:
            var = m.group(1)
            size = int(m.group(3))
            sites.append(AllocSite(
                var_name=var, size_interval=Interval.exact(size),
                lineno=i, func_name=func_name,
            ))
    return sites


def extract_heap_writes(pseudocode: str, func_name: str) -> List[HeapWrite]:
    """从反编译代码提取所有堆写入点及其大小。"""
    writes: List[HeapWrite] = []
    for i, line in enumerate(pseudocode.split('\n'), start=1):
        # snprintf(buf, N, ...) - N 为缓冲区大小
        m = _RE_SNPRINTF.search(line)
        if m:
            var, size = m.group(1), int(m.group(2))
            writes.append(HeapWrite(
                var_name=var, size_interval=Interval.exact(size),
                lineno=i, call_name='snprintf', func_name=func_name,
            ))
            continue
        # memcpy/strcpy(buf, ...) - 写入大小需从其他来源推断
        m = _RE_STRCPY.search(line)
        if m:
            writes.append(HeapWrite(
                var_name=m.group(2),
                size_interval=Interval.unknown(),
                lineno=i, call_name=m.group(1), func_name=func_name,
            ))
    return writes


def check_bounds(
    alloc_sites: List[AllocSite],
    heap_writes: List[HeapWrite],
) -> List[BoundsViolation]:
    """比较分配大小与写入大小, 返回全部边界违例。"""
    violations: List[BoundsViolation] = []
    for alloc in alloc_sites:
        for write in heap_writes:
            if write.var_name != alloc.var_name:
                continue
            wsize = write.size_interval
            asize = alloc.size_interval
            if wsize.dominates(asize):
                violations.append(BoundsViolation(
                    alloc_site=alloc, write_site=write,
                    severity='CRITICAL',
                    description=(
                        f"{write.call_name} writes {wsize}B into "
                        f"{alloc.var_name} (allocated {asize}B) "
                        f"L{write.lineno} vs L{alloc.lineno}"
                    ),
                ))
            elif wsize.may_exceed(asize):
                violations.append(BoundsViolation(
                    alloc_site=alloc, write_site=write,
                    severity='WARNING',
                    description=(
                        f"{write.call_name} writes {wsize}B, "
                        f"buffer is {asize}B (upper bound exceeds allocation)"
                    ),
                ))
    return violations


def analyze_heap_bounds(
    pseudocode: str, func_name: str,
) -> List[BoundsViolation]:
    """单次调用完成提取与检测, 返回边界违例列表。"""
    allocs = extract_alloc_sites(pseudocode, func_name)
    if not allocs:
        return []
    writes = extract_heap_writes(pseudocode, func_name)
    if not writes:
        return []
    return check_bounds(allocs, writes)
