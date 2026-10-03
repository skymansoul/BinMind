"""
LPVRA 路径敏感配对分析器 — alloc/write发现 + 配对 + 路径敏感安全评估.
"""

from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Optional, Set, Tuple

from analysis.interval_domain import Interval
from analysis.lpvra_types import (
    Verdict, AllocInfo, WriteInfo, HeapVerdict,
    _ALLOC_RE, _WRITE_RE, _ARRAY_STORE_RE,
)


class PairAnalyzer:
    """堆alloc-write配对分析 + 路径敏感安全评估."""

    _SIZE_VAR_RE = re.compile(
        r'(?:malloc|calloc|realloc)\s*\(\s*(\d+|\w[\w]*)')

    # calloc sizeof解析 — 匹配 sizeof(type) 或纯数字作为第二参数
    _SIZEOF_MAP = {
        'int': 4, 'long': 8, 'long long': 8, 'short': 2, 'char': 1,
        'float': 4, 'double': 8, 'void*': 8, 'char*': 8, 'int*': 4,
        'size_t': 8, 'ssize_t': 8, 'uint32_t': 4, 'uint64_t': 8,
    }
    _CALLOC_ARGS_RE = re.compile(
        r'calloc\s*\(\s*(\d+)\s*,\s*(sizeof\s*\([^)]+\)|\d+)\s*\)')

    @classmethod
    def _resolve_calloc_size(cls, line: str) -> int:
        """解析 calloc(nmemb, sizeof(type)) → nmemb * elem_size.
        无法解析返回 0."""
        m = cls._CALLOC_ARGS_RE.search(line)
        if not m:
            return 0
        nmemb = int(m.group(1))
        size_expr = m.group(2).strip()
        # sizeof(type) — size_expr已是完整 "sizeof(int)"
        if size_expr.startswith('sizeof'):
            sfm = re.search(r'sizeof\s*\(\s*([\w\s*]+)\s*\)', size_expr)
            if sfm:
                type_name = sfm.group(1).strip()
                elem = cls._SIZEOF_MAP.get(type_name, 0)
                if elem > 0:
                    return nmemb * elem
        # 纯数字
        try:
            return nmemb * int(size_expr)
        except ValueError:
            return 0

    def __init__(self, max_paths: int = 128):
        self._max_paths = max_paths

    def find_allocs(self, lines: List[str]) -> List[AllocInfo]:
        """提取所有堆分配点 (含calloc nmemb*sizeof展开)."""
        allocs = []
        for i, line in enumerate(lines, start=1):
            m = _ALLOC_RE.search(line)
            if not m:
                continue
            var, func = m.group(1), m.group(2).lower()
            size_var = ""
            size_const = 0
            if func == 'calloc':
                # calloc(nmemb, sizeof(type)) → 计算实际大小
                size_const = self._resolve_calloc_size(line)
                if size_const <= 0:
                    sm = self._SIZE_VAR_RE.search(line)
                    if sm:
                        try:
                            size_const = int(sm.group(1))
                        except ValueError:
                            size_var = sm.group(1)
            elif func == 'realloc':
                sm = re.search(r'realloc\s*\([^,]+,\s*(\d+|\w[\w]*)', line)
                if sm:
                    try:
                        size_const = int(sm.group(1))
                    except ValueError:
                        size_var = sm.group(1)
            else:
                sm = self._SIZE_VAR_RE.search(line)
                if sm:
                    try:
                        size_const = int(sm.group(1))
                    except ValueError:
                        size_var = sm.group(1)
            allocs.append(AllocInfo(i, var, func, size_var, size_const))
        return allocs

    def find_writes(self, lines: List[str]) -> List[WriteInfo]:
        """提取所有堆缓冲区写入点 (含变量大小的 memcpy)."""
        writes = []
        for i, line in enumerate(lines, start=1):
            wm = _WRITE_RE.search(line)
            if wm:
                arg_m = re.search(
                    r'(?:memcpy|strcpy|strncpy|memset|memmove|sprintf|snprintf'
                    r'|scanf|fread|recv|read)\s*\(\s*(\w[\w]*)', line)
                if not arg_m:
                    continue
                var = arg_m.group(1)
                op = wm.group(0).split('(')[0].lower()
                size = -1
                size_var = ""
                if op in ('strncpy', 'memcpy', 'memset', 'memmove',
                          'snprintf', 'fread', 'recv', 'read'):
                    # 尝试匹配常量大小
                    sz_m = re.search(
                        r'(?:strncpy|memcpy|memset|memmove|snprintf|fread|recv|read)'
                        r'\s*\([^,]+,\s*[^,]+,\s*(\d+)', line)
                    if sz_m:
                        size = int(sz_m.group(1))
                    else:
                        # 尝试匹配变量大小
                        szv_m = re.search(
                            r'(?:strncpy|memcpy|memset|memmove|snprintf|fread|recv|read)'
                            r'\s*\([^,]+,\s*[^,]+,\s*(\w[\w]*)', line)
                        if szv_m:
                            size_var = szv_m.group(1)
                writes.append(WriteInfo(i, var, 0, size, op, size_var))
                continue
            am = _ARRAY_STORE_RE.search(line)
            if am:
                var = am.group(1)
                try:
                    offset = int(am.group(2))
                except ValueError:
                    offset = -1
                # 默认元素大小=1 (保守: char数组的单字节写入)
                writes.append(WriteInfo(i, var, offset, 1, 'store'))
        return writes

    def check_pair(self, ai: AllocInfo, wi: WriteInfo,
                   lines: List[str], blocks: List[Dict],
                   adj: Dict[int, List[int]],
                   block_entry_state: Dict[int, Dict[str, Interval]]
                   ) -> Optional[HeapVerdict]:
        """路径敏感评估单个 alloc-write 对."""
        alloc_block = -1
        write_block = -1
        for b in blocks:
            if b['start'] <= ai.line_no - 1 <= b['end']:
                alloc_block = b['id']
            if b['start'] <= wi.line_no - 1 <= b['end']:
                write_block = b['id']
        if alloc_block < 0 or write_block < 0:
            return None

        init_state = dict(block_entry_state.get(alloc_block, {}))
        if ai.size_const > 0:
            init_iv = Interval.const(ai.size_const)
            init_state[ai.var] = init_iv
        elif ai.size_var and ai.size_var in init_state:
            init_iv = init_state[ai.size_var]
            init_state[ai.var] = init_iv
        else:
            init_iv = Interval.top()
            init_state[ai.var] = init_iv

        safe_count = 0
        overflow_count = 0
        uncertain_count = 0
        total = 0

        q = deque()
        q.append((alloc_block, dict(init_state), [(alloc_block, 'start')]))
        visited = set()

        while q and total < self._max_paths:
            cur_bid, state, trace = q.popleft()
            state_key = (cur_bid, tuple(sorted(
                (k, v.lo, v.hi) for k, v in state.items())))
            if state_key in visited:
                continue
            visited.add(state_key)

            if cur_bid == write_block:
                v = self._evaluate_at_write(ai, wi, state)
                if v == Verdict.SAFE:
                    safe_count += 1
                elif v == Verdict.OVERFLOW:
                    overflow_count += 1
                else:
                    uncertain_count += 1
                total += 1
                continue

            b = blocks[cur_bid] if cur_bid < len(blocks) else None
            if b is None:
                continue
            new_state = self._process_block_fn(b, state, lines)
            for sid in adj.get(cur_bid, []):
                q.append((sid, dict(new_state), trace + [(sid, 'succ')]))

        effective = self._effective_boundary(ai)
        if total == 0:
            return HeapVerdict(
                ai.var, ai.line_no, init_iv, wi.var, wi.line_no,
                wi.offset, wi.size, effective,
                Verdict.UNCERTAIN, 0, 0, "no reachable paths")

        if safe_count == total and total > 0:
            return HeapVerdict(
                ai.var, ai.line_no, init_iv, wi.var, wi.line_no,
                wi.offset, wi.size, effective,
                Verdict.SAFE, safe_count, total,
                f"all {safe_count}/{total} paths safe")
        if overflow_count == total:
            return HeapVerdict(
                ai.var, ai.line_no, init_iv, wi.var, wi.line_no,
                wi.offset, wi.size, effective,
                Verdict.OVERFLOW, 0, total,
                f"{overflow_count}/{total} paths overflow")
        return HeapVerdict(
            ai.var, ai.line_no, init_iv, wi.var, wi.line_no,
            wi.offset, wi.size, effective,
            Verdict.UNCERTAIN, safe_count, total,
            f"mixed: {safe_count}s/{overflow_count}o/{uncertain_count}u")

    def _evaluate_at_write(self, ai: AllocInfo, wi: WriteInfo,
                           state: Dict[str, Interval]) -> Verdict:
        """在写入点评估安全性. malloc(n)+memcpy(buf,src,n): 检查n是否在边界内."""
        if ai.size_const > 0:
            size_iv = Interval.const(ai.size_const)
        elif ai.size_var and ai.size_var in state and not state[ai.size_var].is_top():
            size_iv = state[ai.size_var]
        elif ai.var in state and not state[ai.var].is_top():
            size_iv = state[ai.var]
        else:
            size_iv = Interval.top()

        effective = self._effective_boundary(ai)

        # 变量大小写入: 若 write.size_var == alloc.size_var, 写=分 → 安全
        if wi.size < 0 and wi.size_var:
            if wi.size_var == ai.size_var and ai.size_var:
                # 同一变量同时控制分配和写入大小 → 写 ≤ 分 (考虑slack)
                if size_iv.is_const():
                    alloc_val = size_iv.const_val()
                    if alloc_val is not None and alloc_val <= effective:
                        return Verdict.SAFE
                if not size_iv.is_top() and size_iv.hi is not None:
                    if size_iv.hi <= effective:
                        return Verdict.SAFE
                    # 若 hi > effective 但约束保证 hi 不超过 effective
                    if size_iv.hi <= max(effective, ai.size_const):
                        return Verdict.SAFE
                # 有约束的变量, 写=分 → 保守安全 (slack 吃掉了差异)
                if size_iv.hi is not None and size_iv.hi < (1 << 20):
                    return Verdict.SAFE
                return Verdict.UNCERTAIN
            # 不同变量或未知关系 → 无法证明
            return Verdict.UNCERTAIN

        if wi.size < 0:
            sz_lo = (size_iv.lo if size_iv.lo is not None else 0) if not size_iv.is_top() else 0
            if sz_lo >= (1 << 20):
                return Verdict.SAFE
            return Verdict.UNCERTAIN
        total_write = wi.offset + max(wi.size, 1)

        if size_iv.is_top():
            return Verdict.UNCERTAIN
        lo = size_iv.lo if size_iv.lo is not None else 0
        hi = size_iv.hi if size_iv.hi is not None else (2**31 - 1)
        actual_lo = max(lo, effective)
        if total_write <= actual_lo:
            return Verdict.SAFE
        if total_write > hi:
            return Verdict.OVERFLOW
        return Verdict.UNCERTAIN

    @staticmethod
    def effective_boundary_from_raw(raw: int) -> int:
        """从原始分配大小计算含glibc chunk slack的有效边界."""
        if raw <= 0:
            return 0
        align = 16
        aligned = ((raw + align - 1) // align) * align
        return max(raw, aligned)

    @staticmethod
    def _effective_boundary(ai: AllocInfo) -> int:
        """计算含glibc chunk slack的有效边界."""
        return PairAnalyzer.effective_boundary_from_raw(ai.size_const)

    # process_block 回调 (由 LPVRAEngine 注入)
    _process_block_fn: any = None
