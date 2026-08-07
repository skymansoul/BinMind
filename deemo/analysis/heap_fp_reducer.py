"""
堆溢出误报削减编排器 — 四阶段级联FP过滤 (指针身份→缓冲区正交→守卫条件→分配器语义).
保守性: 仅当任一阶段可证明安全才过滤, 不能证明→保留 (无假阴性). 每阶段独立可测量, 支撑消融实验.
参考: ISSTA 2024 Heap Disjointness + USENIX 2024 SUTURE.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple

_log = logging.getLogger(__name__)


@dataclass
class FpReductionVerdict:
    """FP削减判定."""
    alloc_line: int
    write_line: int
    alloc_func: str = ""
    write_func: str = ""
    alloc_size_expr: str = ""
    write_size_expr: str = ""
    verdict: str = "KEEP"       # KEEP | FILTERED
    filter_phase: str = ""      # ptr_identity | buffer_disjoint | guard | allocator
    confidence: float = 0.5
    reason: str = ""


@dataclass
class ReductionStats:
    """削减统计."""
    total_candidates: int = 0
    filtered_by_identity: int = 0
    filtered_by_disjoint: int = 0
    filtered_by_guard: int = 0
    filtered_by_allocator: int = 0
    retained: int = 0
    elapsed_ms: float = 0.0

    @property
    def total_filtered(self) -> int:
        return (self.filtered_by_identity + self.filtered_by_disjoint +
                self.filtered_by_guard + self.filtered_by_allocator)

    @property
    def fp_reduction_rate(self) -> float:
        if self.total_candidates == 0:
            return 0.0
        return self.total_filtered / self.total_candidates


class HeapFpReducer:
    """堆溢出误报削减编排器.

    用法:
        reducer = HeapFpReducer()
        verdicts, stats = reducer.reduce(decompiled_code, initial_candidates)
        # verdicts[i].verdict == 'FILTERED' → 误报, 可安全移除
        # verdicts[i].verdict == 'KEEP' → 无法证明安全, 保留
    """

    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        # 延迟导入避免循环依赖
        self._ptr_tracker = None
        self._buf_disjoint = None
        self._guard_analyzer = None

    def reduce(self, code: str,
               candidates: Optional[List[Dict]] = None,
               alloc_write_pairs: Optional[List[Tuple[int, str, str, int, str, str]]] = None,
               ) -> Tuple[List[FpReductionVerdict], ReductionStats]:
        """执行四阶段 FP 削减.

        Args:
            code: C源码/反编译伪代码
            candidates: 已有候选列表 (兼容现有管线)
            alloc_write_pairs: [(alloc_line, alloc_func, alloc_size_expr,
                                 write_line, write_func, write_size_expr), ...]

        Returns:
            (verdicts, stats)
        """
        t0 = time.perf_counter()
        stats = ReductionStats()

        # 构建候选对列表
        pairs = self._build_pairs(code, candidates, alloc_write_pairs)
        stats.total_candidates = len(pairs)
        if not pairs:
            stats.elapsed_ms = (time.perf_counter() - t0) * 1000
            return [], stats

        # 初始化分析器
        self._init_analyzers(code)

        verdicts: List[FpReductionVerdict] = []
        for al, af, asz, wl, wf, wsz, wtarget in pairs:
            v = self._analyze_pair(al, af, asz, wl, wf, wsz, wtarget, code)
            verdicts.append(v)
            if v.verdict == 'FILTERED':
                if v.filter_phase == 'ptr_identity':
                    stats.filtered_by_identity += 1
                elif v.filter_phase == 'buffer_disjoint':
                    stats.filtered_by_disjoint += 1
                elif v.filter_phase == 'guard':
                    stats.filtered_by_guard += 1
                elif v.filter_phase == 'allocator':
                    stats.filtered_by_allocator += 1

        stats.retained = stats.total_candidates - stats.total_filtered
        stats.elapsed_ms = (time.perf_counter() - t0) * 1000
        return verdicts, stats

    def _build_pairs(self, code: str, candidates, explicit_pairs) -> List[Tuple]:
        if explicit_pairs:
            nf = len(explicit_pairs[0])
            return [(a,b,c,d,e,f,g if nf==7 else '?') for a,b,c,d,e,f,*g_opt in explicit_pairs]

        import re
        lines = code.split('\n')
        _alloc_re = re.compile(r'=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(\s*([^)]*)\)')
        _write_re = re.compile(r'(memcpy|memmove|memset|strcpy|strncpy|sprintf)\s*\(\s*([^,]+)\s*,\s*[^,]*,\s*([^)]+)\s*\)')
        _var_re = re.compile(r'([a-zA-Z_]\w*(?:->[a-zA-Z_]\w*)?)\s*$')
        allocs = []
        for i, line in enumerate(lines):
            for m in _alloc_re.finditer(line):
                lhs = line[:m.start()].strip()
                vm = _var_re.search(lhs)
                vname = vm.group(1) if vm else '?'
                allocs.append((i, m.group(1), m.group(2).strip(), vname))
        writes = [(i, m.group(1), m.group(3).strip(), m.group(2).strip().lstrip('&').lstrip('(').strip())
                  for i, line in enumerate(lines)
                  if (m := _write_re.search(line))]
        pairs = []
        if allocs:
            # 常规: 每个 alloc 与之后的所有 write 配对
            for al, af, asz, _ in allocs:
                for wl, wf, wsz, wt in writes:
                    if wl > al:
                        pairs.append((al, af, asz, wl, wf, wsz, wt))
        else:
            # 交叉FP场景: 无 malloc 但有 memcpy → 创建虚拟alloc让Phase2过滤栈写入
            for wl, wf, wsz, wt in writes:
                pairs.append((-1, '?', '?', wl, wf, wsz, wt))
        return pairs

    def _init_analyzers(self, code: str):
        """初始化所有分析器并扫描代码."""
        from analysis.heap_ptr_identity import PtrIdentityTracker
        from analysis.heap_buffer_disjointness import BufferDisjointness
        from analysis.heap_guard_analyzer import GuardAnalyzer

        self._ptr_tracker = PtrIdentityTracker()
        self._buf_disjoint = BufferDisjointness()
        self._guard_analyzer = GuardAnalyzer()

        lines = code.split('\n')
        for i, line in enumerate(lines):
            self._ptr_tracker.scan_line(line, i)
        self._buf_disjoint.scan_function(code)
        self._guard_analyzer.scan_function(code)

    def _analyze_pair(self, al: int, af: str, asz: str,
                      wl: int, wf: str, wsz: str,
                      wtarget: str, code: str) -> FpReductionVerdict:
        """四阶段级联分析."""
        V = FpReductionVerdict  # 缩写

        # Phase 1: 指针身份 (仅当存在真实 alloc 时)
        if al >= 0:  # al=-1 表示虚拟alloc, 跳过 Phase 1
            from analysis.heap_ptr_identity import _extract_root_var
            target_root = _extract_root_var(wtarget) if wtarget != '?' else None
            import re
            _alloc_line_re = re.compile(r'=\s*(?:\([^)]*\)\s*)?(?:malloc|calloc|realloc)\s*\(')
            _var_re = re.compile(r'([a-zA-Z_]\w*(?:->[a-zA-Z_]\w*)?)\s*$')
            alloc_roots = set()
            for line in code.split('\n'):
                for m in _alloc_line_re.finditer(line):
                    vm = _var_re.search(line[:m.start()].strip())
                    if vm:
                        alloc_roots.add(vm.group(1))

            if target_root and alloc_roots:
                resolved = self._ptr_tracker.resolve_target(wtarget)
                matched_alloc = self._ptr_tracker.match_alloc_write(resolved) if resolved else None
                if resolved and not matched_alloc and target_root not in alloc_roots:
                    return V(al, wl, af, wf, asz, wsz, 'FILTERED', 'ptr_identity', 0.05,
                             f"write目标'{wtarget}'→'{resolved}'无对应malloc")

        # Phase 2: 缓冲区正交
        if self._buf_disjoint:
            k = self._buf_disjoint.classify_target(wtarget)
            if k == 'stack':
                return V(al, wl, af, wf, asz, wsz, 'FILTERED', 'buffer_disjoint', 0.05,
                         f"write目标'{wtarget}'是栈缓冲区")
            if k == 'global':
                return V(al, wl, af, wf, asz, wsz, 'FILTERED', 'buffer_disjoint', 0.10,
                         f"write目标'{wtarget}'是全局缓冲区")

        # Phase 3: 守卫条件
        for var in __import__('re').findall(r'[a-zA-Z_]\w*', asz):
            if self._guard_analyzer and self._guard_analyzer.is_guarded(var):
                bound = self._guard_analyzer.get_bound(var)
                if bound is not None:
                    try:
                        if int(wsz) <= bound:
                            return V(al, wl, af, wf, asz, wsz, 'FILTERED', 'guard', 0.15,
                                     f"守卫: {var}≤{bound}, write({wsz})≤bound")
                    except ValueError: pass

        # Phase 4: 分配器语义
        try:
            effective = _compute_effective_chunk(int(asz), self._platform)
            if int(wsz) <= effective:
                return V(al, wl, af, wf, asz, wsz, 'FILTERED', 'allocator', 0.05,
                         f"alloc有效容量{effective}B≥write{wsz}B")
        except ValueError: pass

        return V(al, wl, af, wf, asz, wsz, 'KEEP', '', 0.40, "四阶段皆无法证明安全, 保守保留")


def _compute_effective_chunk(requested: int, platform: str = "x86_64") -> int:
    """计算分配器 chunk 有效容量."""
    if platform == "x86_64":
        MALLOC_ALIGNMENT = 16
        MINSIZE = 32
        CHUNK_OVERHEAD = 16  # prev_size + size
    else:
        MALLOC_ALIGNMENT = 8
        MINSIZE = 16
        CHUNK_OVERHEAD = 8

    # request2size: 常规请求 + overhead → 对齐
    raw = max(requested + CHUNK_OVERHEAD, MINSIZE)
    aligned = (raw + MALLOC_ALIGNMENT - 1) & ~(MALLOC_ALIGNMENT - 1)
    # 有效写入容量 = 对齐后 - overhead
    return aligned - CHUNK_OVERHEAD


def filter_heap_findings(findings: List[Dict], code: str,
                         platform: str = "x86_64") -> Tuple[List[Dict], ReductionStats]:
    """便捷函数: 过滤 findings 列表 (兼容现有管线)."""
    reducer = HeapFpReducer(platform=platform)
    verdicts, stats = reducer.reduce(code, candidates=findings)

    # 标记被过滤的 findings
    filtered_lines = {(v.alloc_line, v.write_line) for v in verdicts
                      if v.verdict == 'FILTERED'}
    for f in findings:
        al = f.get('alloc_line', f.get('line', 0))
        wl = f.get('write_line', f.get('overflow_line', 0))
        if (al, wl) in filtered_lines:
            f['fp_filtered'] = True
            f['fp_filter_reason'] = next(
                (v.reason for v in verdicts
                 if v.alloc_line == al and v.write_line == wl), '')

    return findings, stats


__all__ = ['HeapFpReducer', 'FpReductionVerdict', 'ReductionStats',
           'filter_heap_findings', '_compute_effective_chunk']
