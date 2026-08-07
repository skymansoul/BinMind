"""改进的堆溢出检测器 — 值流约束 + 路径守卫窄化 + 安全证明 + 语义评分.

创建: 2026-06-07
修改: 2026-06-07 (集成路径守卫窄化 + 安全证明器)

管线 (5阶段 + 守卫窄化):
  0. 收集路径守卫 (cmp+jcc 约束)
  1. 识别 malloc/calloc/realloc 调用点
  2. 后向值流推断 + 路径守卫窄化 → 精确 size 区间
  3. 扫描: 显式 [reg+offset] 访问 / 函数调用 / 内联拷贝 / 跨函数 site
  4. 安全证明器: 三态判定 DEFINITELY_SAFE → 跳过
  5. SemanticFPFilter: 语义特征加权评分 (仅 POTENTIALLY_UNSAFE)
"""
from __future__ import annotations

import logging as _log
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .malloc_size_inferrer import MallocSizeInferrer, MallocSite
from .interval_domain import SInterval, AllocatorModel, DEFAULT_ALLOCATOR
from .semantic_fp_filter import SemanticFalsePositiveFilter, SemanticFeatures
from .access_parser import (
    identify_alloc_sites, parse_memory_access, find_nearest_alloc,
    parse_offset, build_mem_regexes)
from .path_guard_collector import collect_guards, PathGuard
from .value_range_narrowing import narrow_with_dual_regs
from .heap_safety_prover import HeapSafetyProver, SafetyVerdict, SafetyProof
from .detector_context import build_context, is_user_function

# 复用原有 HeapBoundInferrer (fallback)
import sys as _sys
_orig_path = list(_sys.path)
_parent = __file__
for _ in range(6):
    _parent = (_parent[:_parent.rfind('/')]
               if '/' in _parent
               else _parent[:_parent.rfind('\\')])
_sys.path.insert(0, _parent)
try:
    from heap_bound_infer import HeapBoundInferrer
except ImportError:
    class HeapBoundInferrer:  # type: ignore[no-redef]
        def __init__(self): self._violations = []
_sys.path = _orig_path


@dataclass
class HeapOverflowFinding:
    """一次堆溢出检测的完整结果."""
    insn_addr: int
    function_name: str
    description: str
    alloc_site: int
    alloc_size_requested: int
    alloc_size_usable: int
    access_offset: int
    access_size: int
    overflow_bytes: int
    semantic_score: float = 0.5
    is_likely_fp: bool = False
    fp_reason: str = ""
    confidence: float = 0.5
    size_source: str = ""
    safety_verdict: str = ""  # DEFINITELY_SAFE / POTENTIALLY_UNSAFE / DEFINITELY_UNSAFE


class ImprovedHeapOverflowDetector:
    """值流约束 + 路径守卫窄化 + 安全证明的堆溢出检测器."""

    def __init__(self, allocator: Optional[AllocatorModel] = None):
        self._size_inferrer = MallocSizeInferrer()
        self._fp_filter = SemanticFalsePositiveFilter(fp_threshold=0.35)
        self._bound_inferrer = HeapBoundInferrer()
        if allocator:
            self._size_inferrer.set_allocator_model(allocator)
        self._mem_write_re, self._mem_read_re = build_mem_regexes()
        self._only_user_code: bool = True

    def analyze(self,
                instructions: List[str],
                blocks: Optional[List[Tuple[int, List[str]]]] = None,
                cfg_edges: Optional[List[Tuple[int, int]]] = None,
                function_name: str = "",
                addrs: Optional[List[int]] = None,
                ) -> List[HeapOverflowFinding]:
        """五阶段管线 + 路径守卫窄化 + 安全证明."""
        findings: List[HeapOverflowFinding] = []

        if not is_user_function(function_name, self._only_user_code):
            return findings

        # 阶段0: 收集路径守卫
        guards = collect_guards(instructions, addrs)

        # 阶段1: 识别分配点
        alloc_sites_raw = identify_alloc_sites(instructions)
        if not alloc_sites_raw:
            return findings

        # 阶段2: size 推断 + 守卫窄化
        malloc_sites: Dict[int, MallocSite] = {}
        for call_idx, func_name in alloc_sites_raw:
            site = self._size_inferrer.infer(instructions, call_idx, func_name)
            nv, _ = narrow_with_dual_regs(call_idx, site.size_interval, guards)
            if nv.was_improved:
                site.size_interval = nv.narrowed
            malloc_sites[call_idx] = site

        prover = self._get_safety_prover()

        # 阶段3a: 扫描显式内存访问 + 安全证明
        for i, instr in enumerate(instructions):
            il = instr.strip()
            if not il or il.startswith(';') or '[' not in il or ']' not in il:
                continue
            if any(x in il.lower() for x in ('rsp', 'rbp', '[rip')):
                continue

            access = parse_memory_access(
                i, il, function_name, self._mem_write_re, self._mem_read_re)
            if access is None:
                continue

            alloc_addr = find_nearest_alloc(access['insn_addr'], malloc_sites)
            if alloc_addr is None:
                continue

            site = malloc_sites[alloc_addr]
            offset = parse_offset(access['offset_expr'])
            usable_lo, _ = self._size_inferrer.usable_range(site)

            # 安全证明: 三态判定
            proof = prover.prove(
                alloc_addr, site.size_interval, offset,
                access['access_size'], guards)
            if proof.verdict == SafetyVerdict.DEFINITELY_SAFE:
                continue

            if offset + access['access_size'] <= usable_lo:
                continue

            finding = self._build_finding(
                access['insn_addr'], function_name, site,
                offset, access['access_size'], instructions, i,
                guards=guards, proof=proof)
            findings.append(finding)

        # 合成跨函数 MallocSite
        synth = self._get_cross_fn_propagator().inject_synthetic_sites(function_name)
        for sa, ss in synth.items():
            if sa not in malloc_sites:
                malloc_sites[sa] = ss

        # 阶段3b: 函数调用型溢出
        findings += self._get_call_overflow_detector().scan(
            instructions, malloc_sites, function_name, guards=guards)

        # 阶段3c: 内联拷贝 + sprintf/循环
        inline_det = self._get_inline_copy_detector()
        findings += inline_det.scan(
            instructions, malloc_sites, function_name, addrs=addrs, guards=guards)

        # 阶段3d: 跨函数调用 site 溢出
        inline_det._track_heap_ptrs(instructions, malloc_sites)
        findings += self._get_cross_fn_propagator().detect_at_callsites(
            instructions, malloc_sites, function_name,
            heap_regs=inline_det._heap_regs, addrs=addrs)

        # 阶段A: 注册跨函数调用 (供 callee 分析)
        self._get_cross_fn_propagator().register_callsites(
            instructions, malloc_sites, function_name,
            heap_regs=inline_det._heap_regs, addrs=addrs)

        findings.sort(key=lambda f: -f.semantic_score)
        return findings

    def _build_finding(self, insn_addr: int, function_name: str,
                       site: MallocSite, offset: int, access_size: int,
                       instructions: List[str], access_idx: int,
                       guards: Optional[List[PathGuard]] = None,
                       proof: Optional[SafetyProof] = None
                       ) -> HeapOverflowFinding:
        usable_lo, _ = self._size_inferrer.usable_range(site)
        ctx = build_context(instructions, access_idx, site, offset, guards)
        features = self._fp_filter.extract_features(site, offset, access_size, ctx)
        sem_score = self._fp_filter.score(features)
        is_fp = self._fp_filter.is_likely_fp(features)
        overflow = max(0, offset + access_size - usable_lo)

        safety_v, confidence = "", sem_score
        if proof is not None:
            if proof.verdict == SafetyVerdict.DEFINITELY_UNSAFE:
                confidence = max(sem_score, 0.92)
                is_fp = False
                safety_v = 'DEFINITELY_UNSAFE'
            elif proof.verdict == SafetyVerdict.POTENTIALLY_UNSAFE:
                safety_v = 'POTENTIALLY_UNSAFE'
            elif proof.verdict == SafetyVerdict.DEFINITELY_SAFE:
                safety_v = 'DEFINITELY_SAFE'

        size_desc = (f'精确:{site.size_interval.lo}'
                     if site.size_interval.lo == site.size_interval.hi
                     else f'区间:[{site.size_interval.lo},{site.size_interval.hi}]')
        return HeapOverflowFinding(
            insn_addr=insn_addr, function_name=function_name,
            description=(
                f'heap overflow: offset={offset} access_size={access_size} '
                f'exceeds alloc={usable_lo} at {function_name}:0x{insn_addr:x}'),
            alloc_site=site.insn_addr,
            alloc_size_requested=site.size_interval.min_possible(),
            alloc_size_usable=usable_lo, access_offset=offset,
            access_size=access_size, overflow_bytes=overflow,
            semantic_score=sem_score, is_likely_fp=is_fp,
            fp_reason=(self._fp_filter._explain(features, sem_score) if is_fp else ""),
            confidence=confidence, size_source=size_desc,
            safety_verdict=safety_v)

# 延迟初始化

    def _get_call_overflow_detector(self):
        if not hasattr(self, '_call_overflow_det'):
            from .call_overflow_detector import CallOverflowDetector
            self._call_overflow_det = CallOverflowDetector(
                self._size_inferrer, self._fp_filter)
        return self._call_overflow_det

    def _get_inline_copy_detector(self):
        if not hasattr(self, '_inline_copy_det'):
            from .inline_copy_detector import InlineCopyDetector
            self._inline_copy_det = InlineCopyDetector()
        return self._inline_copy_det

    def _get_cross_fn_propagator(self):
        if not hasattr(self, '_cross_fn_prop'):
            from .cross_fn_propagator import CrossFunctionPropagator
            self._cross_fn_prop = CrossFunctionPropagator()
        return self._cross_fn_prop

    def _get_safety_prover(self):
        if not hasattr(self, '_safety_prover'):
            self._safety_prover = HeapSafetyProver()
        return self._safety_prover

    @property
    def stats(self) -> dict:
        d = {'fp_filter': self._fp_filter.stats,
             'size_inferrer': self._size_inferrer.stats()}
        if hasattr(self, '_safety_prover'):
            d['safety_prover'] = self._safety_prover.stats
        return d

    def clear(self) -> None:
        self._fp_filter.clear()
        if hasattr(self, '_safety_prover'):
            self._safety_prover.clear()
        if hasattr(self._bound_inferrer, 'clear'):
            self._bound_inferrer.clear()
