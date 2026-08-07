"""GAPSBV 5-stage heap overflow detection: interval→constraint→loop→allocator→FP.
+ affine + taint tracking. Ref: Guo et al. ISSTA 2024."""
import re
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from core.forward_interval_prop import Interval, AllocSite, WriteSite
from core.interval_propagator import ForwardIntervalPropagator
from core.path_constraint_collector import (
    PathConstraintCollector, collect_and_refine)
from core.loop_bound_widening import (
    LoopBoundInferrer, LoopInfo, infer_heap_write_bounds)
from core.allocator_model import AllocatorType, detect_allocator
from core.heap_verifier import verify_overflow, apply_relational_check
from core.affine_analyzer import AffineAnalyzer
from core.taint_tracker import TaintTracker, taint_adjust_confidence
@dataclass
class EnhancedHeapCandidate:
    """Heap overflow candidate with analysis provenance."""
    alloc_site: AllocSite
    write_site: WriteSite
    refined_alloc_iv: Interval
    refined_write_iv: Interval
    loop_info: Optional[LoopInfo]
    effective_alloc: int
    verdict: str  # CONFIRMED | FILTERED | UNCERTAIN
    confidence: float
    fp_likelihood: float
    overflow_bytes_min: int
    overflow_bytes_max: int
    stage_results: Dict[str, Any] = field(default_factory=dict)
    def summary(self) -> str:
        return (
            f"[{self.verdict}] alloc={self.refined_alloc_iv} "
            f"write={self.refined_write_iv} "
            f"eff_chunk={self.effective_alloc}B "
            f"overflow=[{self.overflow_bytes_min}, {self.overflow_bytes_max}]B "
            f"conf={self.confidence:.2f} fp={self.fp_likelihood:.2f}"
        )
class EnhancedHeapOverflowDetector:
    """Five-stage enhanced heap overflow detector.
    Usage:
      detector = EnhancedHeapOverflowDetector(platform="x86_64")
      candidates = detector.detect(ir_lines, binary_path="")
    """
    def __init__(self, platform: str = "x86_64"):
        self._platform = platform
        self._interval_prop = ForwardIntervalPropagator()
        self._constraint_collector = PathConstraintCollector()
        self._loop_inferrer = LoopBoundInferrer()
        self._allocator: AllocatorType = AllocatorType.GLIBC_PTMALLOC2
        self.stats: Dict[str, Any] = {}
    def detect(
        self,
        ir_lines: List[str],
        binary_path: str = "",
        arch_bits: int = 64,
    ) -> List[EnhancedHeapCandidate]:
        """Run all five stages on IR lines, return sorted candidates."""
        t0 = time.time()
        self.stats = {'s1_allocs': 0, 's1_writes': 0,
                      's2_constraints': 0, 's3_loops': 0,
                      's4_verified': 0, 's5_candidates': 0}
        if binary_path:
            detected = detect_allocator(binary_path)
            # UNKNOWN回退到glibc ptmalloc2 — Linux平台默认分配器
            if detected != AllocatorType.UNKNOWN:
                self._allocator = detected
        # Stage 1: Forward interval propagation
        allocs, writes = self._interval_prop.analyze(ir_lines)
        self.stats['s1_allocs'] = len(allocs)
        self.stats['s1_writes'] = len(writes)
        if not allocs or not writes:
            self.stats['elapsed'] = time.time() - t0
            return []
        # 1.5: Kill superseded alloc sites
        # realloc(buf, N) / malloc on same var invalidates earlier alloc sites
        allocs = self._dedup_alloc_sites(allocs)
        # Stage 2: Constraint collection & refinement
        constraints = self._constraint_collector.extract_constraints(ir_lines)
        self.stats['s2_constraints'] = len(constraints)
        # Stage 3: Loop detection
        loops = self._loop_inferrer.detect_loops(ir_lines)
        self.stats['s3_loops'] = len(loops)
        # Stage 3.5: Affine relation analysis
        affine = AffineAnalyzer()
        aff_allocs, aff_writes, _ = affine.analyze(ir_lines)
        # Map alloc var → size var name for affine matching
        aff_alloc_sz: Dict[str, str] = {
            a['var']: a['size_var'] for a in aff_allocs}
        self.stats['affine_mallocs'] = len(aff_allocs)
        self.stats['affine_writes'] = len(aff_writes)
        self.stats['affine_proven'] = 0
        self.stats['taint_adjustments'] = 0
        # Taint: 识别攻击者可控size变量
        taint = TaintTracker()
        taint.analyze(ir_lines)
        self.stats['tainted_vars'] = taint.stats()['tainted_vars']
        # Stage 4 & 5: Verify each alloc-write pair
        candidates: List[EnhancedHeapCandidate] = []
        for alloc in allocs:
            refined_alloc = alloc.size_interval
            # Apply constraints near the allocation site
            refined_alloc, _ = collect_and_refine(
                ir_lines, alloc.var_name, refined_alloc, alloc.loc)
            for write in writes:
                # Alias check: does this write target the alloc variable?
                if write.dst_var != alloc.var_name:
                    # Heuristic: check if write.dst_var is a derived pointer
                    is_alias, alias_offset = self._is_likely_alias(
                        write.dst_var, alloc.var_name,
                        ir_lines, write.loc)
                    if not is_alias:
                        continue
                else:
                    alias_offset = 0
                refined_write = write.size_interval
                refined_write, _ = collect_and_refine(
                    ir_lines, write.dst_var, refined_write, write.loc)
                # Alias offset: write at buf+offset → check [offset, offset+size] vs alloc
                if alias_offset > 0:
                    refined_write = Interval(
                        refined_write.lo + alias_offset,
                        (refined_write.hi + alias_offset
                         if refined_write.hi < 2**63 - 1
                         else 2**63 - 1))
                # Loop context: scale write by loop bound
                loop_info = self._loop_inferrer.get_loop_context(write.loc)
                if loop_info and not loop_info.is_dynamic:
                    write_iv, _ = infer_heap_write_bounds(
                        ir_lines, alloc.var_name, write.loc)
                    if not write_iv.is_top:
                        refined_write = write_iv
                # Stage 4: Allocator-aware verification
                is_loop_synth = (
                    write.loc < len(ir_lines) and
                    'loop_write' in ir_lines[write.loc]
                )
                verdict, confidence, fp_like, eff_alloc, ov_min, ov_max = \
                    verify_overflow(alloc, write, refined_alloc,
                                    refined_write, arch_bits,
                                    self._allocator, loop_info,
                                    is_loop_write=is_loop_synth)
                self.stats['s4_verified'] += 1
                # Affine override: prove overflow from x=k*y+c relations
                alloc_sz_var = aff_alloc_sz.get(alloc.var_name, '')
                for aw in aff_writes:
                    if aw['dst_var'] == write.dst_var and alloc_sz_var:
                        ok, _ = affine.resolve_overflow_candidates(
                            alloc.var_name, alloc_sz_var, aw['size_var'],
                            aw['affine_state'])
                        if ok is True:
                            verdict = 'CONFIRMED'
                            confidence = max(confidence, 0.78)
                            fp_like = min(fp_like, 0.15)
                            self.stats['affine_proven'] += 1
                            break  # proven: stop checking other writes
                        # False/None: continue to check other writes
                # Taint: 攻击者可控→提权, 常量→降权
                prev_conf = confidence
                alloc_sz = aff_alloc_sz.get(alloc.var_name, '')
                write_sz = next((aw['size_var'] for aw in aff_writes
                                 if aw['dst_var'] == write.dst_var), '')
                confidence = taint_adjust_confidence(
                    alloc_sz, write_sz, confidence, taint)
                if confidence != prev_conf:
                    self.stats['taint_adjustments'] += 1
                # Taint verdict upgrade: 两端攻击者可控+无约束 → 真漏洞
                if (alloc_sz and write_sz
                    and taint.taint_score(alloc_sz) >= 1.0
                    and taint.taint_score(write_sz) >= 1.0
                    and verdict in ('FILTERED', 'UNCERTAIN')
                    and alloc.size_interval.is_top
                    and write.size_interval.is_top):
                    verdict = 'CONFIRMED'
                    confidence = max(confidence, 0.62)
                    fp_like = min(fp_like, 0.28)
                    self.stats['taint_upgraded'] = (
                        self.stats.get('taint_upgraded', 0) + 1)
                cand = EnhancedHeapCandidate(
                    alloc_site=alloc,
                    write_site=write,
                    refined_alloc_iv=refined_alloc,
                    refined_write_iv=refined_write,
                    loop_info=loop_info,
                    effective_alloc=eff_alloc,
                    verdict=verdict,
                    confidence=confidence,
                    fp_likelihood=fp_like,
                    overflow_bytes_min=ov_min,
                    overflow_bytes_max=ov_max,
                    stage_results={
                        'constraints_applied': len(constraints),
                        'loops_detected': len(loops),
                        'allocator': self._allocator.value,
                    },
                )
                candidates.append(cand)
        # Relational: write_size = alloc_size * k (k>1) → overflow
        candidates = apply_relational_check(ir_lines, candidates)
        candidates.sort(key=lambda c: (-c.confidence, -c.overflow_bytes_max))
        self.stats['s5_candidates'] = len(candidates)
        self.stats['confirmed'] = sum(1 for c in candidates if c.verdict == 'CONFIRMED')
        self.stats['filtered'] = sum(1 for c in candidates if c.verdict == 'FILTERED')
        self.stats['uncertain'] = sum(1 for c in candidates if c.verdict == 'UNCERTAIN')
        self.stats['elapsed'] = round(time.time() - t0, 4)
        return candidates
    @staticmethod
    def _dedup_alloc_sites(allocs: List[AllocSite]) -> List[AllocSite]:
        """同变量取最新: realloc/malloc覆盖旧alloc site。"""
        seen: Dict[str, AllocSite] = {}
        for a in sorted(allocs, key=lambda x: x.loc):
            seen[a.var_name] = a
        return list(seen.values())
    def _is_likely_alias(
        self, var1: str, var2: str,
        ir_lines: List[str], at_line: int,
    ) -> Tuple[bool, int]:
        """(is_alias, offset): ptr=buf+N, &buf[N], struct→field, direct copy."""
        # Exact match
        if var1 == var2:
            return True, 0
        # Struct field access: base->field aliases base (offset=0, conservative)
        # 例如 c->payload → c 是同一块堆内存的字段写入
        m_field = re.match(rf'^{re.escape(var2)}\s*->\s*(\w[\w.]*)', var1)
        if m_field:
            return True, 0  # 保守: 字段偏移未知时设为0
        # Look for assignment: var1 = var2 [+ offset]
        for i in range(max(0, at_line - 10), at_line):
            line = ir_lines[i]
            # ptr = buf + N  (positive offset)
            m = re.search(
                rf'{re.escape(var1)}\s*=\s*{re.escape(var2)}\s*\+\s*(\d+)',
                line)
            if m:
                return True, int(m.group(1))
            # ptr = &buf[N]
            m = re.search(
                rf'{re.escape(var1)}\s*=.*&{re.escape(var2)}\[(\d+)\]', line)
            if m:
                return True, int(m.group(1))
            # ptr = buf  (direct pointer copy, offset=0)
            if re.search(rf'{re.escape(var1)}\s*=\s*{re.escape(var2)}\s*$', line):
                return True, 0
        return False, 0
    def summary_table(self, candidates: List[EnhancedHeapCandidate]) -> str:
        """One-line-per-candidate summary table."""
        lines = ["EnhancedHeapDetector Results",
                 f"{'Verdict':12s} {'Alloc':20s} {'Write':20s} "
                 f"{'Overflow':12s} {'Conf':6s} {'FP%':6s}",
                 "-" * 80]
        for c in candidates:
            lines.append(
                f"{c.verdict:12s} {str(c.refined_alloc_iv):20s} "
                f"{str(c.refined_write_iv):20s} "
                f"[{c.overflow_bytes_min},{c.overflow_bytes_max}]B "
                f"{c.confidence:.2f}  {c.fp_likelihood:.2f}")
        return '\n'.join(lines)
def detect_heap_overflow_enhanced(
    ir_lines: List[str],
    binary_path: str = "",
    arch_bits: int = 64,
) -> Tuple[List[EnhancedHeapCandidate], Dict[str, Any]]:
    """Run enhanced detection. Returns (candidates, stats)."""
    detector = EnhancedHeapOverflowDetector()
    candidates = detector.detect(ir_lines, binary_path, arch_bits)
    return candidates, detector.stats
__all__ = ['EnhancedHeapCandidate', 'EnhancedHeapOverflowDetector',
           'detect_heap_overflow_enhanced']
