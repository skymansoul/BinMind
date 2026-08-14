"""GAPSBV 5阶段堆溢出检测: 区间→约束→循环→分配器→误报过滤, 附加仿射与污点追踪。"""
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
    """带分析来源的堆溢出候选。"""
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
    """五阶段增强堆溢出检测器 — 用法: EnhancedHeapOverflowDetector(platform).detect(ir_lines)。"""
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
        """在IR行上运行全部五个阶段, 返回排序后的候选。"""
        t0 = time.time()
        self.stats = {'s1_allocs': 0, 's1_writes': 0,
                      's2_constraints': 0, 's3_loops': 0,
                      's4_verified': 0, 's5_candidates': 0}
        if binary_path:
            detected = detect_allocator(binary_path)
            # UNKNOWN回退到glibc ptmalloc2 — Linux平台默认分配器
            if detected != AllocatorType.UNKNOWN:
                self._allocator = detected
        # 阶段1: 前向区间传播
        allocs, writes = self._interval_prop.analyze(ir_lines)
        self.stats['s1_allocs'] = len(allocs)
        self.stats['s1_writes'] = len(writes)
        if not allocs or not writes:
            self.stats['elapsed'] = time.time() - t0
            return []
        # 1.5: 清除被取代的分配点 — 同变量的 realloc/malloc 使旧分配点失效
        allocs = self._dedup_alloc_sites(allocs)
        # 阶段2: 约束收集与求精
        constraints = self._constraint_collector.extract_constraints(ir_lines)
        self.stats['s2_constraints'] = len(constraints)
        # 阶段3: 循环检测
        loops = self._loop_inferrer.detect_loops(ir_lines)
        self.stats['s3_loops'] = len(loops)
        # 阶段3.5: 仿射关系分析
        affine = AffineAnalyzer()
        aff_allocs, aff_writes, _ = affine.analyze(ir_lines)
        # 建立 分配变量→大小变量 映射供仿射匹配
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
        # 阶段4与5: 逐一核验分配-写入对
        candidates: List[EnhancedHeapCandidate] = []
        for alloc in allocs:
            refined_alloc = alloc.size_interval
            # 在分配点附近应用约束
            refined_alloc, _ = collect_and_refine(
                ir_lines, alloc.var_name, refined_alloc, alloc.loc)
            for write in writes:
                # 别名检查: 该写入是否指向分配变量
                if write.dst_var != alloc.var_name:
                    # 启发式: 检查 write.dst_var 是否为派生指针
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
                # 别名偏移: buf+offset 写入 → 检查 [offset, offset+size] 与分配大小
                if alias_offset > 0:
                    refined_write = Interval(
                        refined_write.lo + alias_offset,
                        (refined_write.hi + alias_offset
                         if refined_write.hi < 2**63 - 1
                         else 2**63 - 1))
                # 循环上下文: 按循环上界缩放写入
                loop_info = self._loop_inferrer.get_loop_context(write.loc)
                if loop_info and not loop_info.is_dynamic:
                    write_iv, _ = infer_heap_write_bounds(
                        ir_lines, alloc.var_name, write.loc)
                    if not write_iv.is_top:
                        refined_write = write_iv
                # 阶段4: 分配器感知核验
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
                # 仿射覆写: 由 x=k*y+c 关系证明溢出
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
                            break  # 已证明: 停止检查其他写入
                        # False/None: 继续检查其他写入
                # Taint: 攻击者可控→提权, 常量→降权
                prev_conf = confidence
                alloc_sz = aff_alloc_sz.get(alloc.var_name, '')
                write_sz = next((aw['size_var'] for aw in aff_writes
                                 if aw['dst_var'] == write.dst_var), '')
                confidence = taint_adjust_confidence(
                    alloc_sz, write_sz, confidence, taint)
                if confidence != prev_conf:
                    self.stats['taint_adjustments'] += 1
                # 污点判定升级: 两端攻击者可控且无约束 → 真漏洞
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
        # 关系检查: write_size = alloc_size * k (k>1) → 溢出
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
        """返回 (is_alias, offset): 支持 ptr=buf+N, &buf[N], 结构体字段, 直接复制。"""
        # 完全匹配
        if var1 == var2:
            return True, 0
        # 结构体字段访问: base->field 别名 base (偏移保守取0)
        # 例如 c->payload → c 是同一块堆内存的字段写入
        m_field = re.match(rf'^{re.escape(var2)}\s*->\s*(\w[\w.]*)', var1)
        if m_field:
            return True, 0  # 保守: 字段偏移未知时设为0
        # 查找赋值: var1 = var2 [+ offset]
        for i in range(max(0, at_line - 10), at_line):
            line = ir_lines[i]
            # ptr = buf + N (正偏移)
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
            # ptr = buf (直接指针复制, 偏移0)
            if re.search(rf'{re.escape(var1)}\s*=\s*{re.escape(var2)}\s*$', line):
                return True, 0
        return False, 0
    def summary_table(self, candidates: List[EnhancedHeapCandidate]) -> str:
        """每个候选一行的汇总表。"""
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
    """运行增强检测, 返回 (候选, 统计)。"""
    detector = EnhancedHeapOverflowDetector()
    candidates = detector.detect(ir_lines, binary_path, arch_bits)
    return candidates, detector.stats
__all__ = ['EnhancedHeapCandidate', 'EnhancedHeapOverflowDetector',
           'detect_heap_overflow_enhanced']
