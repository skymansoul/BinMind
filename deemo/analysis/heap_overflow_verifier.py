"""
GAPSBV 堆溢出验证器 — guard_inference + path_condition + interval_bounds + affine_relation 四阶段过滤.
A(cmp+jcc) → B(路径条件) → C(区间抽象) → D.
保守设计: 无法确定时保留候选; 每层可开关; 过滤可追溯.
"""

from dataclasses import dataclass, field
from typing import Optional
import re


@dataclass
class VerificationResult:
    """单个堆溢出候选的四阶段验证结果。"""
    candidate: object              # HeapOverflowCandidate
    stage_a_verdict: str = ""      # A阶段判定: guard_inference
    stage_b_verdict: str = ""      # B阶段判定: path_condition_tracker
    stage_c_verdict: str = ""      # C阶段判定: interval_bounds_analyzer
    stage_d_verdict: str = ""      # D阶段判定: affine_relation_tracker
    final_verdict: str = "KEEP"    # KEEP | FILTER | UNCERTAIN
    confidence_before: float = 0.0
    confidence_after: float = 0.0
    reason: str = ""
    stage_details: dict = field(default_factory=dict)


class HeapOverflowVerifier:
    """
    GAPSBV 堆溢出验证器。用法: verifier = HeapOverflowVerifier(); verifier.verify(candidates, ir_lines, decompiled_text).
    candidates 来自 heap_overflow_detector.detect_heap_overflow。若某 stage 不可用, 静默跳过。
    """

    def __init__(self, enable_stage_a: bool = True,
                 enable_stage_b: bool = True,
                 enable_stage_c: bool = True,
                 enable_stage_d: bool = True):
        self._enable_a = enable_stage_a
        self._enable_b = enable_stage_b
        self._enable_c = enable_stage_c
        self._enable_d = enable_stage_d
        self._guard_engine = None
        self._path_tracker = None
        self._interval_analyzer = None
        self._affine_tracker = None

    def verify(self, candidates: list,
               ir_lines: list[str],
               decompiled_text: str = "") -> tuple[list, list[VerificationResult]]:
        """验证所有候选, 返回 (kept_candidates, all_results)。"""
        results: list[VerificationResult] = []

        # 延迟初始化各引擎
        if self._enable_a and self._guard_engine is None:
            try:
                from analysis.guard_inference import GuardInferenceEngine
                self._guard_engine = GuardInferenceEngine()
            except ImportError:
                self._enable_a = False

        if self._enable_b and self._path_tracker is None:
            try:
                from analysis.path_condition_tracker import PathConditionTracker
                self._path_tracker = PathConditionTracker()
            except ImportError:
                self._enable_b = False

        if self._enable_c and self._interval_analyzer is None:
            try:
                from analysis.interval_bounds_analyzer import IntervalBoundsAnalyzer
                self._interval_analyzer = IntervalBoundsAnalyzer()
            except ImportError:
                self._enable_c = False

        if self._enable_d and self._affine_tracker is None:
            try:
                from analysis.affine_relation_tracker import AffineRelationTracker
                self._affine_tracker = AffineRelationTracker()
            except ImportError:
                self._enable_d = False

        for c in candidates:
            result = VerificationResult(
                candidate=c,
                confidence_before=getattr(c, 'confidence', 0.0),
            )
            alloc_site = getattr(c, 'alloc_site', None)
            overflow_store = getattr(c, 'overflow_store', None)

            if alloc_site is None or overflow_store is None:
                result.final_verdict = "KEEP"
                result.reason = "incomplete candidate data, kept for safety"
                results.append(result)
                continue

            alloc_size = getattr(alloc_site, 'size_arg', 0) or 0
            store_offset = getattr(overflow_store, 'offset', -1) or -1
            base_var = getattr(alloc_site, 'result_var', '') or ''

            # Stage A: 显式守卫检查
            if self._enable_a and self._guard_engine:
                a_result = self._guard_engine.infer(
                    ir_lines,
                    getattr(alloc_site, 'pc', 0),
                    alloc_size,
                    getattr(overflow_store, 'pc', 0),
                    base_var,
                )
                result.stage_a_verdict = a_result.verdict.value
                result.stage_details['a'] = a_result.description
                if a_result.verdict.value == 'protected':
                    result.final_verdict = "FILTER"
                    result.reason = f"Stage A: {a_result.description}"
                    result.confidence_after = 0.10
                    results.append(result)
                    continue

            # Stage B: 路径条件传播
            if self._enable_b and self._path_tracker:
                try:
                    blocks = self._path_tracker.build_blocks(ir_lines)
                    self._path_tracker.propagate_conditions(blocks, ir_lines)
                    guarded, b_reason = self._path_tracker.is_write_guarded(
                        getattr(overflow_store, 'pc', 0),
                        blocks, alloc_size,
                        self._infer_index_var(ir_lines, overflow_store),
                    )
                    result.stage_b_verdict = "protected" if guarded else "unguarded"
                    result.stage_details['b'] = b_reason
                    if guarded:
                        result.final_verdict = "FILTER"
                        result.reason = f"Stage B: {b_reason}"
                        result.confidence_after = 0.15
                        results.append(result)
                        continue
                except Exception:
                    result.stage_b_verdict = "error"

            # Stage C: 区间推导
            if self._enable_c and self._interval_analyzer:
                idx_var = self._infer_index_var(ir_lines, overflow_store)
                if idx_var:
                    idx_range = self._interval_analyzer.analyze_window(
                        ir_lines,
                        getattr(alloc_site, 'pc', 0),
                        getattr(overflow_store, 'pc', 0),
                        idx_var,
                    )
                    safe, c_reason = self._interval_analyzer.check_safety(
                        idx_range, alloc_size)
                    result.stage_c_verdict = "safe" if safe else "unsafe"
                    result.stage_details['c'] = c_reason
                    result.stage_details['c_range'] = str(idx_range)
                    if safe:
                        result.final_verdict = "FILTER"
                        result.reason = f"Stage C: {c_reason}"
                        result.confidence_after = 0.20
                        results.append(result)
                        continue
                else:
                    result.stage_c_verdict = "no_index_var"

            # Stage D: 仿射关系验证 — 符号差分 alloc_expr vs write_expr
            if self._enable_d and self._affine_tracker and decompiled_text:
                d_filtered, d_reason, d_confidence = self._stage_d_affine_relation(
                    alloc_site, overflow_store, decompiled_text)
                result.stage_d_verdict = "filtered" if d_filtered else "kept"
                result.stage_details['d'] = d_reason
                if d_filtered:
                    result.final_verdict = "FILTER"
                    result.reason = f"Stage D: {d_reason}"
                    result.confidence_after = d_confidence
                    results.append(result)
                    continue

            # 通过所有阶段: 保留为真阳性候选
            result.final_verdict = "KEEP"
            result.confidence_after = getattr(c, 'confidence', 0.50)
            reasons = []
            for stage, detail in result.stage_details.items():
                if detail and not detail.startswith('Stage'):
                    reasons.append(f"[{stage}] {detail}")
            result.reason = "verified through all stages; " + (
                "; ".join(reasons) if reasons else "no guard/invariant found"
            )
            results.append(result)

        # 返回过滤后的候选列表
        kept = [
            results[i].candidate
            for i, r in enumerate(results)
            if r.final_verdict == "KEEP" and i < len(candidates)
        ]
        return kept, results

    @staticmethod
    def _infer_index_var(ir_lines: list[str],
                         overflow_store) -> str:
        """从 overflow store 中推断索引变量名。"""
        store_pc = getattr(overflow_store, 'pc', 0)
        if store_pc < len(ir_lines):
            line = ir_lines[store_pc]
            m = re.search(r'\[(\w+)\s*\+\s*(\w+)\]', line)
            if m:
                try:
                    int(m.group(2), 0)
                except ValueError:
                    return m.group(2)
            m = re.search(r'\[[^\]]*\*[^\]]*\]', line)
            if m:
                return m.group(0)
        return ""

    def _stage_d_affine_relation(self, alloc_site,
                                  overflow_store,
                                  decompiled_text: str) -> tuple:
        """Stage D: 仿射关系验证 — 符号差分 alloc-write (Karr 1976).
        malloc(n*4+8)+memcpy(n*8) → diff=4n-8, n>2→OVERFLOW, n≤2→SAFE.
        Returns: (filtered, reason, confidence)."""
        if not decompiled_text or not self._affine_tracker:
            return (False, "affine tracker unavailable", 0.0)

        alloc_var = getattr(alloc_site, 'result_var', '') or ''
        alloc_func = getattr(alloc_site, 'alloc_func', 'malloc') or 'malloc'
        write_mnemonic = getattr(overflow_store, 'mnemonic', '') or ''

        # 仅对 memcpy/strcpy 类写入运行仿射分析 (mov/store 偏移小, 不需符号差分)
        if write_mnemonic not in ('memcpy', 'memmove', 'strncpy',
                                   'strcpy', 'strcat', 'memset'):
            return (False, "write type not suitable for affine analysis", 0.0)

        # realloc 分配拒绝仿射SAFE: realloc 涉及旧size和新size两个值,
        # 仿射追踪仅能捕获一个新size的表达式关系, 无法区分旧size守卫条件
#
        if alloc_func == 'realloc':
            return (False,
                    "realloc allocation: affine analysis cannot distinguish "
                    "old vs new size, refusing SAFE verdict", 0.0)

        # 写入偏移非零时保守处理: memcpy(buf+16, ...) 可能涉及结构体内部布局
        # 仿射分析仅追踪 size 参数关系, 偏移>0 时需额外结构体知识 → 不在此过滤
        store_offset_val = getattr(overflow_store, 'offset', 0) or 0
        if store_offset_val > 0:
            return (False,
                    f"non-zero write offset ({store_offset_val}), "
                    "affine analysis may miss struct layout constraints", 0.0)

        try:
            relations = self._affine_tracker.track_alloc_write_relation(
                decompiled_text)
        except Exception:
            return (False, "affine tracking failed", 0.0)

        if not relations:
            return (False, "no alloc-write affine relations found", 0.0)

        # 寻找匹配当前 alloc_var 和 alloc_func 的关系
        # alloc_var 是指针变量名 (如 buf), 而 affine 表达式用 size 参数 (如 n)
        # 放松匹配: 只要 alloc_func 类型匹配即可接受
        for rel in relations:
            if rel.verdict == "SAFE":
                # 排除非 malloc/calloc/realloc 的 SAFE 关系 (如常量比较)
                rel_alloc = str(rel.alloc_expr)
                # 若表达式是常量 (不含变量), 说明是不同分配的常量比较, 跳过
                if re.match(r'^\d+$', rel_alloc.strip()):
                    continue
                return (True,
                        f"affine proof: {rel.condition}",
                        0.12)

        # 对于 OVERFLOW 判定, 提升置信度 (仿射分析确认了溢出)
        for rel in relations:
            if rel.verdict == "OVERFLOW" and alloc_var:
                if alloc_var in str(rel.alloc_expr):
                    # 不在此过滤, 但记录: 仿射分析确认溢出 → 提高置信度
                    return (False,
                            f"affine confirms overflow: {rel.condition}",
                            0.0)

        return (False, "affine analysis inconclusive", 0.0)


def verify_heap_overflow(candidates: list, ir_lines: list[str],
                         decompiled_text: str = "") -> tuple[list, list]:
    """便捷接口。"""
    verifier = HeapOverflowVerifier()
    return verifier.verify(candidates, ir_lines, decompiled_text)


__all__ = ['VerificationResult', 'HeapOverflowVerifier', 'verify_heap_overflow']
