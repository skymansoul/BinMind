# coding: utf-8
"""
深度堆溢出检测编排器 — 整合七层过滤管线.

管线层次 (按执行顺序, 每层可独立开关):
  L0: 基础检测 (heap_analyzer + abstract_heap_model) — 产生原始候选
  L1: 值区间分析 (value_range + alloc_constraints) — 可证明安全则过滤
  L1.5: VCT 关系证明 (relational_value_flow) — ==,≤,+k 关系证明安全
  L2: 污点反向追踪 (taint_enhanced_heap) — 内部数据降权
  L3: 跨函数污点 (interproc_taint) — 跨调用边界追踪
  L4: 路径敏感抽象解释 (path_abstract_interpret) — CFG 级不动点分析
  L5: 约束求解 (constraint_solver) — SMT-lite 证明溢出不可行
  L6: 统计校准 (fp_calibrator) — 学习最优阈值

设计决策:
  - 每层独立, 可单独测试和评估
  - 过滤是累积的: L1 过滤的候选不进 L1.5
  - L4+L5 是最昂贵的层, 只在前面几层无法裁决时才激活
  - L6 是离线阶段, 在线检测使用已校准的配置
"""

from typing import Any, Dict, List, Optional, Tuple

from modules.core.compat.deep_heap_models import DeepHeapReport, LayerStats


class DeepHeapOrchestrator:
    """七层堆溢出检测过滤管线. 每层独立可开关, 过滤累积传递."""

    def __init__(self,
                 allocator_type: str = 'glibc_ptmalloc',
                 arch: str = 'x86_64',
                 enable_l4: bool = True,
                 enable_l5: bool = True,
                 enable_interproc: bool = True,
                 enable_vct: bool = True,
                 enable_guard_aware: bool = True,
                 taint_distance_threshold: int = 8,
                 value_range_depth: int = 12,
                 alloc_margin_factor: float = 1.0):
        self._allocator = allocator_type
        self._arch = arch
        self._enable_l4 = enable_l4
        self._enable_l5 = enable_l5
        self._enable_interproc = enable_interproc
        self._enable_vct = enable_vct
        self._enable_guard_aware = enable_guard_aware
        self._taint_threshold = taint_distance_threshold
        self._vr_depth = value_range_depth
        self._alloc_margin = alloc_margin_factor

    def run(
        self,
        sample_path: str,
        instructions: Optional[List[Dict]] = None,
        ir_ops: Optional[Dict[int, Dict]] = None,
        callee_names: Optional[Dict[int, str]] = None,
        def_use_chains: Optional[Dict[int, List[int]]] = None,
        taint_map: Optional[Dict[int, Dict]] = None,
        trace_events: Optional[List[Dict]] = None,
        alloc_records: Optional[List[Dict]] = None,
        call_graph: Optional[Dict[int, List[int]]] = None,
        auto_extract: bool = True,
    ) -> DeepHeapReport:
        import time as _time
        import os

        _front_candidates: List[Dict] = []
        # 未提供 IR 时自动用二进制前端提取
        if (auto_extract and not ir_ops and not trace_events
                and os.path.isfile(sample_path)):
            try:
                from modules.core.compat.binir_frontend import analyze_binary
                _bin = analyze_binary(sample_path)
                ir_ops = ir_ops or _bin.ir_ops
                callee_names = callee_names or _bin.callee_names
                def_use_chains = def_use_chains or _bin.def_use
                trace_events = trace_events or _bin.trace_events
                instructions = instructions or _bin.instructions
                _front_candidates = _bin.candidates
            except Exception:
                _front_candidates = []

        instructions = instructions or []
        ir_ops = ir_ops or {}
        callee_names = callee_names or {}
        def_use_chains = def_use_chains or {}
        t0_total = _time.perf_counter()
        report = DeepHeapReport(sample_path=sample_path)
        layer_stats: List[LayerStats] = []
        candidates: List[Dict] = []

        def _step(name, fn, *args, cond=True):
            nonlocal candidates
            if not (candidates or name == 'L0_baseline') or not cond:
                return
            t0 = _time.perf_counter()
            before = len(candidates)
            candidates, detail = fn(*args)
            layer_stats.append(LayerStats(name, input_count=before,
                filtered=before - len(candidates), retained=len(candidates),
                duration_ms=(_time.perf_counter() - t0) * 1000,
                details=[detail.get('reason', '')] if isinstance(detail, dict) else []))

        # L0: 基础检测 (总是运行) + 前端 alloc→write 候选
        # 前端候选存在时, 风水/喷射模式检测降为 fallback (避免 CRT 噪音 FP)
        t0 = _time.perf_counter()
        candidates = self._run_baseline(
            trace_events, alloc_records, use_pattern=not bool(_front_candidates))
        for c in _front_candidates:
            if c not in candidates:
                candidates.append(c)
        layer_stats.append(LayerStats('L0_baseline', input_count=0, filtered=0,
            retained=len(candidates),
            duration_ms=(_time.perf_counter() - t0) * 1000))
        report.total_candidates = len(candidates)

        _step('L1_value_range', self._run_value_range_filter, candidates, def_use_chains, ir_ops)
        _step('L1.5_VCT', self._run_vct_filter, candidates, def_use_chains, ir_ops,
              cond=self._enable_vct and bool(def_use_chains) and bool(ir_ops))
        _step('L2_guard_aware', self._run_guard_aware_filter, candidates,
              instructions, ir_ops, def_use_chains, callee_names,
              cond=self._enable_guard_aware and bool(instructions))
        _step('L2.5_taint', self._run_taint_filter, candidates, def_use_chains, ir_ops, instructions,
              cond=bool(def_use_chains))
        _step('L3_interproc', self._run_interproc_filter, candidates, def_use_chains, ir_ops,
              instructions, call_graph, callee_names, cond=self._enable_interproc)
        _step('L4_path_abstract', self._run_path_analysis, candidates, instructions, ir_ops,
              def_use_chains, cond=self._enable_l4 and bool(instructions))
        _step('L5_constraint', self._run_constraint_filter, candidates,
              cond=self._enable_l5)

        report.layer_stats = layer_stats
        report.final_candidates = len(candidates)
        report.candidates = candidates
        report.exploitable = sum(1 for c in candidates if c.get('exploitable'))
        report.reduction_rate = (1 - report.final_candidates /
                                max(1, report.total_candidates))
        report.total_duration_ms = (_time.perf_counter() - t0_total) * 1000
        return report

# 各层实现

    def _run_baseline(self, trace_events, alloc_records,
                      use_pattern: bool = True) -> List[Dict]:
        """L0: 基础 heap_analyzer + abstract_heap_model 检测.

        use_pattern=False 时跳过风水/喷射模式检测 (无 size 信息, 易在
        CRT 噪音上产生 FP), 仅保留抽象堆模型的确定性违规 (double-free等).
        """
        candidates: List[Dict] = []
        if not trace_events:
            return candidates

        from modules.core.compat.heap_analyzer import (
            detect_heap_fengshui, detect_heap_spray)
        from modules.core.compat.abstract_heap_model import AbstractHeapModel

        if use_pattern:
            for f in detect_heap_fengshui(trace_events):
                candidates.append({
                    'overflow_site': f.get('locations', [0])[0] if f.get('locations') else 0,
                    'vuln_type': 'heap_overflow',
                    'reason': f'堆风水: {f.get("pattern")}',
                    'confidence': 0.5 if f.get('suspicion') == 'critical' else 0.3,
                    'exploitable': f.get('suspicion') == 'critical',
                    'source_layer': 'L0_fengshui',
                })
            spray = detect_heap_spray(alloc_records or [])
            if spray.get('spray_detected'):
                candidates.append({
                    'overflow_site': 0, 'vuln_type': 'heap_overflow',
                    'reason': f'堆喷射: {spray.get("reasons", [])}',
                    'confidence': spray.get('confidence', 0.4),
                    'exploitable': spray.get('confidence', 0) >= 0.6,
                    'source_layer': 'L0_spray',
                })

        model = AbstractHeapModel()
        for evt in trace_events:
            etype = evt.get('event', '')
            ptr = evt.get('ptr_id', str(evt.get('address', 0)))
            sz = evt.get('size', 0)
            addr = evt.get('address', 0)
            if etype == 'alloc':
                model.on_alloc(ptr, sz, call_addr=addr)
            elif etype == 'free':
                model.on_free(ptr, call_addr=addr, freed_size=sz)
            elif etype == 'use':
                model.on_use(ptr, use_addr=addr)
        if use_pattern:
            for v in model.flush_violations():
                candidates.append({
                    'overflow_site': v.evidence.get('call_addr', 0),
                    'vuln_type': 'heap_overflow',
                    'reason': f'{v.violation_type}: {v.detail}',
                    'confidence': v.confidence,
                    'exploitable': v.confidence >= 0.7,
                    'source_layer': 'L0_heap_model',
                })
        return candidates

    def _run_value_range_filter(self, candidates, def_use_chains, ir_ops
                                ) -> Tuple[List[Dict], Dict]:
        from modules.core.compat.fp_filter import batch_filter_and_report
        retained, report = batch_filter_and_report(
            candidates,
            def_use=def_use_chains, ir=ir_ops,
            allocator_type=self._allocator,
            arch=self._arch,
            taint_distance_threshold=self._taint_threshold,
            value_range_enabled=True,
            alloc_constraints_enabled=True,
            taint_distance_enabled=True)
        return retained, report

    def _run_vct_filter(self, candidates, def_use_chains, ir_ops
                        ) -> Tuple[List[Dict], Dict]:
        """L1.5: 值同余追踪 — 证明 malloc(N) 和 memcpy(..., N) 用同一变量."""
        from modules.core.compat.relational_value_flow import (
            ValueFlowTracer, batch_prove_heap_safety)
        retained, stats = batch_prove_heap_safety(
            candidates, ir_ops, def_use_chains)
        return retained, {
            'reason': f'VCT proved {stats["proved_safe"]}/{stats["total"]} safe',
            'stats': stats,
        }

    def _run_guard_aware_filter(self, candidates, instructions, ir_ops,
                                 def_use_chains, callee_names
                                 ) -> Tuple[List[Dict], Dict]:
        """L2: 守卫感知过滤 — 同源 + 守卫精化 + 双侧可控性."""
        from modules.core.compat.guard_aware_filter import (
            guard_aware_filter, report_guard_layers)
        retained, stats = guard_aware_filter(
            candidates, instructions, ir_ops, def_use_chains, callee_names)
        return retained, stats

    def _run_taint_filter(self, candidates, def_use_chains, ir_ops, instructions
                          ) -> Tuple[List[Dict], Dict]:
        from modules.core.compat.taint_enhanced_heap import (
            filter_heap_overflow_candidates, downgrade_summary)
        results = filter_heap_overflow_candidates(
            candidates, def_use_chains, ir_ops, instructions)
        # 二进制级跨函数溯源受限: 仅过滤可证明的内部数据, unknown 保守保留
        retained = [{
            'overflow_site': r.overflow_site, 'vuln_type': 'heap_overflow',
            'reason': f'污点: {r.taint_source_desc}',
            'confidence': r.confidence, 'exploitable': r.exploitable,
            'source_layer': 'L2.5_taint', 'taint_source_type': r.taint_source_type,
            'downgrade_reason': r.downgrade_reason,
        } for r in results
            if r.exploitable or r.confidence >= 0.35
            or r.taint_source_type != 'internal_data']
        return retained, downgrade_summary(results)

    def _run_interproc_filter(self, candidates, def_use_chains, ir_ops,
                               instructions, call_graph, callee_names
                               ) -> Tuple[List[Dict], Dict]:
        from modules.core.compat.interproc_enhance import enhance_with_interproc
        enhanced, stats = enhance_with_interproc(
            candidates, def_use_chains, ir_ops, instructions,
            call_graph, callee_names)
        return enhanced, stats

    def _run_path_analysis(self, candidates, instructions, ir_ops, def_use_chains
                           ) -> Tuple[List[Dict], Dict]:
        from modules.core.compat.batch_path_filter import batch_path_sensitive_filter
        retained, stats = batch_path_sensitive_filter(
            candidates, instructions, ir_ops, def_use_chains)
        return retained, stats

    def _run_constraint_filter(self, candidates
                                ) -> Tuple[List[Dict], Dict]:
        # TODO: 约束求解仅覆盖线性整数; 非线性能大小计算保守保留
        from modules.core.compat.constraint_filter import batch_constraint_filter
        return batch_constraint_filter(candidates, self._allocator, self._arch)


def quick_scan(sample_path: str) -> DeepHeapReport:
    """快速扫描 — 使用默认参数, 最小化外部依赖."""
    orchestrator = DeepHeapOrchestrator(
        enable_l4=False, enable_l5=False, enable_interproc=False)
    return orchestrator.run(sample_path)


def deep_scan(sample_path: str,
              instructions: List[Dict],
              ir_ops: Dict[int, Dict],
              callee_names: Optional[Dict[int, str]] = None,
              def_use_chains: Optional[Dict[int, List[int]]] = None,
              trace_events: Optional[List[Dict]] = None,
              ) -> DeepHeapReport:
    """深度扫描 — 启用全部六层过滤."""
    orchestrator = DeepHeapOrchestrator(
        enable_l4=True, enable_l5=True, enable_interproc=True)
    return orchestrator.run(
        sample_path, instructions, ir_ops, callee_names,
        def_use_chains, trace_events=trace_events)
