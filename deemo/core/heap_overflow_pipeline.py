"""
Heap overflow detection pipeline — chains all modules:
context tracking → size propagation → boundary detection → FP filtering.

Unified entry point for heap overflow detection. Callers pass IR lines;
the pipeline internally dispatches through four stages and returns final
candidates plus pipeline stats.

Each stage is independent. If a module is unavailable (ImportError),
that stage is skipped — guaranteeing basic detection results in the
worst case.
"""

from typing import Optional


def detect_heap_overflows_full(
    ir_lines: list[str],
    decompiled_text: str = '',
) -> tuple[list, dict]:
    """Full pipeline: context tracking + size propagation + boundary detection + FP filtering.

    返回 (candidates, pipeline_stats)
    """
    stats = {'stage_context': 0, 'stage_size_prop': 0,
             'stage_detect': 0, 'stage_filter': 0}

    # Stage 0: context tracking — get effective allocation size per variable
    alloc_context = {}
    try:
        from core.heap_context_tracker import extract_alloc_context, get_effective_alloc_size
        alloc_context = extract_alloc_context(ir_lines)
        stats['stage_context'] = len(alloc_context)
    except ImportError:
        pass

    # 阶段1: 基础边界检测
    candidates = []
    try:
        from core.heap_overflow_detector import detect_heap_overflow
        candidates = detect_heap_overflow(ir_lines, decompiled_text)
        stats['stage_detect'] = len(candidates)
    except ImportError:
        pass

    if not candidates:
        return [], stats

    # Stage 1.5: correct allocation sizes with context
    if alloc_context:
        from core.heap_context_tracker import get_effective_alloc_size
        for c in candidates[:]:
            var = c.alloc_site.result_var
            if var:
                effective = get_effective_alloc_size(
                    var, c.overflow_store.pc, alloc_context)
                if effective > c.alloc_site.size_arg:
                    c.alloc_site.size_arg = effective
                    # 重新检查溢出条件
                    if c.overflow_store.offset < effective:
                        candidates.remove(c)

    # Stage 2: size propagation for dynamic allocations
    dyn_count = 0
    try:
        from core.heap_size_propagator import propagate_size_for_var
        for c in candidates:
            if c.alloc_site.size_is_dynamic or c.alloc_site.size_arg <= 0:
                est = propagate_size_for_var(
                    c.alloc_site.result_var, ir_lines, c.alloc_site.pc)
                if est.lower_bound > 0:
                    c.alloc_site.size_arg = est.lower_bound
                    c.alloc_site.size_is_dynamic = False
                    dyn_count += 1
        stats['stage_size_prop'] = dyn_count
    except ImportError:
        pass

    # 阶段3: 三阶段误报过滤
    try:
        from core.heap_fp_filter_stages import apply_fp_filters
        before = len(candidates)
        candidates = apply_fp_filters(candidates, ir_lines)
        stats['stage_filter'] = before - len(candidates)
    except ImportError:
        pass

    candidates.sort(key=lambda c: -c.confidence)
    return candidates, stats
