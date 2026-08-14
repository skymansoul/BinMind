"""
堆溢出检测管线 — 串联全部模块: 上下文追踪→大小传播→边界检测→误报过滤。
统一入口: 调用方传入IR行, 管线内部经四阶段分发并返回最终候选与统计;
各阶段独立, 模块缺失时跳过该阶段, 保证基础检测结果。
"""

from typing import Optional


def detect_heap_overflows_full(
    ir_lines: list[str],
    decompiled_text: str = '',
    enable_hovf: bool = True,
) -> tuple[list, dict]:
    """完整管线: 上下文追踪+大小传播+边界检测+误报过滤, 返回 (候选, 统计)。
    enable_hovf=False 时跳过 Stage 3.5, 用于消融对照。
    """
    stats = {'stage_context': 0, 'stage_size_prop': 0,
             'stage_detect': 0, 'stage_filter': 0}

    # 阶段0: 上下文追踪 — 获取每个变量的有效分配大小
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

    # 阶段1.2: 源码级强化候选提取 — 8种写入模式补充
    if not candidates and decompiled_text:
        try:
            from core.source_level_candidate_extractor import (
                extract_candidates_from_code,
            )
            src_candidates, _ = extract_candidates_from_code(decompiled_text)
            candidates = src_candidates
            stats['stage_src_extract'] = len(candidates)
        except ImportError:
            pass

    if not candidates:
        # 基础与源码级通道均无候选时, 仍须运行 HOVF 追加通道,
        # 该通道独立检测强类型解引用与带偏移库写入, 可单独产出候选.
        pass
    else:
        # 阶段1.5: 用上下文修正分配大小
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

     # 阶段2: 动态分配的传播
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

    # 阶段2.5: 分配大小污点追踪 — 标注size来源是否为外部输入
    taint_count = 0
    try:
        from core.alloc_size_taint import analyze_alloc_taint, TaintLevel
        code_text = '\n'.join(ir_lines)
        taint_sites = analyze_alloc_taint(code_text)
        for c in candidates:
            for ts in taint_sites:
                if ts.taint_level == TaintLevel.NOT_TAINTED:
                    c.alloc_site._size_taint = 'not_tainted'
                    taint_count += 1
                elif ts.taint_level == TaintLevel.TAINTED:
                    c.alloc_site._size_taint = 'tainted'
                else:
                    c.alloc_site._size_taint = 'indeterminate'
        stats['stage_taint'] = taint_count
    except (ImportError, AttributeError):
        pass

    # 阶段3: 三阶段误报过滤
    try:
        from core.heap_fp_filter_stages import apply_fp_filters
        before = len(candidates)
        candidates = apply_fp_filters(candidates, ir_lines)
        stats['stage_filter'] = before - len(candidates)
    except ImportError:
        pass

    # 阶段3.5: HOVF 追加通道 + 分配器宽松核验 (附加阶段, 不改动既有结果)
    if enable_hovf:
        try:
            from core.hovf_engine import refine_heap_candidates
            from core.hovf_write_extract import extract_hovf_alloc_sites
            alloc_sites = extract_hovf_alloc_sites(ir_lines)
            before = len(candidates)
            candidates, hovf_stats = refine_heap_candidates(
                ir_lines, alloc_sites, candidates, slack_bound='usable')
            stats['stage_hovf'] = before - len(candidates)
            stats['hovf_stats'] = hovf_stats
        except (ImportError, AttributeError):
            pass

    candidates.sort(key=lambda c: -c.confidence)
    return candidates, stats
