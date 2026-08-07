"""

Phase 2 — 堆布局推断: 连续chunk间距建模
Phase 3 — Z3约束证明: SMT可满足性验证
Phase 4 — Strided Interval: 步长区间消除sizeof(T)假溢出

设计决策: 与快速阶段(0-1)分离, 因 Phase 2-4 依赖更重的计算
  (堆布局推断可能需要遍历所有alloc; Z3需要外部求解器)。
"""


from typing import Any, Dict, List, Optional, Tuple

from core.allocator_constraints import AllocSize


# Phase 2: 堆布局推断

def phase_heap_layout(
    candidates: list,
    pseudocode: str = "",
    platform: str = "x86_64",
    **_kw,
) -> Tuple[list, "FilterStage"]:
    """Phase 2: 堆布局推断。建模连续分配的chunk, 判断写入是否跨越chunk边界。"""
    from analysis.unified_fp_filter import FilterStage
    stage = FilterStage(name='heap_layout', input_count=len(candidates))
    kept = []

    try:
        from analysis.heap_layout_oracle import HeapLayoutOracle
        oracle = HeapLayoutOracle(platform)
        region = oracle.infer_region(pseudocode)
    except ImportError:
        stage.remaining_count = len(candidates)
        return candidates, stage

    if not region.chunks:
        stage.remaining_count = len(candidates)
        return candidates, stage

    for c in candidates:
        alloc_site = getattr(c, 'alloc_site', None)
        store = getattr(c, 'overflow_store', None)
        if alloc_site is None or store is None:
            kept.append(c)
            continue

        result_var = getattr(alloc_site, 'result_var', '')
        target = oracle.find_target_chunk(region, result_var)
        if target is None or target.usable_size <= 0:
            kept.append(c)
            continue

        offset = getattr(store, 'offset', 0)
        store_sz = getattr(store, 'store_size', 1)
        is_safe, reason = oracle.is_write_safe(offset, target, region, store_sz)

        if is_safe:
            stage.filter_reasons[reason] = stage.filter_reasons.get(reason, 0) + 1
            continue

        kept.append(c)

    stage.remaining_count = len(kept)
    stage.filtered_count = stage.input_count - len(kept)
    return kept, stage


# Phase 3: Z3 约束证明

def phase_z3_prove(
    candidates: list,
    constraints_map: Optional[Dict[str, List[Any]]] = None,
    platform: str = "x86_64",
    **_kw,
) -> Tuple[list, "FilterStage"]:
    """Phase 3: Z3约束证明。对收集到路径约束的候选做SMT验证。"""
    from analysis.unified_fp_filter import FilterStage
    stage = FilterStage(name='z3_prove', input_count=len(candidates))
    kept = []

    if constraints_map is None:
        constraints_map = {}

    try:
        from analysis.heap_bounds_prover import HeapBoundsProver
        prover = HeapBoundsProver()
    except ImportError:
        stage.remaining_count = len(candidates)
        return candidates, stage

    for c in candidates:
        alloc_site = getattr(c, 'alloc_site', None)
        store = getattr(c, 'overflow_store', None)
        if alloc_site is None or store is None:
            kept.append(c)
            continue

        size_arg = getattr(alloc_site, 'size_arg', 0)
        offset = getattr(store, 'offset', 0)
        store_sz = getattr(store, 'store_size', 1)

        constraints = None
        for _var_key, cons in constraints_map.items():
            constraints = cons
            break

        result = prover.prove_safety(
            alloc_size=size_arg, write_offset=offset,
            write_size=store_sz, path_constraints=constraints,
            alloc_func=getattr(alloc_site, 'alloc_func', 'malloc'),
            platform=platform,
        )

        if result.is_safe:
            reason = f'z3: {result.details[:80]}'
            stage.filter_reasons[reason] = stage.filter_reasons.get(reason, 0) + 1
            continue

        kept.append(c)

    stage.remaining_count = len(kept)
    stage.filtered_count = stage.input_count - len(kept)
    return kept, stage


# Phase 4: Strided Interval 验证

def phase_strided_interval(
    candidates: list,
    ir_lines: Optional[List[str]] = None,
    platform: str = "x86_64",
    **_kw,
) -> Tuple[list, "FilterStage"]:
    """Phase 4: Strided Interval验证。步长区间消除sizeof(T)假溢出。"""
    from analysis.unified_fp_filter import FilterStage
    stage = FilterStage(name='strided_interval', input_count=len(candidates))
    kept = []

    if ir_lines is None:
        ir_lines = []

    try:
        from analysis.strided_interval import StridedInterval
    except ImportError:
        stage.remaining_count = len(candidates)
        return candidates, stage

    for c in candidates:
        alloc_site = getattr(c, 'alloc_site', None)
        store = getattr(c, 'overflow_store', None)
        if alloc_site is None or store is None:
            kept.append(c)
            continue

        size_arg = getattr(alloc_site, 'size_arg', 0)
        stride = _infer_stride_from_ir(ir_lines)
        if stride <= 1:
            kept.append(c)
            continue

        alloc_si = StridedInterval(0, size_arg, stride)
        effective = AllocSize.from_request(size_arg, platform)

        if not alloc_si.may_exceed(effective.effective):
            reason = f'stride: {alloc_si} safe for effective={effective.effective}'
            stage.filter_reasons[reason] = stage.filter_reasons.get(reason, 0) + 1
            continue

        kept.append(c)

    stage.remaining_count = len(kept)
    stage.filtered_count = stage.input_count - len(kept)
    return kept, stage


def _infer_stride_from_ir(ir_lines: List[str]) -> int:
    """从IR中推断访问步长 (sizeof element)。"""
    import re
    sizes = {'int': 4, 'long': 8, 'char': 1, 'short': 2,
             'float': 4, 'double': 8, 'void*': 8, 'void': 1}
    for line in ir_lines:
        m = re.search(r'sizeof\s*\(\s*(\w+(?:\s*\*)?)\s*\)', line, re.IGNORECASE)
        if m:
            type_name = m.group(1).replace('*', '').strip()
            if m.group(1).endswith('*'):
                return 8
            return sizes.get(type_name, 4)
        m = re.search(r'(\d+)\s*\*\s*sizeof', line, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return 1


__all__ = ['phase_heap_layout', 'phase_z3_prove', 'phase_strided_interval']
