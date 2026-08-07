"""FP过滤阶段实现 — 七阶段级联, 每阶段为独立函数.

S1: 分配器语义 — 过滤用户请求范围内的写入
S2: 守卫感知 — idx < N → 受保护store
S3: 上游size约束 — malloc前size≤MAX
S4: 证明义务 — 双向约束传播
S5: Slack空间 — offset在chunk尾部填充
S6: 值域传播 — 区间抽象解释
S7: 非堆写入过滤
"""


from typing import Any, List, Tuple


# 辅助: 从 integrator 实例获取候选字段


def _get_alloc_size(integrator, c) -> int:
    return integrator._FPReductionIntegrator__get_alloc_size(c)


# S1: 分配器语义

def stage1_allocator_semantics(integrator, candidates: List[Any]) -> List[Any]:
    """S1: 仅过滤用户请求范围内的写入.

    不自动过滤对齐填充内的写入 (可能溢出到chunk header).
    对齐填充的软调整由 S5 (SlackSpace) 负责.

    安全约束: 仅当偏移已知 (静态) 时才过滤.
    动态偏移 (如 buf[user_idx]) 保留给后续阶段.
    """
    kept = []
    for c in candidates:
        alloc_sz = integrator._get_alloc_size(c)
        write_off = integrator._get_write_offset(c)
        write_sz = integrator._get_write_size(c)

        if alloc_sz > 0 and write_off >= 0 and write_sz > 0:
            # 动态偏移: 不确定实际写入位置 → 保留 (保守)
            is_dynamic = False
            if hasattr(c, 'overflow_store'):
                is_dynamic = getattr(c.overflow_store, 'offset_is_dynamic', False)
            elif isinstance(c, dict):
                is_dynamic = c.get('offset_is_dynamic', False)

            if not is_dynamic and write_off + write_sz <= alloc_sz:
                integrator._add_note(c, 'S1: write within requested alloc')
                continue
        kept.append(c)
    return kept


# S2: 守卫感知写入

def stage2_guard_aware(
    integrator, candidates: List[Any], ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """S2: 存在 idx < alloc_size 守卫 → 过滤."""
    try:
        from analysis.guard_condition_analyzer import is_store_safeguarded
    except ImportError:
        return candidates, 0

    kept = []
    removed = 0
    for c in candidates:
        store_pc = integrator._get_store_pc(c)
        base_var = integrator._get_base_var(c)
        alloc_sz = integrator._get_alloc_size(c)
        offset = integrator._get_write_offset(c)

        if offset >= 0 or alloc_sz <= 0 or store_pc < 0:
            kept.append(c)
            continue

        safe, _, conf = is_store_safeguarded(
            ir_lines, base_var, base_var, store_pc, alloc_sz)
        if safe and conf >= 0.80:
            removed += 1
            continue
        kept.append(c)
    return kept, removed


# S3: 上游size约束

def stage3_size_constraints(
    integrator, candidates: List[Any], ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """S3: malloc前size≤MAX → 降低置信度."""
    try:
        from analysis.size_constraint_collector import SizeConstraintCollector
    except ImportError:
        return candidates, 0

    collector = SizeConstraintCollector()
    adjusted = 0
    for c in candidates:
        alloc_sz = integrator._get_alloc_size(c)
        if alloc_sz > 0:
            continue
        alloc_var = integrator._get_alloc_var(c)
        if not alloc_var:
            continue
        size_var = integrator._get_size_var(c)
        if not size_var or not size_var.isidentifier():
            continue
        alloc_pc = getattr(
            getattr(c, 'alloc_site', None), 'pc', len(ir_lines) // 2)
        summary = collector.collect_for_alloc(ir_lines, alloc_pc, size_var)
        if summary.is_proved_bounded and summary.hi > 0:
            write_sz = integrator._get_write_size(c)
            write_mnemonic = getattr(
                getattr(c, 'overflow_store', None), 'mnemonic', '')
            if write_sz > 0 and write_sz <= summary.hi:
                integrator._adjust_confidence(c, -0.50)
                integrator._add_note(
                    c, f'S3: {size_var}≤{summary.hi}, write={write_sz}≤{summary.hi}')
                adjusted += 1
            elif write_sz <= 0 and write_mnemonic in (
                    'memcpy', 'memset', 'strncpy', 'copy', 'call', ''):
                integrator._adjust_confidence(c, -0.40)
                integrator._add_note(
                    c, f'S3: {size_var}≤{summary.hi}, shared size var → safe')
                adjusted += 1
    return candidates, adjusted


# S4: 证明义务引擎

def stage4_proof_obligations(
    integrator, candidates: List[Any], ir_lines: List[str],
) -> Tuple[List[Any], int, int]:
    """S4: 双向约束传播 — 证明(alloc,write)对安全."""
    try:
        from analysis.heap_proof_obligation import HeapProofEngine
    except ImportError:
        return candidates, 0, 0

    engine = HeapProofEngine()
    engine.collect_constraints(ir_lines)
    hard_filtered = 0
    soft_adjusted = 0

    for c in candidates:
        alloc_sz = integrator._get_alloc_size(c)
        write_off = integrator._get_write_offset(c)
        write_sz = integrator._get_write_size(c)
        offset_var = integrator._get_offset_var(c)
        size_var = integrator._get_size_var(c)
        alias_off = integrator._get_alias_offset(c)

        obl = engine.prove_obligation(
            alloc_sz, write_off, write_sz,
            offset_var=offset_var, size_var=size_var,
            alias_offset=alias_off,
        )

        if obl.verdict.value == 'proved_safe':
            integrator._adjust_confidence(c, -0.60)
            integrator._add_note(c, f'S4: {obl.proof_detail}')
            hard_filtered += 1
        elif obl.verdict.value == 'proved_overflow':
            integrator._adjust_confidence(c, +0.15)
            integrator._add_note(c, f'S4: {obl.proof_detail}')

    return candidates, hard_filtered, soft_adjusted


# S5: Slack空间

def stage5_slack_space(
    integrator, candidates: List[Any],
) -> Tuple[List[Any], int]:
    """S5: offset在chunk尾部填充 (alignment padding) 内 → 软降级."""
    adjusted = 0
    for c in candidates:
        alloc_sz = integrator._get_alloc_size(c)
        write_off = integrator._get_write_offset(c)
        if alloc_sz <= 0 or write_off < 0:
            continue
        mnemonic = getattr(getattr(c, 'overflow_store', None), 'mnemonic', '')
        if mnemonic in ('strcpy', 'memcpy', 'strncpy', 'memset', 'strcat', 'copy'):
            continue
        chunk = max(32, ((alloc_sz + 15) // 16) * 16)
        if alloc_sz < write_off <= chunk:
            integrator._adjust_confidence(c, -0.40)
            integrator._add_note(c, 'S5: offset within chunk slack')
            adjusted += 1
    return candidates, adjusted


# S6: 值域传播

def stage6_value_range(
    integrator, candidates: List[Any], ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """S6: 区间抽象解释 — 传播变量取值范围."""
    try:
        from analysis.value_range_propagator import ValueRangePropagator
    except ImportError:
        return candidates, 0

    prop = ValueRangePropagator()
    adjusted = 0

    track_vars = set()
    for c in candidates:
        av = integrator._get_alloc_var(c)
        ov = integrator._get_offset_var(c)
        if av:
            track_vars.add(av)
        if ov:
            track_vars.add(ov)

    if not track_vars:
        return candidates, adjusted

    prop.propagate(ir_lines, track_vars)

    for c in candidates:
        alloc_var = integrator._get_alloc_var(c)
        if not alloc_var or alloc_var not in prop.ranges:
            continue
        iv = prop.ranges[alloc_var].at(
            getattr(getattr(c, 'alloc_site', None), 'pc', 0))
        if iv.is_constant and iv.low > 0:
            chunk = max(32, ((iv.low + 15) // 16) * 16)
            if integrator._get_write_offset(c) < chunk:
                integrator._adjust_confidence(c, -0.25)
                integrator._add_note(c, f'S6: effective boundary={chunk}')
                adjusted += 1

    return candidates, adjusted


# S7: 非堆写入过滤

def stage7_non_heap(
    integrator, candidates: List[Any], ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """S7: 栈/全局变量写入硬过滤.

    两阶段:
      A. 快速: store.base_var 不在任何alloc.result_var中
      B. 精确: heap_disambiguator 检查
    """
    kept = []
    removed = 0

    malloc_vars = set()
    for c in candidates:
        if hasattr(c, 'alloc_site') and c.alloc_site.result_var:
            malloc_vars.add(c.alloc_site.result_var)
        elif isinstance(c, dict) and c.get('alloc_var'):
            malloc_vars.add(c['alloc_var'])

    for c in candidates:
        base_var = integrator._get_base_var(c)
        if base_var and malloc_vars and base_var not in malloc_vars:
            removed += 1
            integrator._add_note(c, 'S7: base_var not in alloc results')
            continue

        store_pc = integrator._get_store_pc(c)
        if 0 <= store_pc < len(ir_lines):
            try:
                from analysis.heap_disambiguator import is_likely_heap_write
                store_line = ir_lines[store_pc]
                is_heap, conf, _ = is_likely_heap_write(
                    store_line, malloc_return_vars=malloc_vars)
                if not is_heap and conf >= 0.80:
                    removed += 1
                    continue
            except ImportError:
                pass
        kept.append(c)
    return kept, removed
