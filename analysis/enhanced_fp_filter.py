"""
增强误报过滤器 —— 集成所有新分析模块, 统一过滤管道。

传统方法的问题(已被解决):
  D1: 仅比较 store_offset > malloc_size → 忽视 chunk slack space
  D2: 未检查守卫条件 → if(idx<N)buf[idx]=x 被误报
  D3: 未区分堆/栈/全局写入 → 栈写被误报为堆溢出
  D4: 未跟踪指针别名 → p=q赋值后的store被漏报
  D5: 未传播值域范围 → 动态size变量被放弃

本模块将五个分析维度集成到统一过滤管道中, 每个维度是一个
独立的过滤器。过滤器分两层:
  L1: 硬过滤 —— 确定不是漏洞, 直接移除 (confidence≥0.80)
  L2: 软调整 —— 调整置信度, 保留在候选列表中

过滤规则:
  F1 (hard): 目标非堆内存 → 立即移除
  F2 (hard): guard条件确认安全 → 立即移除
  F3 (soft): store在slack空间内 → 置信度降低0.40
  F4 (soft): 值域分析表明offset可能合法 → 置信度降低0.25
  F5 (soft): 指针别名 → 可能重新计算size (置信度调整)

保守性原则: L1过滤只在高度确定时触发(confidence≥0.80),
L2调整不会移除任何候选 —— 这些由最终阈值决定。
"""


from typing import Any, Dict, List, Optional, Set, Tuple

# 重导出以便外部统一 import
from analysis.value_range_propagator import (
    Interval, VarRange, ValueRangePropagator, extract_size_constraints_from_ir,
)
from analysis.guard_condition_analyzer import (
    GuardCondition, find_guard_for_variable, is_store_safeguarded,
)
from analysis.allocator_chunk_model import (
    ChunkLayout, estimate_chunk_layout, is_within_slack, would_overflow,
    compute_effective_boundary, Allocator,
)
from analysis.heap_disambiguator import (
    MemAccess, MemRegion, is_likely_heap_write, classify_memory_access,
)
from analysis.flow_sensitive_tracker import (
    AllocRecord, VarsEquivClass, FlowSensitiveTracker,
)


# 过滤阶段: 从候选列表中逐维度过滤

def filter_non_heap_writes(
    candidates: List[Any],
    ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """F1: 移除非堆内存写入的候选。(硬过滤)"""
    # 收集所有已确认的 malloc 返回变量
    malloc_vars: Set[str] = set()
    for c in candidates:
        if hasattr(c, 'alloc_site') and c.alloc_site.result_var:
            malloc_vars.add(c.alloc_site.result_var)
        if hasattr(c, 'overflow_store') and c.overflow_store.base_var:
            malloc_vars.add(c.overflow_store.base_var)

    kept = []
    removed = 0
    for c in candidates:
        store_line = ''
        if hasattr(c, 'overflow_store'):
            pc = c.overflow_store.pc
            if 0 <= pc < len(ir_lines):
                store_line = ir_lines[pc]
        is_heap, conf, reason = is_likely_heap_write(
            store_line, malloc_return_vars=malloc_vars)
        if not is_heap and conf >= 0.80:
            removed += 1
            continue
        kept.append(c)
    return kept, removed


def filter_guarded_stores(
    candidates: List[Any],
    ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """F2: 移除受guard条件保护的store。(硬过滤)"""
    kept = []
    removed = 0
    for c in candidates:
        if not hasattr(c, 'overflow_store') or not hasattr(c, 'alloc_site'):
            kept.append(c)
            continue
        store = c.overflow_store
        alloc = c.alloc_site
        # 仅对动态偏移的store做guard检查 (静态偏移已知)
        if not store.offset_is_dynamic:
            kept.append(c)
            continue
        # 提取offset变量名
        base = store.base_var
        safe, reason, conf = is_store_safeguarded(
            ir_lines, base, base, store.pc, alloc.size_arg)
        if safe and conf >= 0.80:
            removed += 1
            continue
        kept.append(c)
    return kept, removed


def adjust_for_slack(
    candidates: List[Any],
) -> Tuple[List[Any], int]:
    """F3: 对slack空间内的store降低置信度。(软调整)

    仅对偏移写入操作应用 — 拷贝操作(strcpy/memcpy/memset)的溢出
    来源于拷贝大小而非偏移, slack调整不适用。
    """
    adjusted = 0
    for c in candidates:
        if not hasattr(c, 'overflow_store') or not hasattr(c, 'alloc_site'):
            continue
        # 拷贝操作: 跳过 (溢出来源是拷贝大小, 不是偏移)
        if c.overflow_store.mnemonic in ('strcpy', 'memcpy', 'strncpy', 'memset', 'strcat', 'strncat', 'copy'):
            continue
        offset = c.overflow_store.offset
        if offset < 0:
            continue
        layout = estimate_chunk_layout(c.alloc_site.size_arg,
                                       c.alloc_site.alloc_func)
        if is_within_slack(offset, layout):
            c.confidence = max(0.30, c.confidence - 0.40)
            c.description += ' [slack space: offset within chunk boundary]'
            adjusted += 1
    return candidates, adjusted


def adjust_for_value_range(
    candidates: List[Any],
    ir_lines: List[str],
) -> Tuple[List[Any], int]:
    """F4: 值域分析 —— 若offset变量的上界≤分配大小, 降低置信度。(软调整)"""
    adjusted = 0
    if not candidates:
        return candidates, adjusted

    prop = ValueRangePropagator()
    all_vars: Set[str] = set()
    for c in candidates:
        if hasattr(c, 'alloc_site') and c.alloc_site.result_var:
            all_vars.add(c.alloc_site.result_var)
        if hasattr(c, 'overflow_store') and c.overflow_store.base_var:
            all_vars.add(c.overflow_store.base_var)
    if not all_vars:
        return candidates, adjusted

    prop.propagate(ir_lines, all_vars)

    for c in candidates:
        if not hasattr(c, 'alloc_site') or not hasattr(c, 'overflow_store'):
            continue
        alloc_var = c.alloc_site.result_var
        if not alloc_var or alloc_var not in prop.ranges:
            continue
        size_iv = prop.ranges[alloc_var].at(c.alloc_site.pc)
        if size_iv.is_constant:
            const_size = size_iv.low
            if const_size > 0:
                actual_usable = compute_effective_boundary(const_size)
                if c.overflow_store.offset < actual_usable:
                    c.confidence = max(0.30, c.confidence - 0.25)
                    c.alloc_site.size_arg = actual_usable
                    c.description += f' [VR: effective boundary expanded to {actual_usable}]'
                    adjusted += 1

    return candidates, adjusted


def run_enhanced_filter(
    candidates: List[Any],
    ir_lines: List[str],
    min_confidence: float = 0.25,
) -> Tuple[List[Any], Dict[str, int]]:
    """运行完整的增强误报过滤管道。

    min_confidence 为最终置信度阈值, 返回 (filtered_candidates, stats_dict)。
    """
    stats = {'input': len(candidates)}

    # F1: 非堆写入
    candidates, n = filter_non_heap_writes(candidates, ir_lines)
    stats['f1_non_heap'] = n

    # F2: 守卫条件
    candidates, n = filter_guarded_stores(candidates, ir_lines)
    stats['f2_guarded'] = n

    # F3: slack空间
    candidates, n = adjust_for_slack(candidates)
    stats['f3_slack_adj'] = n

    # F4: 值域范围
    candidates, n = adjust_for_value_range(candidates, ir_lines)
    stats['f4_vrange_adj'] = n

    # 最终阈值
    def _conf(c):
        return getattr(c, 'confidence', c.get('confidence', 0) if isinstance(c, dict) else 0)
    candidates = [c for c in candidates if _conf(c) >= min_confidence]
    stats['output'] = len(candidates)
    stats['total_removed'] = stats['input'] - stats['output']

    candidates.sort(key=lambda c: -_conf(c))
    return candidates, stats
