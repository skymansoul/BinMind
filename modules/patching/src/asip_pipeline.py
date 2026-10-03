"""
ASIP统一管线桥接 — 将间接约束传播+受提示拓宽+值流精确配对
集成到现有堆溢出检测流程.

集成策略:
  Phase 1 (配对精确化): 替代heap_dataflow的80行窗口兜底
    → asip_vflow_pair.precise_alloc_write_related
  Phase 2 (间接guard补充): 补充heap_guard_collector遗漏的约束
    → asip_indirect_prop.resolve_indirect_guards
  Phase 3 (受提示拓宽): 约束求解时用hint限制widen
    → asip_hinted_widen.widen_with_hints

与现有管线的关系:
  不修改任何原有文件, 仅作为后处理增强层.
  原有管线输出候选 → ASIP对每个候选执行三阶段过滤:
    1. 精确配对验证 → 无关对直接过滤
    2. 间接guard补充 → 收窄区间 → 重新求解
    3. 受提示拓宽 → 防止区间过早发散

设计决策: ASIP是"正交叠加", 不改变原有管线的任何判定路径.
当ASIP判定SAFE时覆盖原有VULN, 当ASIP无法判定时保留原有结果.
"""
from __future__ import annotations

import re
from typing import Dict, List, Optional, Tuple

from modules.patching.src.asip_indirect_prop import resolve_indirect_guards
from modules.patching.src.asip_vflow_pair import precise_alloc_write_related
from modules.patching.src.asip_hinted_widen import (
    WideningHint, extract_hints_from_guards, extract_hints_from_text,
    widen_with_hints,
)


def asip_filter_pairing(
    asm_lines: List[str],
    candidates: List,
    func_bounds: Dict[int, str],
    alloc_slots: Dict[int, str],
) -> List:
    """Phase 1: 精确配对过滤.

    对每个候选, 验证其alloc-write对是否真正关联.
    无关对直接过滤.
    """
    kept = []
    for c in candidates:
        alloc_line = _get_alloc_line(c)
        write_line = _get_write_line(c)
        alloc_slot = alloc_slots.get(alloc_line, '')

        related, reason = precise_alloc_write_related(
            asm_lines, alloc_line, write_line, func_bounds, alloc_slot)

        if related:
            kept.append(c)
    return kept


def asip_enrich_guards(
    asm_lines: List[str],
    candidates: List,
    target_reg: str,
    trace_range: Tuple[int, int],
) -> List:
    """Phase 2: 间接guard补充.

    对每个候选, 补充被heap_guard_collector遗漏的间接约束.
    返回增强后的候选列表 (附带额外guard条件).
    """
    start, end = trace_range
    indirect = resolve_indirect_guards(
        asm_lines, target_reg, start, end)

    if not indirect:
        return candidates

    # 将间接guard转化为区间约束, 附加到候选
    for c in candidates:
        extra_guards = _indirect_to_guard_conditions(indirect)
        if hasattr(c, 'extra_guards'):
            c.extra_guards.extend(extra_guards)
        else:
            c.extra_guards = extra_guards
    return candidates


def asip_widen_refine(
    source: str,
    var_bounds: Dict[str, Tuple[Optional[int], Optional[int]]],
    guards: List,
    target_vars: List[str],
    max_iter: int = 5,
) -> Dict[str, Tuple[Optional[int], Optional[int]]]:
    """Phase 3: 受提示拓宽收窄.

    对区间域的变量边界执行受提示延迟拓宽,
    利用路径guard条件限制widen发散方向.

    返回收窄后的变量边界.
    """
    hints = extract_hints_from_guards(guards, target_vars)
    if source:
        hints.extend(extract_hints_from_text(source, target_vars))

    if not hints:
        return var_bounds

    refined = {}
    for var, (lo, hi) in var_bounds.items():
        var_hints = [h for h in hints if h.var == var]
        if not var_hints:
            refined[var] = (lo, hi)
            continue

        # 对有hint的变量: 若边界已发散到+∞, 用hint收窄
        new_lo, new_hi = lo, hi
        for h in var_hints:
            if hi is None and h.upper_bound is not None:
                new_hi = h.upper_bound
            if lo is None and h.lower_bound is not None:
                new_lo = h.lower_bound
        refined[var] = (new_lo, new_hi)

    return refined


def _get_alloc_line(candidate) -> int:
    """从候选对象提取alloc行号."""
    if hasattr(candidate, 'alloc_site') and hasattr(candidate.alloc_site, 'pc'):
        return candidate.alloc_site.pc
    return -1


def _get_write_line(candidate) -> int:
    """从候选对象提取write行号."""
    if hasattr(candidate, 'overflow_store') and hasattr(candidate.overflow_store, 'pc'):
        return candidate.overflow_store.pc
    return -1


def _indirect_to_guard_conditions(indirect_guards: List) -> List:
    """将IndirectGuard转化为guard条件格式(兼容PathFeasibilityChecker)."""
    result = []
    for ig in indirect_guards:
        # 简化为dict格式, 供后续路径可行性检查使用
        result.append({
            'type': 'indirect_guard',
            'reg': ig.reg,
            'slot': ig.slot,
            'bound': ig.bound,
            'jcc': ig.jcc,
            'line': ig.line,
        })
    return result


__all__ = [
    'asip_filter_pairing', 'asip_enrich_guards',
    'asip_widen_refine',
]
