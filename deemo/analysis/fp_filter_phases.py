"""
统一误报过滤器的五个阶段实现函数。

从 UnifiedFPFilter 中提取, 保持每个阶段的独立性:
  Phase 0 — 分配器语义: glibc 对齐/最小chunk约束
  Phase 1 — 路径约束收集: 分支条件 → 变量→上界映射
  Phase 2 — 堆布局推断: 连续chunk间距建模
  Phase 3 — Z3约束证明: SMT可满足性验证
  Phase 4 — Strided Interval: 步长区间消除sizeof(T)假溢出

每个函数签名:
  phase_fn(candidates, platform, checker, pseudocode, ir_lines, constraints_map)
  → (kept_candidates, FilterStage, updated_constraints_map)

设计决策: 提取为独立函数而非方法, 便于单元测试和阶段独立性验证。
"""


import re
from typing import Any, Dict, List, Optional, Tuple

from core.allocator_constraints import AllocSize


def _make_stage(name: str, input_count: int) -> "FilterStage":
    """创建阶段统计对象 —— 延迟 import 避免循环。"""
    from analysis.unified_fp_filter import FilterStage
    return FilterStage(name=name, input_count=input_count)


# Phase 0: 分配器语义

def phase_allocator_semantics(
    candidates: list,
    platform: str = "x86_64",
    **_kw,
) -> Tuple[list, "FilterStage"]:
    """Phase 0: 分配器语义过滤。

    规则:
      1. 对齐提升: malloc(20) → 实际 32B usable → store offset 24 安全
      2. realloc 扩张: 若新大小覆盖 offset → 安全
      3. calloc nmemb*size: 乘积对齐
    """
    from analysis.unified_fp_filter import FilterStage
    stage = FilterStage(name='allocator_semantics', input_count=len(candidates))
    kept = []

    for c in candidates:
        alloc_size = getattr(c, 'alloc_site', None)
        if alloc_size is None:
            kept.append(c)
            continue

        size_arg = getattr(alloc_size, 'size_arg', 0)
        alloc_func = getattr(alloc_size, 'alloc_func', 'malloc')
        store = getattr(c, 'overflow_store', None)
        offset = getattr(store, 'offset', 0) if store else 0
        store_sz = getattr(store, 'store_size', 1) if store else 1

        if size_arg <= 0:
            kept.append(c)
            continue

        effective = AllocSize.from_request(size_arg, platform)

        if offset + store_sz <= effective.effective:
            reason = f'alignment: {size_arg}B→{effective.effective}B covers offset={offset}'
            stage.filter_reasons[reason] = stage.filter_reasons.get(reason, 0) + 1
            continue

        # 使用 allocator constraint checker
        from core.allocator_constraints import AllocatorConstraintChecker
        checker = AllocatorConstraintChecker(platform)
        verdict = checker.check_overflow(size_arg, offset + store_sz, alloc_func)
        if verdict == 'FILTER':
            reason = f'alloc_constraint: {alloc_func}({size_arg}) safe for write {offset}+{store_sz}'
            stage.filter_reasons[reason] = stage.filter_reasons.get(reason, 0) + 1
            continue

        kept.append(c)

    stage.remaining_count = len(kept)
    stage.filtered_count = stage.input_count - len(kept)
    return kept, stage


# Phase 1: 路径约束收集

def phase_path_constraints(
    candidates: list,
    pseudocode: str = "",
    platform: str = "x86_64",
    **_kw,
) -> Tuple[list, "FilterStage", Dict[str, List[Any]]]:
    """Phase 1: 路径约束收集。

    对每个候选, 在伪代码中搜索涉及 alloc 变量的约束条件。
    """
    from analysis.unified_fp_filter import FilterStage
    stage = FilterStage(name='path_constraints', input_count=len(candidates))
    constraints_map: Dict[str, List[Any]] = {}
    kept = []

    try:
        from analysis.path_constraint_collector import PathConstraintCollector
        collector = PathConstraintCollector()
    except ImportError:
        stage.remaining_count = len(candidates)
        return candidates, stage, constraints_map

    for c in candidates:
        alloc_site = getattr(c, 'alloc_site', None)
        if alloc_site is None:
            kept.append(c)
            continue

        size_var = _extract_size_var_from_alloc(pseudocode, alloc_site)
        if size_var:
            bounds = collector.collect(pseudocode, target_var=size_var)
            if bounds:
                pc = bounds.get(size_var)
                if pc and pc.constraints:
                    constraints_map[size_var] = pc.constraints
                    size_arg = getattr(alloc_site, 'size_arg', 0)
                    store = getattr(c, 'overflow_store', None)
                    offset = getattr(store, 'offset', 0) if store else 0
                    effective = AllocSize.from_request(size_arg, platform)
                    if offset <= effective.effective:
                        reason = f'constraint bounds: {size_var} constrained, offset safe'
                        stage.filter_reasons[reason] = (
                            stage.filter_reasons.get(reason, 0) + 1)
                        continue

        kept.append(c)

    stage.remaining_count = len(kept)
    stage.filtered_count = stage.input_count - len(kept)
    return kept, stage, constraints_map


# 辅助函数 (供 Phase 0/1 使用)

def _extract_size_var_from_alloc(pseudocode: str, alloc_site) -> str:
    """从分配点提取 size 参数的变量名。"""
    pc = getattr(alloc_site, 'pc', -1)
    lines = pseudocode.splitlines()

    if 0 <= pc < len(lines):
        line = lines[pc]
        m = re.search(r'malloc\s*\(\s*(\w+)\s*\)', line, re.IGNORECASE)
        if m and not m.group(1).isdigit():
            return m.group(1)
        m = re.search(r'calloc\s*\(\s*(\w+)\s*,\s*(\w+)\s*\)', line, re.IGNORECASE)
        if m and not m.group(2).isdigit():
            return m.group(2)

    size_arg = getattr(alloc_site, 'size_arg', 0)
    return str(size_arg) if size_arg > 0 else ''


__all__ = ['phase_allocator_semantics', 'phase_path_constraints']
