#!/usr/bin/env python3
"""
ASIP增强源码检测器 v5 — 精细化的逻辑溢出+物理安全判定.

五引擎级联误报过滤:
  E1: guard过滤 — if(n>X) return → X≤alloc_size → SAFE
  E2: clamp过滤 — if(n>X) n=X → X≤alloc_size → SAFE
  E3: 路径条件 — if(n>0&&n<=X) → X≤alloc_size → SAFE
  E4: alloc=write配对 — malloc(var)+memcpy(buf,src,var) → SAFE
  E5: 取模保护 — buf[i%N] → N≤alloc_size → SAFE

正则与提取函数从 asip_source_regex / asip_source_extract 导入.
"""

from typing import Dict, List, Optional

from core.heap_overflow_detector import (
    HeapAllocSite, HeapStore, HeapOverflowCandidate,
)
from core.asip_source_extract import (
    _extract_allocs, _extract_guard_limits,
    _extract_clamp_limits, _extract_loop_bounds, _extract_reallocs,
    _extract_cross_function_writes, _extract_modulo_protections,
    _extract_alloc_size_var, _extract_path_conditions,
)
from core.asip_source_writes import _extract_writes
from core.asip_source_regex import _parse_size


# 主入口

def extract_candidates_v3(source: str) -> List[HeapOverflowCandidate]:
    """源码级逻辑溢出检测: 候选生成 + 五引擎误报过滤."""
    lines = source.strip().split('\n')
    allocs = _extract_allocs(lines)
    if not allocs:
        return []

    guard_limits = _extract_guard_limits(lines)
    clamp_limits = _extract_clamp_limits(lines)
    loop_bounds = _extract_loop_bounds(lines)
    reallocs = _extract_reallocs(lines)
    cross_writes = _extract_cross_function_writes(lines)
    modulo_protected = _extract_modulo_protections(lines)
    alloc_var_to_size_var = _extract_alloc_size_var(lines)
    path_conditions = _extract_path_conditions(lines)

    candidates = []
    for alloc in allocs:
        effective_size = alloc.size_arg
        if alloc.result_var in reallocs:
            effective_size = reallocs[alloc.result_var]

        writes = _extract_writes(lines, alloc)
        if alloc.result_var in cross_writes:
            for cw in cross_writes[alloc.result_var]:
                writes.append(cw)

        for store, write_size in writes:
            cand = _evaluate_write(
                alloc, store, write_size, effective_size,
                guard_limits, clamp_limits, loop_bounds,
                alloc_var_to_size_var, modulo_protected,
                path_conditions,
            )
            if cand is not None:
                candidates.append(cand)

    return candidates


# 安全判定

def _is_within_slack_space(alloc_arg: int, write_end: int) -> bool:
    """E6已移除: 源码级按逻辑大小判定, off-by-one也是逻辑溢出."""
    return write_end <= alloc_arg


def _evaluate_write(
    alloc, store, write_size, effective_size,
    guard_limits, clamp_limits, loop_bounds,
    alloc_var_to_size_var, modulo_protected,
    path_conditions,
) -> Optional[HeapOverflowCandidate]:
    """评估单个写入是否溢出."""
    alloc_sz = effective_size

    # E5: 取模保护
    if store.offset_is_dynamic and store.base_var in modulo_protected:
        mod_val = modulo_protected[store.base_var]
        if store.store_size > 0 and mod_val + store.store_size <= alloc_sz:
            return None

    # strcpy: 始终无界
    if store.mnemonic == 'strcpy':
        return HeapOverflowCandidate(
            alloc_site=alloc, overflow_store=store,
            overflow_bytes=0, confidence=0.70,
            description=f'{alloc.alloc_func}({alloc_sz}) → unbounded strcpy',
        )

    # memcpy/memmove/strncpy
    if store.mnemonic in ('memcpy', 'memmove', 'strncpy'):
        if write_size is not None and write_size > 0:
            write_end = store.offset + write_size
            if write_end <= alloc_sz:
                return None
            if _is_within_slack_space(alloc_sz, write_end):
                return None
            overflow = write_end - alloc_sz
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=overflow, confidence=0.80,
                description=f'{alloc.alloc_func}({alloc_sz}) → '
                            f'write@{store.offset}+{write_size}B '
                            f'(overflow {overflow}B)',
            )
        else:
            # 乘法因子检测
            if alloc_sz < 0 and store.store_size > 0:
                alloc_factor = -alloc_sz
                if store.store_size > alloc_factor:
                    overflow = store.store_size - alloc_factor
                    return HeapOverflowCandidate(
                        alloc_site=alloc, overflow_store=store,
                        overflow_bytes=overflow, confidence=0.80,
                        description=f'{alloc.alloc_func}(var*{alloc_factor}) → '
                                    f'write per element {store.store_size}B '
                                    f'(overflow {overflow}B per element)',
                    )
            if _is_dynamic_write_safe(
                alloc_sz, store, guard_limits, clamp_limits,
                alloc_var_to_size_var, path_conditions,
            ):
                return None
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=0, confidence=0.55,
                description=f'{alloc.alloc_func}({alloc_sz}) → '
                            f'dynamic {store.mnemonic}',
            )

    # snprintf
    if store.mnemonic == 'snprintf':
        if write_size is not None and write_size > 0:
            write_end = store.offset + write_size
            if write_end <= alloc_sz:
                return None
            if _is_within_slack_space(alloc_sz, write_end):
                return None
            overflow = write_end - alloc_sz
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=overflow, confidence=0.80,
                description=f'{alloc.alloc_func}({alloc_sz}) → '
                            f'snprintf size {write_size}B',
            )
        return None

    # memset
    if store.mnemonic == 'memset':
        if write_size is not None and write_size > 0:
            write_end = store.offset + write_size
            if write_end <= alloc_sz:
                return None
            if _is_within_slack_space(alloc_sz, write_end):
                return None
            overflow = write_end - alloc_sz
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=overflow, confidence=0.80,
                description=f'{alloc.alloc_func}({alloc_sz}) → '
                            f'memset {write_size}B',
            )
        return None

    # store: 偏移写入
    if write_size is not None and write_size > 0:
        if not store.offset_is_dynamic:
            write_end = store.offset + write_size
            if write_end <= alloc_sz:
                return None
            if _is_within_slack_space(alloc_sz, write_end):
                return None
            overflow = write_end - alloc_sz
            return HeapOverflowCandidate(
                alloc_site=alloc, overflow_store=store,
                overflow_bytes=overflow, confidence=0.80,
                description=f'{alloc.alloc_func}({alloc_sz}) → '
                            f'write@{store.offset}+{write_size}B '
                            f'(overflow {overflow}B)',
            )
        else:
            if '_loop_' in loop_bounds:
                lb = loop_bounds['_loop_']
                max_write = _get_max_write_size(lb, guard_limits, clamp_limits)
                if max_write <= alloc_sz:
                    return None
                overflow = max_write - alloc_sz
                return HeapOverflowCandidate(
                    alloc_site=alloc, overflow_store=store,
                    overflow_bytes=overflow, confidence=0.75,
                    description=f'{alloc.alloc_func}({alloc_sz}) → '
                                f'loop write up to {max_write}B '
                                f'(overflow {overflow}B)',
                )

    return None


# 辅助函数

def _is_dynamic_write_safe(
    alloc_sz, store, guard_limits, clamp_limits,
    alloc_var_to_size_var, path_conditions,
) -> bool:
    """判断动态大小写入是否安全(E1-E4引擎过滤)."""
    # E1: guard限制
    for var, limit in guard_limits.items():
        if limit <= alloc_sz:
            return True

    # E2: clamp限制
    for var, limit in clamp_limits.items():
        if limit <= alloc_sz:
            return True

    # E3: 路径条件
    for pc in path_conditions:
        upper = pc.get('upper', 0)
        if upper > 0 and upper <= alloc_sz:
            return True

    # E4: 动态alloc=动态write
    if alloc_sz == 0:
        if guard_limits or clamp_limits:
            return True
        for pc in path_conditions:
            upper = pc.get('upper', 0)
            if upper > 0:
                return True

    if alloc_var_to_size_var:
        for size_var, alloc_var in alloc_var_to_size_var.items():
            if size_var in guard_limits or size_var in clamp_limits:
                return True

    if alloc_sz == 0:
        for pc in path_conditions:
            upper = pc.get('upper', 0)
            if upper > 0:
                return True
        if alloc_var_to_size_var and (guard_limits or clamp_limits):
            return True

    return False


def _get_max_write_size(loop_bound, guard_limits, clamp_limits) -> int:
    """循环内最大写入估算(受guard/clamp约束)."""
    for var, limit in guard_limits.items():
        if limit < loop_bound:
            return limit
    for var, limit in clamp_limits.items():
        if limit < loop_bound:
            return limit
    return loop_bound


__all__ = ['extract_candidates_v3', 'extract_candidates_v2']
