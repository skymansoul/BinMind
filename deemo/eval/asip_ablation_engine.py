#!/usr/bin/env python3
"""
ASIP消融引擎评估逻辑 — 带引擎开关的溢出评估与安全性判定.

  _evaluate_write_ablation: 带引擎开关的溢出评估
  _is_dynamic_write_safe_ablation: 动态写入安全性判定
  _get_max_write_size_ablation: 循环最大写入估算
"""
from __future__ import annotations
from typing import Optional

from core.heap_overflow_detector import HeapOverflowCandidate
from core.asip_source_detector import _is_within_slack_space

from eval.asip_ablation_config import AblationConfig


def _evaluate_write_ablation(
    alloc, store, write_size, effective_size,
    guard_limits, clamp_limits, loop_bounds,
    alloc_var_to_size_var, modulo_protected, path_conditions,
    cfg: AblationConfig,
) -> Optional[HeapOverflowCandidate]:
    """带引擎开关的溢出评估."""
    alloc_sz = effective_size

    # E5: 取模保护(仅B5+启用)
    if cfg.e5_modulo and store.offset_is_dynamic and store.base_var in modulo_protected:
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
                            f'write@{store.offset}+{write_size}B',
            )
        else:
            # 动态大小: 乘法因子
            if alloc_sz < 0 and store.store_size > 0:
                alloc_factor = -alloc_sz
                if store.store_size > alloc_factor:
                    overflow = store.store_size - alloc_factor
                    return HeapOverflowCandidate(
                        alloc_site=alloc, overflow_store=store,
                        overflow_bytes=overflow, confidence=0.80,
                        description=f'{alloc.alloc_func}(var*{alloc_factor}) → '
                                    f'write per element {store.store_size}B',
                    )
            # 引擎过滤
            if _is_dynamic_write_safe_ablation(
                alloc_sz, store, guard_limits, clamp_limits,
                alloc_var_to_size_var, path_conditions, cfg,
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
                            f'write@{store.offset}+{write_size}B',
            )
        else:
            if '_loop_' in loop_bounds:
                lb = loop_bounds['_loop_']
                max_write = _get_max_write_size_ablation(
                    lb, guard_limits, clamp_limits, cfg,
                )
                if max_write <= alloc_sz:
                    return None
                overflow = max_write - alloc_sz
                return HeapOverflowCandidate(
                    alloc_site=alloc, overflow_store=store,
                    overflow_bytes=overflow, confidence=0.75,
                    description=f'{alloc.alloc_func}({alloc_sz}) → '
                                f'loop write up to {max_write}B',
                )

    return None


def _is_dynamic_write_safe_ablation(
    alloc_sz, store, guard_limits, clamp_limits,
    alloc_var_to_size_var, path_conditions, cfg: AblationConfig,
) -> bool:
    """带引擎开关的动态写入安全性判定."""
    # E1: guard过滤
    if cfg.e1_guard:
        for var, limit in guard_limits.items():
            if isinstance(limit, int) and limit <= alloc_sz:
                return True
    # E2: clamp过滤
    if cfg.e2_clamp:
        for var, limit in clamp_limits.items():
            if limit <= alloc_sz:
                return True
    # E3: 路径条件
    if cfg.e3_path:
        for pc in path_conditions:
            upper = pc.get('upper', 0)
            if upper > 0 and upper <= alloc_sz:
                return True
    # E4: alloc=write配对
    if cfg.e4_alloc_write:
        if alloc_sz == 0:
            if (cfg.e1_guard and guard_limits) or (cfg.e2_clamp and clamp_limits):
                return True
            if cfg.e3_path:
                for pc in path_conditions:
                    upper = pc.get('upper', 0)
                    if upper > 0:
                        return True
        if alloc_var_to_size_var:
            for size_var, alloc_var in alloc_var_to_size_var.items():
                has_guard = (cfg.e1_guard and size_var in guard_limits)
                has_clamp = (cfg.e2_clamp and size_var in clamp_limits)
                if has_guard or has_clamp:
                    return True
        if alloc_sz == 0:
            if cfg.e3_path:
                for pc in path_conditions:
                    upper = pc.get('upper', 0)
                    if upper > 0:
                        return True
            if alloc_var_to_size_var and (
                (cfg.e1_guard and guard_limits) or (cfg.e2_clamp and clamp_limits)
            ):
                return True
    return False


def _get_max_write_size_ablation(
    loop_bound, guard_limits, clamp_limits, cfg: AblationConfig,
) -> int:
    """带引擎开关的循环最大写入估算."""
    if cfg.e1_guard:
        for var, limit in guard_limits.items():
            if isinstance(limit, int) and limit < loop_bound:
                return limit
    if cfg.e2_clamp:
        for var, limit in clamp_limits.items():
            if limit < loop_bound:
                return limit
    return loop_bound
