# coding: utf-8
"""
批量路径敏感过滤入口 — 对堆溢出候选集执行 PathSensitiveHeapAnalyzer.

"""

from typing import Any, Dict, List, Tuple

from modules.core.compat.path_abstract_interpret import (
    PathSensitiveHeapAnalyzer,
)
from modules.core.compat.cfg_extractor import extract_cfg_subgraph
from modules.core.compat.value_range import infer_interval


def batch_path_sensitive_filter(
    candidates: List[Dict],
    instructions: List[Dict],
    ir_ops: Dict[int, Dict],
    def_use_chains: Dict[int, List[int]],
) -> Tuple[List[Dict], Dict[str, Any]]:
    """对堆溢出候选批量执行路径敏感过滤 (含 widening + narrowing)."""
    retained: List[Dict] = []
    filtered_count = 0
    analysis_timeouts = 0
    total_narrow_iters = 0

    for c in candidates:
        alloc_site = _addr(c.get('alloc_site', c.get('overflow_site', 0)))
        write_site = _addr(c.get('write_site', c.get('overflow_site', 0)))

        if alloc_site == 0 or write_site == 0:
            retained.append(c)
            continue

        subgraph = extract_cfg_subgraph(
            instructions, ir_ops, alloc_site, write_site)
        if len(subgraph) < 2:
            retained.append(c)
            continue

        alloc_var = c.get('alloc_size_var', 'size')
        constants = {}
        if c.get('alloc_size'):
            constants = {alloc_var: c.get('alloc_size', 0)}
        alloc_interval = infer_interval(
            alloc_var, alloc_site, def_use_chains, ir_ops, constants)

        analyzer = PathSensitiveHeapAnalyzer(subgraph)
        result = analyzer.analyze(alloc_site, write_site, alloc_interval)
        total_narrow_iters += result.narrow_iterations

        if result.provably_safe:
            filtered_count += 1
        else:
            c['path_analysis'] = {
                'provably_safe': result.provably_safe,
                'alloc_interval': result.alloc_final_interval,
                'write_interval': result.write_final_interval,
                'iterations': result.iteration_count,
                'narrow_iters': result.narrow_iterations,
                'detail': result.detail,
            }
            retained.append(c)

        if result.iteration_count >= PathSensitiveHeapAnalyzer.MAX_ITERATIONS:
            analysis_timeouts += 1

    stats = {
        'total': len(candidates), 'retained': len(retained),
        'filtered_by_path_analysis': filtered_count,
        'analysis_timeouts': analysis_timeouts,
        'total_narrow_iterations': total_narrow_iters,
        'reduction_rate': f'{filtered_count/max(1,len(candidates)):.1%}',
    }
    return retained, stats


def _addr(v: Any) -> int:
    if isinstance(v, int): return v
    if isinstance(v, str):
        try: return int(v, 16) if v.startswith('0x') else int(v)
        except: return 0
    return 0
