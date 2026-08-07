# coding: utf-8
"""
跨函数污点增强入口 — 对堆溢出候选批量附加跨函数污点信息.

"""

from typing import Any, Dict, List, Optional, Tuple

from modules.core.compat.interproc_taint import InterProcTaintEngine


def enhance_with_interproc(
    candidates: List[Dict],
    def_use_chains: Dict[int, List[int]],
    ir_ops: Dict[int, Dict],
    instructions: List[Dict],
    call_graph: Optional[Dict[int, List[int]]] = None,
    callee_names: Optional[Dict[int, str]] = None,
) -> Tuple[List[Dict], Dict[str, Any]]:
    """对堆溢出候选做跨函数污点增强.

    返回: (增强后的候选, 统计)
    """
    engine = InterProcTaintEngine(def_use_chains, ir_ops, instructions)
    if call_graph and callee_names:
        engine.build_summaries(call_graph, callee_names)

    enhanced = []
    stats = {'total': len(candidates), 'cross_func_traced': 0,
             'external_input_confirmed': 0, 'unknown_traced': 0}

    for c in candidates:
        site = c.get('overflow_site', c.get('alloc_site', 0))
        if isinstance(site, str):
            try: site = int(site, 16)
            except: pass

        result = engine.trace_across_functions(site, max_depth=12)
        if result.crosses_calls > 0:
            stats['cross_func_traced'] += 1

        c['interproc_taint'] = {
            'source_type': result.source_type,
            'source_func': result.source_func,
            'crosses_calls': result.crosses_calls,
            'path_length': len(result.path),
        }

        if result.source_type == 'external_input':
            stats['external_input_confirmed'] += 1
        elif result.source_type == 'unknown':
            stats['unknown_traced'] += 1

        enhanced.append(c)

    return enhanced, stats
