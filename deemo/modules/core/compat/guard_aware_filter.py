# coding: utf-8
"""守卫感知过滤层 — 组合同源证明 + 守卫精化 + 双侧可控性.

面向真实二进制候选的三个独立降误报手段, 顺序应用:
  1. same_source: alloc/write 大小值同一槽且同一 store 供给 → 可证安全
  2. guard_refine: write 值路径存在上限守卫且 alloc 覆盖 → 可证安全
  3. controllability: 双侧大小均不可控 → 降权 (不作为可利用候选)

该层定位为 deep_heap_orchestrator 中 VCT 之后的增强层, 聚焦解决
"同一变量复用"、"分支守卫上限"、"内部数据不可控" 三类二进制误报.
"""

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from modules.core.compat.guard_refine import (
    extract_guards, refine_with_guards, prove_safe_with_guards)
from modules.core.compat.size_controllability import (
    batch_controllability_filter, classify_candidate)


def guard_aware_filter(
    candidates: List[Dict],
    instructions: List[Dict],
    ir_ops: Dict[int, Dict],
    def_use: Dict[int, List[int]],
    callee_names: Optional[Dict[int, str]] = None,
    drop_internal: bool = True,
    enable_same_source: bool = True,
    enable_guard: bool = True,
    enable_control: bool = True,
) -> Tuple[List[Dict], Dict[str, Any]]:
    """对候选执行守卫感知过滤, 返回 (保留, 统计)."""
    retained: List[Dict] = []
    stats = {'total': len(candidates),
             'same_source_safe': 0, 'guard_safe': 0,
             'controllability_dropped': 0, 'retained': 0}

    # 先应用双侧可控性 (独立维度)
    work = candidates
    if enable_control:
        work, cstats = batch_controllability_filter(
            candidates, def_use, ir_ops, callee_names,
            drop_internal=drop_internal)
        stats['controllability_dropped'] = cstats['dropped_internal']

    for c in work:
        proven = False

        # 1. 同源证明: malloc(N) 与 memcpy(...,N) 使用同一槽同一 store
        if enable_same_source and c.get('same_source'):
            c['_same_source_safe'] = True
            c['exploitable'] = False
            c['confidence'] = min(c.get('confidence', 0.5), 0.1)
            c['filter_reason'] = '同源证明: alloc/write 大小同一变量'
            stats['same_source_safe'] += 1
            continue

        # 2. 守卫精化: write 路径有上限守卫且 alloc 覆盖
        if enable_guard and c.get('write_def'):
            safe, reason, _ = prove_safe_with_guards(c, instructions)
            if safe:
                c['_guard_safe'] = True
                c['exploitable'] = False
                c['confidence'] = min(c.get('confidence', 0.5), 0.1)
                c['filter_reason'] = reason
                stats['guard_safe'] += 1
                continue

        retained.append(c)

    stats['retained'] = len(retained)
    return retained, stats


def report_guard_layers(results: List[Dict],
                        instructions: List[Dict],
                        ir_ops: Dict[int, Dict],
                        def_use: Dict[int, List[int]]) -> Dict[str, Any]:
    """生成各子层统计报告 (用于回归输出)."""
    total = len(results)
    same = sum(1 for c in results if c.get('_same_source_safe'))
    guard = sum(1 for c in results if c.get('_guard_safe'))
    control = sum(1 for c in results
                  if c.get('_control', {}).get('downgrade'))
    return {
        'total': total,
        'same_source_safe': same,
        'guard_safe': guard,
        'controllability_downgraded': control,
        'fp_reduction': f'{(same + guard + control) / max(1, total):.1%}',
    }
