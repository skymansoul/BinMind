"""
UAF深度检测统一入口 — 集成语义VRF + 增强VRF(字段/Realloc/循环/跨函数) + CFG + TARPS.
提供 analyze_uaf_deep() 作为 analyze_uaf() 的增强替代.
"""
import logging
from typing import Dict, List

_log = logging.getLogger(__name__)


def analyze_uaf_deep(code: str, func_name: str = "") -> Dict:
    """UAF深度分析: 基础VRF + 增强VRF(字段/realloc/循环/跨函数) + TARPS.

    返回与 analyze_uaf() 兼容的 Dict, 额外包含各层级计数.
    """
    result = {
        'total': 0, 'confirmed': 0, 'likely': 0,
        'filtered': 0, 'detected': False,
        'interproc_count': 0, 'realloc_count': 0,
        'field_count': 0, 'loop_df_count': 0,
        'details': [],
    }
    seen_ptrs = set()  # 去重

    def _merge_findings(findings, prefix=''):
        for f in findings:
            key = f'{prefix}:{f.get("ptr","?")}:{f.get("type","?")}:{f.get("free_line",f.get("realloc_line",0))}'
            if key in seen_ptrs:
                continue
            seen_ptrs.add(key)
            conf = f.get('confidence', 0)
            if conf >= 0.60:
                result['confirmed'] += 1
                result['detected'] = True
            elif conf >= 0.30:
                result['likely'] += 1
                result['detected'] = True
            else:
                result['filtered'] += 1
            result['total'] += 1
            result['details'].append(f)

    # Level 1: 基础语义VRF (alloc/free/use 三元组 + 四层FP过滤)
    try:
        from analysis.uaf_semantic_vrf import analyze_uaf
        base = analyze_uaf(code)
        result['total'] = base['total']
        result['confirmed'] = base['confirmed']
        result['likely'] = base['likely']
        result['filtered'] = base['filtered']
        result['detected'] = base['detected']
        for s in base.get('sites', []):
            seen_ptrs.add(f'base:{s.ptr_name}:{s.free_line}')
    except Exception as _e:
        _log.warning('uaf_semantic_vrf failed: %s', _e)

    # Level 2: 增强VRF (结构体字段 + Realloc旧指针 + 循环double-free + 跨函数double-free)
    try:
        from analysis.uaf_field_realloc_vrf import analyze_uaf_enhanced
        enhanced = analyze_uaf_enhanced(code)
        _merge_findings(enhanced.get('details', []), 'enhanced')
        result['field_count'] = enhanced.get('by_type', {}).get('struct_field', 0)
        result['realloc_count'] = enhanced.get('by_type', {}).get('realloc_old', 0)
        result['loop_df_count'] = enhanced.get('by_type', {}).get('loop_double_free', 0)
        result['interproc_count'] = enhanced.get('by_type', {}).get('interproc_double_free', 0)
    except Exception as _e:
        _log.warning('uaf_field_realloc_vrf failed: %s', _e)

    # Level 3: Realloc 别名悬空检测 (补充增强VRF遗漏的realloc场景)
    try:
        from analysis.uaf_realloc_integration import check_realloc_uaf
        realloc_findings = check_realloc_uaf(code)
        _merge_findings(realloc_findings, 'realloc')
        result['realloc_count'] += len(realloc_findings)
    except Exception as _e:
        _log.warning('uaf_realloc_integration failed: %s', _e)

    # Level 4: 跨函数CFG UAF检测 (alloc/free/use分散在不同函数)
    try:
        from analysis.uaf_interproc_cfg import InterProcCFGBuilder
        builder = InterProcCFGBuilder()
        cg = builder.build(code)
        if cg and cg.nodes:
            for node in cg.nodes.values():
                interproc_uafs = builder.find_cross_function_uaf(node)
                _merge_findings(interproc_uafs, 'cfg')
                result['interproc_count'] += len(interproc_uafs)
    except Exception as _e:
        _log.warning('uaf_interproc_cfg failed: %s', _e)

    return result


__all__ = ['analyze_uaf_deep']
