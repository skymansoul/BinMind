#!/usr/bin/env python3
# coding: utf-8
"""
管线完整性审计器 — 扫描所有 compat/ 模块, 识别分析深度缺口.

输出:
  1. 每类漏洞的当前分析层数 (L0-L6)
  2. 缺失的分析能力 (与最佳实践对比)
  3. 建议优先级排序
  4. CVSS 漏洞类型覆盖矩阵

方法论: 将每个 compat/ 模块映射到分析深度谱系:
  L0: 模式匹配 (启发式规则)
  L1: 值范围分析 (区间/同余)
  L2: 数据流追踪 (污点/def-use)
  L3: 跨过程分析 (函数摘要/调用链)
  L4: 路径敏感分析 (CFG 遍历/抽象解释)
  L5: 约束求解 (符号推理/证明)
  L6: 统计校准 (基准数据/阈值调优)

"""

import os, sys, json, time
from pathlib import Path
from typing import Dict, List, Tuple

_CORE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_CORE_DIR))

# 漏洞类型定义与目标层数
VULN_TYPES = {
    'heap_overflow': {
        'name': 'Heap Overflow',
        'target_layers': 6,
        'modules': ['constraint_solver', 'alloc_constraint_encoder',
                     'congruence_domain', 'value_range', 'path_abstract_interpret',
                     'narrow_refine', 'batch_path_filter', 'cfg_extractor',
                     'constraint_filter', 'alloc_constraints',
                     'interproc_taint', 'interproc_enhance',
                     'fp_calibrator', 'deep_heap_orchestrator'],
        'best_practice': 'ISSTA 2024 Heap Disjointness + Granger 1989 congruence',
        'cvss_ids': ['CWE-122', 'CWE-787'],
    },
    'use_after_free': {
        'name': 'Use-After-Free',
        'target_layers': 6,
        'modules': ['uaf_constraint', 'uaf_pipeline', 'uaf_enhance',
                     'uaf_detector', 'uaf_escape_analysis'],
        'best_practice': 'CRIX (USENIX 22) + UAFL (ICSE 20)',
        'cvss_ids': ['CWE-416', 'CWE-415'],
    },
    'format_string': {
        'name': 'Format String',
        'target_layers': 4,
        'modules': ['fmt_constraint'],
        'best_practice': 'FormatShield (NDSS 21) + Lin et al. (PLDI 19)',
        'cvss_ids': ['CWE-134'],
    },
    'integer_overflow': {
        'name': 'Integer Overflow',
        'target_layers': 6,
        'modules': ['int_overflow', 'int_overflow_enhance'],
        'best_practice': 'IntScope (NDSS 09) + RICH (NDSS 07)',
        'cvss_ids': ['CWE-190', 'CWE-191', 'CWE-680'],
    },
    'off_by_one': {
        'name': 'Off-by-One',
        'target_layers': 3,
        'modules': ['off_by_one'],
        'best_practice': 'Null-byte poisoning detection (Phrack 66)',
        'cvss_ids': ['CWE-193', 'CWE-131'],
    },
    'double_free': {
        'name': 'Double-Free',
        'target_layers': 3,
        'modules': ['double_free'],
        'best_practice': 'Fastbin dup / tcache dup detection',
        'cvss_ids': ['CWE-415'],
    },
    'type_confusion': {
        'name': 'Type Confusion',
        'target_layers': 3,
        'modules': ['type_confusion'],
        'best_practice': 'TypeSan (CCS 17) + HexType (CCS 18)',
        'cvss_ids': ['CWE-843'],
    },
    'uninitialized_memory': {
        'name': 'Uninitialized Memory',
        'target_layers': 3,
        'modules': ['uninitialized_memory'],
        'best_practice': 'UniSan (USENIX 21) + EffectiveSan (PLDI 17)',
        'cvss_ids': ['CWE-457'],
    },
    'buffer_underflow': {
        'name': 'Buffer Underflow',
        'target_layers': 3,
        'modules': ['buffer_underflow'],
        'best_practice': 'UnderGuard + BoundsChecker',
        'cvss_ids': ['CWE-124'],
    },
    'cross_pipeline': {
        'name': 'Cross-Pipeline Correlation',
        'target_layers': 1,
        'modules': ['cross_pipeline_correlate'],
        'best_practice': 'Multi-modal evidence fusion (Bayesian)',
        'cvss_ids': ['N/A'],
    },
}

# 未覆盖但有研究价值的漏洞类型
MISSING_VULN_TYPES = [
    {'type': 'race_condition_heap', 'cwe': 'CWE-362',
     'description': '堆上的竞态条件 (TOCTOU)',
     'priority': 'MEDIUM', 'estimated_layers': 2},
    {'type': 'null_ptr_deref', 'cwe': 'CWE-476',
     'description': '空指针解引用路径分析',
     'priority': 'LOW', 'estimated_layers': 2},
]


def count_module_layers(module_name: str) -> int:
    """通过启发式分析估算模块的分析深度."""
    mod_path = _CORE_DIR / 'compat' / f'{module_name}.py'
    if not mod_path.exists():
        return 0

    content = mod_path.read_text(encoding='utf-8', errors='ignore')
    lines = content.split('\n')
    layer_score = 0

    # 检测分析层次的关键词
    l0_markers = ['def detect', 'def find', 'pattern', 'regex', 'heuristic']
    l1_markers = ['Interval', 'range', 'congruence', 'value_range', 'lo', 'hi',
                  'min_val', 'max_val', 'modulus', 'residue']
    l2_markers = ['taint', 'def_use', 'source', 'sink', 'data_flow',
                  'propagat', 'trace_back']
    l3_markers = ['interproc', 'call_graph', 'callee', 'caller', 'function_summary',
                  'cross_function', 'ret_site']
    l4_markers = ['path_sensitive', 'cfg', 'basic_block', 'branch', 'widen',
                  'narrow', 'abstract_interp', 'loop_header', 'join']
    l5_markers = ['constraint', 'solver', 'satisfy', 'prove', 'sat', 'unsat',
                  'infeasible', 'linear', 'inequality', 'symbolic']
    l6_markers = ['calibrat', 'statistical', 'threshold', 'baseline', 'benchmark',
                  'fp_rate', 'roc', 'ground_truth', 'tune']

    for line in lines:
        line_lower = line.lower()
        if any(m in line_lower for m in l0_markers):
            layer_score = max(layer_score, 1)
        if any(m in line_lower for m in l1_markers):
            layer_score = max(layer_score, 2)
        if any(m in line_lower for m in l2_markers):
            layer_score = max(layer_score, 3)
        if any(m in line_lower for m in l3_markers):
            layer_score = max(layer_score, 4)
        if any(m in line_lower for m in l4_markers):
            layer_score = max(layer_score, 5)
        if any(m in line_lower for m in l5_markers):
            layer_score = max(layer_score, 6)
        if any(m in line_lower for m in l6_markers):
            layer_score = max(layer_score, 7)

    return layer_score


def run_audit() -> Dict:
    """运行完整性审计."""
    report = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'covered_types': {},
        'missing_types': MISSING_VULN_TYPES,
        'summary': {},
    }

    total_layers = 0
    max_layers = 0
    total_modules = 0
    total_lines = 0

    for type_id, info in VULN_TYPES.items():
        module_layers = {}
        type_max = 0
        for mod_name in info['modules']:
            layers = count_module_layers(mod_name)
            mod_path = _CORE_DIR / 'compat' / f'{mod_name}.py'
            if mod_path.exists():
                lines = len(mod_path.read_text(encoding='utf-8', errors='ignore').split('\n'))
            else:
                lines = 0
            module_layers[mod_name] = {'depth': layers, 'lines': lines}
            type_max = max(type_max, layers)
            total_modules += 1
            total_lines += lines

        gap = info['target_layers'] - type_max
        total_layers += type_max
        max_layers += info['target_layers']

        report['covered_types'][type_id] = {
            'name': info['name'],
            'max_depth': type_max,
            'target_depth': info['target_layers'],
            'gap': gap,
            'status': 'SATURATED' if gap <= 0 else f'GAP={gap}',
            'modules': module_layers,
            'cvss': info['cvss_ids'],
        }

    coverage_pct = (total_layers / max(max_layers, 1)) * 100
    report['summary'] = {
        'vuln_types_covered': len(VULN_TYPES),
        'vuln_types_missing': len(MISSING_VULN_TYPES),
        'total_modules': total_modules,
        'total_lines': total_lines,
        'layer_coverage_pct': round(coverage_pct, 1),
        'types_saturated': sum(
            1 for t in report['covered_types'].values()
            if t['status'] == 'SATURATED'),
        'types_with_gaps': sum(
            1 for t in report['covered_types'].values()
            if t['status'] != 'SATURATED'),
        'top_priority_gap': _find_top_gap(report['covered_types']),
    }
    return report


def _find_top_gap(covered: Dict) -> str:
    """找到最大的分析缺口."""
    gaps = [(tid, info['name'], info['gap'])
            for tid, info in covered.items()
            if info['gap'] > 0]
    gaps.sort(key=lambda x: x[2], reverse=True)
    if gaps:
        return f'{gaps[0][1]} (gap={gaps[0][2]} layers)'
    return 'None — all types saturated'


def print_audit_report(report: Dict):
    """打印审计报告."""
    s = report['summary']
    print(f"\n{'='*70}")
    print(f"PIPELINE COMPLETENESS AUDIT — {report['timestamp']}")
    print(f"{'='*70}")
    print(f"  Vulnerability types covered: {s['vuln_types_covered']}")
    print(f"  Missing types (high-priority): {s['vuln_types_missing']}")
    print(f"  Total compat modules: {s['total_modules']}")
    print(f"  Total lines of analysis: {s['total_lines']}")
    print(f"  Layer coverage: {s['layer_coverage_pct']}% ({s['types_saturated']}/{len(VULN_TYPES)} saturated)")
    print(f"  Top priority gap: {s['top_priority_gap']}")
    print(f"\n{'─'*70}")
    print(f"  {'Type':<22} {'Depth':<8} {'Target':<8} {'Gap':<6} {'Status':<12}")
    print(f"  {'─'*70}")

    for tid, info in report['covered_types'].items():
        status_icon = 'OK' if info['status'] == 'SATURATED' else '!!'
        print(f"  {info['name']:<22} {info['max_depth']:<8} "
              f"{info['target_depth']:<8} {info['gap']:<6} "
              f"{status_icon} {info['status']:<10}")

    print(f"\n{'─'*70}")
    print(f"  Missing vulnerability types (not yet covered):")
    for mt in sorted(MISSING_VULN_TYPES, key=lambda x: x['priority']):
        print(f"    [{mt['priority']}] {mt['type']} ({mt['cwe']}) — {mt['description']}")

    print(f"\n{'='*70}")
    print(f"  Audit complete. Recommendation: {_get_recommendation(report)}")
    print(f"{'='*70}\n")


def _get_recommendation(report: Dict) -> str:
    """生成最优先建议."""
    gaps = [(tid, info) for tid, info in report['covered_types'].items()
            if info['gap'] > 0]
    if gaps:
        gaps.sort(key=lambda x: x[1]['gap'], reverse=True)
        return f'Deepen {gaps[0][1]["name"]} (gap={gaps[0][1]["gap"]} layers)'

    missing_high = [m for m in MISSING_VULN_TYPES if m['priority'] == 'HIGH']
    if missing_high:
        return f'Add {missing_high[0]["type"]} ({missing_high[0]["cwe"]}) detection'

    return 'Expand existing types to deeper layers or add new CWE coverage'


if __name__ == '__main__':
    import argparse
    ap = argparse.ArgumentParser(description='BinMind Pipeline Completeness Audit')
    ap.add_argument('--output', default='benchmark_results',
                    help='输出目录')
    ap.add_argument('--json-only', action='store_true',
                    help='仅输出 JSON')
    args = ap.parse_args()

    report = run_audit()
    out_dir = os.path.join(str(_CORE_DIR), args.output)
    os.makedirs(out_dir, exist_ok=True)

    out_path = os.path.join(out_dir, 'completeness_audit.json')
    with open(out_path, 'w') as f:
        json.dump(report, f, indent=2)
    if not args.json_only:
        print_audit_report(report)
    print(f'  JSON → {out_path}')
    print(f'\nCompleteness audit complete')
