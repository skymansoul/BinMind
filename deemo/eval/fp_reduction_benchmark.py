"""
FP削减独立基准测试 — 测量四阶段级联过滤的交叉误报削减效果.
用法: python -m eval.fp_reduction_benchmark [--samples DIR] [--output DIR]
输出: fp_reduction_results.json (含消融实验数据)
"""

import json, os, sys, time
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'tests', 'cve_samples')
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')


def _classify_sample(dirname: str) -> str:
    """根据目录名推断漏洞类型."""
    dn = dirname.lower()
    if any(k in dn for k in ('fmt', 'format_string', 'fmtstr', 'printf')):
        return 'format_string'
    if any(k in dn for k in ('int', 'integer_overflow', 'intovf')):
        return 'integer_overflow'
    if any(k in dn for k in ('uaf', 'use_after', 'double_free')):
        return 'uaf'
    if any(k in dn for k in ('stack', 'stk_', 'stack_overflow')):
        return 'stack_overflow'
    if any(k in dn for k in ('heap', 'overflow', 'ho_')):
        return 'heap_overflow'
    return 'unknown'


def _has_heap_vuln(code: str) -> bool:
    """启发式判断代码是否含堆溢出漏洞."""
    import re
    has_malloc = bool(re.search(r'\b(malloc|calloc|realloc)\s*\(', code))
    has_heap_write = bool(re.search(r'\b(memcpy|memmove|memset|strcpy|strncpy|sprintf)\s*\(', code))
    return has_malloc and has_heap_write


def run_fp_reduction_benchmark(samples_dir: str = None,
                               output_dir: str = None) -> Dict:
    """运行FP削减基准测试.

    对每个样本: 运行 HeapFpReducer, 记录各阶段过滤结果.
    关键指标: 交叉误报率 (堆检测器在非堆样本上的告警率).
    """
    if samples_dir is None:
        samples_dir = SAMPLES_DIR
    if output_dir is None:
        output_dir = OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    from analysis.heap_fp_reducer import HeapFpReducer, _compute_effective_chunk

    reducer = HeapFpReducer(platform="x86_64")
    results: List[Dict] = []
    ablation = {
        'phase1_ptr_identity': {'total_pairs': 0, 'filtered': 0, 'fp_samples': []},
        'phase2_buffer_disjoint': {'total_pairs': 0, 'filtered': 0, 'fp_samples': []},
        'phase3_guard': {'total_pairs': 0, 'filtered': 0, 'fp_samples': []},
        'phase4_allocator': {'total_pairs': 0, 'filtered': 0, 'fp_samples': []},
    }
    cross_fp_stats = {
        'heap_on_stack': {'total': 0, 'detected': 0, 'filtered': 0},
        'heap_on_uaf': {'total': 0, 'detected': 0, 'filtered': 0},
        'heap_on_fmt': {'total': 0, 'detected': 0, 'filtered': 0},
        'heap_on_int': {'total': 0, 'detected': 0, 'filtered': 0},
    }
    # 类型名到缩写的映射 (与 cross_fp_stats key 对齐)
    _type_to_cross_key = {
        'stack_overflow': 'heap_on_stack',
        'uaf': 'heap_on_uaf',
        'format_string': 'heap_on_fmt',
        'integer_overflow': 'heap_on_int',
    }

    for dirname in sorted(os.listdir(samples_dir)):
        dirpath = os.path.join(samples_dir, dirname)
        if not os.path.isdir(dirpath):
            continue
        vuln_c = os.path.join(dirpath, 'vuln.c')
        if not os.path.exists(vuln_c):
            continue

        try:
            with open(vuln_c, 'r', encoding='utf-8', errors='replace') as f:
                code = f.read()
        except Exception:
            continue

        vuln_type = _classify_sample(dirname)
        t0 = time.perf_counter()

        # 运行FP削减器
        try:
            verdicts, stats = reducer.reduce(code)
        except Exception as e:
            results.append({
                'sample': dirname, 'type': vuln_type,
                'error': str(e)[:120],
                'duration_ms': round((time.perf_counter() - t0) * 1000, 1),
            })
            continue

        duration_ms = round((time.perf_counter() - t0) * 1000, 1)

        # 记录消融数据
        phase_breakdown = {
            'total_pairs': stats.total_candidates,
            'phase1_ptr_identity': stats.filtered_by_identity,
            'phase2_buffer_disjoint': stats.filtered_by_disjoint,
            'phase3_guard': stats.filtered_by_guard,
            'phase4_allocator': stats.filtered_by_allocator,
            'retained': stats.retained,
        }

        # 更新消融统计
        for phase_key in ablation:
            ablation[phase_key]['total_pairs'] += stats.total_candidates

        if stats.filtered_by_identity > 0:
            ablation['phase1_ptr_identity']['filtered'] += stats.filtered_by_identity
            ablation['phase1_ptr_identity']['fp_samples'].append(dirname)
        if stats.filtered_by_disjoint > 0:
            ablation['phase2_buffer_disjoint']['filtered'] += stats.filtered_by_disjoint
            ablation['phase2_buffer_disjoint']['fp_samples'].append(dirname)
        if stats.filtered_by_guard > 0:
            ablation['phase3_guard']['filtered'] += stats.filtered_by_guard
            ablation['phase3_guard']['fp_samples'].append(dirname)
        if stats.filtered_by_allocator > 0:
            ablation['phase4_allocator']['filtered'] += stats.filtered_by_allocator
            ablation['phase4_allocator']['fp_samples'].append(dirname)

        # 交叉误报追踪: 堆检测器在非堆样本上的行为
        has_pairs = stats.total_candidates > 0
        filtered_all = (stats.total_candidates > 0
                        and stats.retained == 0
                        and stats.total_filtered > 0)

        if vuln_type != 'heap_overflow' and has_pairs:
            cross_key = _type_to_cross_key.get(vuln_type)
            if cross_key and cross_key in cross_fp_stats:
                cross_fp_stats[cross_key]['total'] += 1
                cross_fp_stats[cross_key]['detected'] += 1
                if filtered_all:
                    cross_fp_stats[cross_key]['filtered'] += 1

        # 逐对详情
        pair_details = []
        for v in verdicts:
            pair_details.append({
                'alloc_line': v.alloc_line,
                'write_line': v.write_line,
                'alloc_func': v.alloc_func,
                'write_func': v.write_func,
                'verdict': v.verdict,
                'filter_phase': v.filter_phase,
                'reason': v.reason,
            })

        results.append({
            'sample': dirname,
            'type': vuln_type,
            'has_heap_vuln': _has_heap_vuln(code),
            'phase_breakdown': phase_breakdown,
            'fp_reduction_rate': stats.fp_reduction_rate,
            'verdicts': pair_details,
            'duration_ms': duration_ms,
        })

        # 控制台输出
        filt_str = f"total={stats.total_candidates} filt={stats.total_filtered} "
        filt_str += f"P1={stats.filtered_by_identity} P2={stats.filtered_by_disjoint} "
        filt_str += f"P3={stats.filtered_by_guard} P4={stats.filtered_by_allocator}"
        print(f"{dirname:45s} type={vuln_type:18s} {filt_str} ({duration_ms:.0f}ms)")

# 汇总
    total_pairs = sum(r['phase_breakdown']['total_pairs'] for r in results if 'phase_breakdown' in r)
    total_filtered = sum(
        r['phase_breakdown']['phase1_ptr_identity']
        + r['phase_breakdown']['phase2_buffer_disjoint']
        + r['phase_breakdown']['phase3_guard']
        + r['phase_breakdown']['phase4_allocator']
        for r in results if 'phase_breakdown' in r)

    # 按类型统计
    type_summary: Dict[str, Dict] = {}
    for r in results:
        vt = r['type']
        if vt not in type_summary:
            type_summary[vt] = {'total': 0, 'with_pairs': 0, 'filtered_all': 0, 'total_pairs': 0, 'total_filtered': 0}
        type_summary[vt]['total'] += 1
        if 'phase_breakdown' in r:
            pb = r['phase_breakdown']
            type_summary[vt]['total_pairs'] += pb['total_pairs']
            if pb['total_pairs'] > 0:
                type_summary[vt]['with_pairs'] += 1
            filtered = (pb['phase1_ptr_identity'] + pb['phase2_buffer_disjoint']
                       + pb['phase3_guard'] + pb['phase4_allocator'])
            type_summary[vt]['total_filtered'] += filtered
            if pb['total_pairs'] > 0 and pb['retained'] == 0:
                type_summary[vt]['filtered_all'] += 1

    # 交叉FP削减率
    cross_fp_summary = {}
    for key, cs in cross_fp_stats.items():
        if cs['total'] > 0:
            before_rate = cs['detected'] / cs['total'] * 100
            after_rate = (cs['detected'] - cs['filtered']) / cs['total'] * 100
            reduction = ((cs['detected'] - cs['filtered']) / max(1, cs['detected'])) * 100
        else:
            before_rate = after_rate = reduction = 0
        cross_fp_summary[key] = {
            'total_samples': cs['total'],
            'detected_before': cs['detected'],
            'filtered_by_reducer': cs['filtered'],
            'remaining_after': cs['detected'] - cs['filtered'],
            'before_fp_rate_pct': round(before_rate, 1),
            'after_fp_rate_pct': round(after_rate, 1),
            'reduction_pct': round(reduction, 1),
        }

    summary = {
        'total_samples': len(results),
        'total_pairs': total_pairs,
        'total_filtered': total_filtered,
        'overall_fp_reduction_pct': round(total_filtered / max(1, total_pairs) * 100, 1),
        'type_summary': type_summary,
        'cross_fp_summary': cross_fp_summary,
        'ablation': {k: {'total_pairs': v['total_pairs'], 'filtered': v['filtered'],
                         'filter_rate_pct': round(v['filtered'] / max(1, v['total_pairs']) * 100, 1),
                         'affected_samples': len(v['fp_samples'])}
                    for k, v in ablation.items()},
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'saturation_check': {},
    }

    # 饱和判定: FP削减率≥40%且剩余FP<20% → 饱和
    for key, cs in cross_fp_summary.items():
        reduced = cs['reduction_pct'] >= 40
        low_abs = cs['after_fp_rate_pct'] < 20
        summary['saturation_check'][key] = {
            'fp_reduction_40pct': reduced,
            'absolute_fp_below_20pct': low_abs,
            'saturated': reduced and low_abs,
        }

    # 输出JSON
    out_path = os.path.join(output_dir, 'fp_reduction_results.json')
    with open(out_path, 'w', encoding='utf-8') as f:
        json.dump({'summary': summary, 'results': results,
                   'ablation': ablation, 'cross_fp_stats': cross_fp_stats},
                  f, indent=2, ensure_ascii=False)

    # 控制台摘要
    print(f"\n{'='*70}")
    print(f"FP Reduction Benchmark — Summary")
    print(f"{'='*70}")
    print(f"  Total samples: {summary['total_samples']}")
    print(f"  Total (alloc,write) pairs: {total_pairs}")
    print(f"  Total filtered: {total_filtered} ({summary['overall_fp_reduction_pct']}%)")
    print(f"\n  Cross-type FP Reduction:")
    for key, cs in cross_fp_summary.items():
        print(f"    {key}: {cs['before_fp_rate_pct']}% → {cs['after_fp_rate_pct']}% "
              f"({cs['reduction_pct']}% reduction, {cs['filtered_by_reducer']}/{cs['detected_before']} filtered)")

    print(f"\n  Ablation (per-phase contribution):")
    for phase, data in summary['ablation'].items():
        print(f"    {phase}: {data['filtered']}/{data['total_pairs']} pairs "
              f"({data['filter_rate_pct']}%), {data['affected_samples']} samples")

    print(f"\n  Saturation Check:")
    for key, sc in summary['saturation_check'].items():
        status = "SATURATED" if sc['saturated'] else "needs work"
        reduc_ok = "Y" if sc['fp_reduction_40pct'] else 'N'
        fp_ok = "Y" if sc['absolute_fp_below_20pct'] else 'N'
        print(f"    {key}: {status} (reduction>=40%: {reduc_ok}, FP<20%: {fp_ok})")

    print(f"\n  Results: {out_path}")
    return summary


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--samples', default=None)
    p.add_argument('--output', default=None)
    args = p.parse_args()
    run_fp_reduction_benchmark(args.samples, args.output)
