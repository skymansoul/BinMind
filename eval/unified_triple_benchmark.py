"""
统一三类型基准测试 — 堆溢出 + 格式串 + 整数溢出 一次运行。

用法: python -m eval.unified_triple_benchmark [--samples DIR] [--output DIR]
输出: unified_benchmark_results.json + unified_benchmark_summary.csv
"""

import json, os, sys, time
from typing import Any, Dict, List, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

SAMPLES_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           'tests', 'cve_samples')
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'results')


def _classify_sample(dirname: str) -> str:
    """根据目录名推断漏洞类型。优先匹配具体类型。"""
    dn = dirname.lower()
    if any(k in dn for k in ('fmt', 'format_string', 'printf', 'fmtstr')):
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


def run_triple_benchmark(samples_dir: str = None, output_dir: str = None) -> Dict:
    """运行三类型综合基准测试。"""
    if samples_dir is None:
        samples_dir = SAMPLES_DIR
    if output_dir is None:
        output_dir = OUTPUT_DIR
    os.makedirs(output_dir, exist_ok=True)

    all_results: List[Dict] = []
    type_stats: Dict[str, Dict] = {}

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
        result = {'sample': dirname, 'type': vuln_type, 'detections': {}}

# 堆溢出检测
        try:
            from core.unified_heap_pipeline import analyze_heap_safety
            findings, stats = analyze_heap_safety(code, 'main', vuln_c)
            heap_detected = len(findings) > 0

# FP削减器后处理
            fp_reduced = False
            fp_reason = ''
            try:
                from analysis.heap_fp_reducer import HeapFpReducer
                reducer = HeapFpReducer()
                fp_verdicts, fp_stats = reducer.reduce(code)
                if fp_stats.total_candidates > 0 and fp_stats.retained == 0:
                    fp_reduced = True
                    fp_reason = 'all_pairs_filtered'
                elif fp_stats.total_candidates > 0:
                    fp_reason = f'{fp_stats.total_filtered}/{fp_stats.total_candidates}_filtered'
            except Exception:
                pass

            result['detections']['heap'] = {
                'total': len(findings),
                'definite': sum(1 for f in findings if f.get('verdict') == 'DEFINITE'),
                'possible': sum(1 for f in findings if f.get('verdict') == 'POSSIBLE'),
                'filtered': stats.get('filtered', 0),
                'detected': heap_detected,
                'fp_reducer_applied': fp_reduced,
                'fp_reducer_reason': fp_reason,
                'detected_after_fp_reducer': heap_detected and not fp_reduced,
            }
        except Exception as e:
            result['detections']['heap'] = {'error': str(e)[:100]}

# 格式串检测
        try:
            from analysis.fmt_constraint_solver import (
                analyze_format_calls, FmtRisk, score_exploitability)
            calls = analyze_format_calls(code)
            risky = [c for c in calls if c.risk.value >= FmtRisk.MEDIUM.value]
            result['detections']['format_string'] = {
                'total_calls': len(calls),
                'risky_calls': len(risky),
                'max_risk': max((c.risk.value for c in calls), default=0),
                'max_score': max((score_exploitability(c) for c in calls), default=0),
                'detected': len(risky) > 0,
            }
        except Exception as e:
            result['detections']['format_string'] = {'error': str(e)[:100]}

# 整数溢出检测
        try:
            from analysis.int_overflow_vrf import (
                detect_integer_overflows, IntOverflowClass)
            overflows = detect_integer_overflows(code)
            definite = [o for o in overflows if o.overflow_class in
                       (IntOverflowClass.DEFINITE, IntOverflowClass.WRAP_TO_HEAP)]

# 有符号下溢补充检测
            from analysis.int_overflow_signed_idx import detect_signed_index_underflow
            underflow_findings = detect_signed_index_underflow(code)

            result['detections']['integer_overflow'] = {
                'total': len(overflows) + len(underflow_findings),
                'definite': len(definite) + len(underflow_findings),
                'possible': len(overflows) - len(definite),
                'underflow': len(underflow_findings),
                'detected': len(overflows) > 0 or len(underflow_findings) > 0,
            }
        except Exception as e:
            result['detections']['integer_overflow'] = {'error': str(e)[:100]}

# UAF检测 (深度统一: VRF + Realloc + InterProc)
        try:
            from analysis.uaf_deep_unified import analyze_uaf_deep
            uaf = analyze_uaf_deep(code, 'main')
            result['detections']['uaf'] = {
                'total': uaf['total'],
                'confirmed': uaf['confirmed'],
                'likely': uaf['likely'],
                'filtered': uaf.get('filtered', 0),
                'detected': uaf['detected'],
                'interproc': uaf.get('interproc_count', 0),
                'realloc': uaf.get('realloc_count', 0),
            }
        except Exception as e:
            result['detections']['uaf'] = {'error': str(e)[:100]}

        result['duration_ms'] = round((time.perf_counter() - t0) * 1000, 1)
        all_results.append(result)

        # 简要输出
        heap_ok = result['detections'].get('heap', {}).get('detected', False)
        fmt_ok = result['detections'].get('format_string', {}).get('detected', False)
        int_ok = result['detections'].get('integer_overflow', {}).get('detected', False)
        uaf_ok = result['detections'].get('uaf', {}).get('detected', False)
        print(f"{dirname:45s} type={vuln_type:18s} H={heap_ok} F={fmt_ok} I={int_ok} U={uaf_ok} "
              f"({result['duration_ms']:.0f}ms)")

# 汇总统计
    for r in all_results:
        vt = r['type']
        if vt not in type_stats:
            type_stats[vt] = {'total': 0, 'heap': 0, 'fmt': 0, 'int_ovf': 0, 'uaf': 0,
                              'heap_after_fp_reducer': 0}
        type_stats[vt]['total'] += 1
        h = r['detections'].get('heap', {})
        if h.get('detected'):
            type_stats[vt]['heap'] += 1
        if h.get('detected_after_fp_reducer'):
            type_stats[vt]['heap_after_fp_reducer'] += 1
        if r['detections'].get('format_string', {}).get('detected'):
            type_stats[vt]['fmt'] += 1
        if r['detections'].get('integer_overflow', {}).get('detected'):
            type_stats[vt]['int_ovf'] += 1
        if r['detections'].get('uaf', {}).get('detected'):
            type_stats[vt]['uaf'] += 1

    summary = {
        'total_samples': len(all_results),
        'type_stats': type_stats,
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
    }

    # 输出 JSON
    results_path = os.path.join(output_dir, 'unified_benchmark_results.json')
    with open(results_path, 'w', encoding='utf-8') as f:
        json.dump({'summary': summary, 'results': all_results}, f, indent=2)

    # 输出摘要
    print(f"\n=== Unified Benchmark Summary ===")
    print(f"  {'Type':20s}  {'n':>3s}  {'heap_before':>10s}  {'heap_after':>10s}  "
          f"{'fmt':>5s}  {'int_ovf':>7s}  {'uaf':>5s}")
    for vt, ts in sorted(type_stats.items()):
        h_before = ts['heap'] / max(1, ts['total']) * 100
        h_after = ts.get('heap_after_fp_reducer', ts['heap']) / max(1, ts['total']) * 100
        f_rate = ts['fmt'] / max(1, ts['total']) * 100
        i_rate = ts['int_ovf'] / max(1, ts['total']) * 100
        u_rate = ts['uaf'] / max(1, ts['total']) * 100
        reduction = h_before - h_after
        print(f"  {vt:20s}: n={ts['total']:3d}  {h_before:5.1f}%→{h_after:5.1f}% "
              f"({reduction:+.1f}%)  fmt={f_rate:5.1f}%  int={i_rate:5.1f}%  uaf={u_rate:5.1f}%")

    print(f"\nResults: {results_path}")
    return summary


if __name__ == '__main__':
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument('--samples', default=None)
    p.add_argument('--output', default=None)
    args = p.parse_args()
    run_triple_benchmark(args.samples, args.output)
