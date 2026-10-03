# coding: utf-8
"""堆 CVE 回归一键入口 — 编译 → 扫描 → 收集对比 → 报告.

用法:
  python run_heap_regression.py                    # 全流程
  python run_heap_regression.py --skip-compile     # 跳过编译
  python run_heap_regression.py --out-dir results

输出: build_report.json, scan_results.json, regression_report.md/csv/json
指标: TP/FP/TN/FN, Precision/Recall/F1, FP rate, 逐层 FP 削减, 平均耗时
"""

import json, os, sys, time, argparse, csv
from pathlib import Path

_THIS = Path(__file__).resolve().parent
_DEEMO = _THIS.parent.parent.parent.parent   # regression → tests → core → modules → deemo
_CORE = _THIS.parent.parent
for p in (_DEEMO, _CORE, _THIS):
    if str(p) not in sys.path:
        sys.path.insert(0, str(p))

from tests.regression.compile_heap_samples import compile_all, OUT_EXT  # noqa: E402
from tests.regression.run_scanner import ScanResult, scan_elf_deep       # noqa: E402
from tests.regression.collect_results import collect, load_ground_truth  # noqa: E402


def find_binaries(root: str) -> list:
    """查找所有已编译二进制."""
    out = []
    build = os.path.join(root, 'build')
    if os.path.isdir(build):
        for f in sorted(os.listdir(build)):
            if f.endswith(OUT_EXT):
                out.append(os.path.join(build, f))
    return out


def scan_all_deep(binary_paths: list) -> list:
    """批量深度扫描, 返回含逐层统计的 ScanResult 列表."""
    results = []
    for i, path in enumerate(binary_paths):
        print(f'[{i+1}/{len(binary_paths)}] scan {os.path.basename(path)} ...',
              end=' ', flush=True)
        r = scan_elf_deep(path)
        status = (f'OK cand={len(r.candidates)} '
                  f'({r.wall_time_ms:.0f}ms)' if r.success
                  else f'FAIL: {r.error[:80]}')
        print(status)
        results.append(r)
    return results


def layer_reduction_summary(results: list) -> dict:
    """汇总各层累计过滤统计."""
    layers = {}
    for r in results:
        if not r.success:
            continue
        for s in r.layer_stats:
            layers.setdefault(s['name'], {'input': 0, 'retained': 0})
            layers[s['name']]['input'] += s['input']
            layers[s['name']]['retained'] += s['retained']
    return layers


def fp_reduction_vs_baseline(results: list, gt: dict) -> dict:
    """对比 L0 基线候选与最终候选的 FP 削减 (统计安全样本的误报)."""
    baseline_fp = 0
    final_fp = 0
    for r in results:
        expected = gt.get(r.sample_id, False)
        if expected:
            continue  # 只统计安全样本 (ground truth 标注非漏洞)
        l0 = next((s['retained'] for s in r.layer_stats
                   if s['name'] == 'L0_baseline'), 0)
        if l0 > 0:
            baseline_fp += 1
        if len(r.candidates) > 0:
            final_fp += 1
    return {
        'baseline_fp_samples': baseline_fp,
        'final_fp_samples': final_fp,
        'fp_reduction_rate': (1 - final_fp / max(1, baseline_fp)),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--samples-root', default=str(_CORE / 'tests' / 'cve_samples'))
    ap.add_argument('--out-dir', default=str(_THIS / 'output'))
    ap.add_argument('--skip-compile', action='store_true')
    ap.add_argument('--format', default='markdown',
                    choices=['markdown', 'csv', 'json'])
    args = ap.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    print('=' * 64)
    print('HEAP CVE REGRESSION (real-binary deep pipeline)')
    print(f'  samples: {args.samples_root}')
    print(f'  output : {args.out_dir}')
    print('=' * 64)

    # 编译
    build_json = os.path.join(args.out_dir, 'build_report.json')
    if not args.skip_compile:
        print('\nCompiling samples ...')
        summary = compile_all(args.samples_root, output_json=build_json)
        print(f'  built {summary["success"]}/{summary["total"]} '
              f'(failed={summary["failed"]})')
        binaries = summary['elf_paths']
    else:
        summary = json.load(open(build_json, encoding='utf-8'))
        binaries = find_binaries(args.samples_root)
    if not binaries:
        print('ERROR: no binaries. Run without --skip-compile.')
        sys.exit(1)

    # 扫描
        print(f'\nScanning {len(binaries)} binaries ...')
    t0 = time.perf_counter()
    scan_results = scan_all_deep(binaries)
    scan_output = {
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
        'total': len(scan_results),
        'results': [
            {'sample_id': r.sample_id, 'success': r.success,
             'candidates': len(r.candidates),
             'exploitable': sum(1 for c in r.candidates
                                if c.get('exploitable')),
             'wall_time_ms': r.wall_time_ms, 'error': r.error,
             'layer_stats': r.layer_stats}
            for r in scan_results
        ],
    }
    with open(os.path.join(args.out_dir, 'scan_results.json'), 'w',
              encoding='utf-8') as f:
        json.dump(scan_output, f, indent=2, default=str)

    # 收集对比
        print('\nCollecting vs ground truth ...')
    gt_path = os.path.join(args.samples_root, 'ground_truth.json')
    report = collect(scan_output['results'], gt_path)

    layers = layer_reduction_summary(scan_results)
    gt = load_ground_truth(gt_path)
    fp_red = fp_reduction_vs_baseline(scan_results, gt)

    if args.format == 'markdown':
        text = report_to_markdown(report, layers, fp_red)
        ext = '.md'
    elif args.format == 'csv':
        text = report_to_csv(report)
        ext = '.csv'
    else:
        text = json.dumps({
            'summary': {'tp': report.tp, 'fp': report.fp, 'tn': report.tn,
                        'fn': report.fn, 'precision': report.precision,
                        'recall': report.recall, 'f1': report.f1,
                        'fp_rate': report.fp_rate},
            'fp_reduction_vs_baseline': fp_red,
            'layer_stats': layers,
        }, indent=2, ensure_ascii=False)
        ext = '.json'
    report_path = os.path.join(args.out_dir, f'heap_regression{ext}')
    with open(report_path, 'w', encoding='utf-8') as f:
        f.write(text)

    print('\n' + '=' * 64)
    print('RESULT')
    print('=' * 64)
    print(f'  TP={report.tp}  FP={report.fp}  TN={report.tn}  FN={report.fn}')
    print(f'  Precision={report.precision:.1%}  Recall={report.recall:.1%}  '
          f'F1={report.f1:.3f}')
    print(f'  FP rate={report.fp_rate:.1%}  '
          f'FP reduction vs L0={fp_red["fp_reduction_rate"]:.1%}')
    print(f'  Avg time={report.avg_time_ms:.1f}ms')
    print(f'\nReport: {report_path}')

    sys.exit(0 if (report.fn == 0 and report.fp == 0) else 1)


def report_to_markdown(report, layers: dict, fp_red: dict) -> str:
    lines = [
        '# Heap CVE Regression Report (real binary)',
        '',
        '## Summary',
        '',
        '| Metric | Value |',
        '|--------|-------|',
        f'| Total Samples | {report.total} |',
        f'| True Positives | {report.tp} |',
        f'| False Positives | {report.fp} |',
        f'| True Negatives | {report.tn} |',
        f'| False Negatives | {report.fn} |',
        f'| Precision | {report.precision:.2%} |',
        f'| Recall | {report.recall:.2%} |',
        f'| F1 Score | {report.f1:.3f} |',
        f'| FP Rate | {report.fp_rate:.2%} |',
        f'| FP Reduction vs L0 | {fp_red["fp_reduction_rate"]:.2%} |',
        f'| Avg Time/Scan | {report.avg_time_ms:.1f}ms |',
        '',
        '## Layer Filtering (cumulative)',
        '',
        '| Layer | Input | Retained | Filtered |',
        '|-------|-------|----------|----------|',
    ]
    for name, st in layers.items():
        lines.append(f'| {name} | {st["input"]} | {st["retained"]} | '
                     f'{st["input"] - st["retained"]} |')
    lines += ['', '## Per-Sample Results', '',
              '| Sample | Expected | Detected | Verdict | Candidates | '
              'Time(ms) |', '|--------|----------|----------|---------|'
              '-----------|---------|']
    for v in report.samples:
        lines.append(f'| {v.sample_id} | {v.expected} | {v.detected} | '
                     f'{v.verdict} | {v.candidates} | {v.wall_time_ms:.0f} |')
    return '\n'.join(lines)


def report_to_csv(report) -> str:
    lines = ['sample_id,expected,detected,verdict,candidates,time_ms']
    for v in report.samples:
        lines.append(f'{v.sample_id},{v.expected},{v.detected},{v.verdict},'
                     f'{v.candidates},{v.wall_time_ms:.0f}')
    return '\n'.join(lines)


if __name__ == '__main__':
    main()
