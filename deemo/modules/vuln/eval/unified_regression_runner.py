"""统一回归测试入口 — 依次运行所有漏洞类型的回归套件.

创建: 2026-08-10
用途: 一键运行 HEAP + UAF + Format String + Integer Overflow 四个回归套件.
      汇总结果输出到 unified_regression_results.json.

使用: python unified_regression_runner.py [--quick] [--json PATH]
"""

import json
import subprocess
import sys
import time
from pathlib import Path

_HERE = Path(__file__).resolve().parent

SUITES = [
    {
        'type': 'heap_overflow',
        'module': 'vuln.test_samples.heap_overflow.regression_suite',
        'script': _HERE.parent / 'test_samples' / 'heap_overflow'
                 / 'regression_suite.py',
    },
    {
        'type': 'uaf',
        'module': 'vuln.detection.src.uaf.uaf_regression_runner',
        'script': _HERE.parent / 'detection' / 'src' / 'uaf'
                 / 'uaf_regression_runner.py',
    },
    {
        'type': 'format_string',
        'module': 'vuln.detection.src.format.fmt_regression_runner',
        'script': _HERE.parent / 'detection' / 'src' / 'format'
                 / 'fmt_regression_runner.py',
    },
    {
        'type': 'integer_overflow',
        'module': 'vuln.detection.src.int_overflow.int_regression_runner',
        'script': _HERE.parent / 'detection' / 'src' / 'int_overflow'
                 / 'int_regression_runner.py',
    },
]


def run_suite(suite: dict, quick: bool) -> dict:
    """运行单个回归套件, 返回汇总字典."""
    script = suite['script']
    if not script.exists():
        return {'type': suite['type'], 'error': f'script not found: {script}'}

    cmd = [sys.executable, str(script)]
    if quick:
        cmd.append('--quick')

    t0 = time.perf_counter()
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=120,
                      cwd=str(script.parent))
    elapsed = time.perf_counter() - t0

    return {
        'type': suite['type'],
        'returncode': r.returncode,
        'stdout': r.stdout[-2000:] if len(r.stdout) > 2000 else r.stdout,
        'stderr': r.stderr[-500:] if len(r.stderr) > 500 else r.stderr,
        'elapsed_s': round(elapsed, 2),
    }


def parse_metrics(stdout: str) -> dict:
    """从 stdout 中解析 TP/TN/FP/FN/Precision/Recall/F1."""
    import re
    metrics = {}
    m = re.search(r'TP=(\d+)\s+TN=(\d+)\s+FP=(\d+)\s+FN=(\d+)', stdout)
    if m:
        metrics.update({'tp': int(m.group(1)), 'tn': int(m.group(2)),
                       'fp': int(m.group(3)), 'fn': int(m.group(4))})
    m = re.search(r'Precision=([\d.]+)%', stdout)
    if m:
        metrics['precision'] = float(m.group(1)) / 100
    m = re.search(r'Recall=([\d.]+)%', stdout)
    if m:
        metrics['recall'] = float(m.group(1)) / 100
    m = re.search(r'F1=([\d.]+)', stdout)
    if m:
        metrics['f1'] = float(m.group(1))
    return metrics


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Unified Multi-Type Regression Runner')
    ap.add_argument('--quick', action='store_true', help='Skip compilation')
    ap.add_argument('--type', type=str, default=None,
                   help='Run only one type (heap_overflow/uaf/format_string/integer_overflow)')
    ap.add_argument('--json', type=str, default=None,
                   help='Output JSON path for unified results')
    args = ap.parse_args()

    suites = SUITES if not args.type else \
        [s for s in SUITES if s['type'] == args.type]

    if not suites:
        print(f'Unknown type: {args.type}')
        return

    all_results = {}
    grand_tp = grand_tn = grand_fp = grand_fn = 0

    for suite in suites:
        print(f'\n{"="*60}')
        print(f'Running {suite["type"]} regression...')
        print(f'{"="*60}')
        result = run_suite(suite, args.quick)
        print(result['stdout'])
        if result['stderr']:
            print(f'STDERR: {result["stderr"]}')

        metrics = parse_metrics(result['stdout'])
        result['metrics'] = metrics
        all_results[suite['type']] = result

        if metrics:
            grand_tp += metrics.get('tp', 0)
            grand_tn += metrics.get('tn', 0)
            grand_fp += metrics.get('fp', 0)
            grand_fn += metrics.get('fn', 0)

    # 汇总
    total = grand_tp + grand_tn + grand_fp + grand_fn
    macro_precision = grand_tp / max(1, grand_tp + grand_fp)
    macro_recall = grand_tp / max(1, grand_tp + grand_fn)
    macro_f1 = (2 * macro_precision * macro_recall
                / max(0.001, macro_precision + macro_recall))

    print(f'\n{"="*60}')
    print(f'UNIFIED REGRESSION SUMMARY')
    print(f'{"="*60}')
    print(f'  Total samples: {total}')
    print(f'  Grand TP={grand_tp}  TN={grand_tn}  FP={grand_fp}  FN={grand_fn}')
    print(f'  Macro Precision={macro_precision:.1%}  '
          f'Recall={macro_recall:.1%}  F1={macro_f1:.3f}')

    unified = {
        'grand_totals': {
            'tp': grand_tp, 'tn': grand_tn, 'fp': grand_fp, 'fn': grand_fn,
            'precision': round(macro_precision, 4),
            'recall': round(macro_recall, 4),
            'f1': round(macro_f1, 4),
        },
        'per_type': all_results,
    }

    out_file = _HERE / 'unified_regression_results.json'
    out_file.write_text(json.dumps(unified, indent=2, ensure_ascii=False))
    print(f'Saved: {out_file}')

    if args.json:
        json_path = Path(args.json)
        json_path.parent.mkdir(parents=True, exist_ok=True)
        json_path.write_text(json.dumps(unified, indent=2, ensure_ascii=False))


if __name__ == '__main__':
    main()
