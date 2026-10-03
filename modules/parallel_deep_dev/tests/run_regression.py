"""一键回归测试入口 — 编译 → 扫描 → 收集对比。

用法: python tests/run_regression.py [--class heap|uaf]
                      [--skip-build] [--workers N]
输出: 每样本检出/漏报/误报状态与耗时, 汇总指标。
"""

import argparse
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    ap.add_argument('--skip-build', action='store_true')
    ap.add_argument('--workers', type=int, default=4)
    args = ap.parse_args()

    t_all = time.time()
    if not args.skip_build:
        print(f'=== [1/3] 编译样本 ({args.sample_class}) ===')
        from build_samples import build_all
        build_all(args.sample_class)
    else:
        print('=== [1/3] 跳过编译 ===')

    print(f'\n=== [2/3] 扫描样本 ({args.sample_class}) ===')
    from scan_scheduler import scan_all
    results = scan_all(args.sample_class, max_workers=args.workers)

    print('\n=== [3/3] 收集与对比 ===')
    from collect_results import compute_metrics, write_artifacts
    from .backends import load_detectors
    _, _, tool = load_detectors(args.sample_class)
    metrics = compute_metrics(results)
    write_artifacts(results, metrics, args.sample_class, tool)

    print(f'\n{"="*64}')
    print(f'回归结果汇总 ({args.sample_class})')
    print(f'{"="*64}')
    for name, m in sorted(metrics.items()):
        print(f'  {name:12s} Precision={m["precision"]:.4f} '
              f'Recall={m["recall"]:.4f} F1={m["f1"]:.4f} '
              f'FPR={m["fpr"]:.4f} '
              f'({m["tp"]}T/{m["fp"]}F/{m["tn"]}N/{m["fn"]}Fn) '
              f'avg={m["avg_ms"]}ms')
    main_tool = metrics.get(tool)
    base_tool = metrics.get('Baseline')
    if main_tool and base_tool and base_tool['fpr'] > 0:
        red = (1 - main_tool['fpr'] / base_tool['fpr']) * 100
        print(f'\n  FPR 削减: {base_tool["fpr"]:.4f} → '
              f'{main_tool["fpr"]:.4f} ({red:.1f}%)')
    print(f'  总耗时: {time.time()-t_all:.1f}s')
    print(f'  汇总: {Path("tests") / "regression_results.json"}')
    print(f'{"="*64}')
    return 0


if __name__ == '__main__':
    sys.exit(main())
