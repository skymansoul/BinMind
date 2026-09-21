"""一键回归: 生成样本 → 编译 → 扫描 → 汇总指标.

创建: 2025-05-12
用法:
  python run_all.py [--gcc D:/mingw64/bin/gcc] [--objs bin/plain]
覆盖 O0/O2 两档产物, 输出 report.json/report.csv。

自动推进机制:
  - 生成样本(已存在则跳过)
  - 编译(无 gcc 则告警继续)
  - 扫描(O0 与 O2 各自独立扫描)
  - 汇总并打印对照指标
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def step(cmd, desc: str) -> int:
    print(f'\n=== {desc} ===')
    proc = subprocess.run([sys.executable] + cmd, cwd=_HERE)
    return proc.returncode


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--gcc', default='')
    ap.add_argument('--samples', default='samples')
    args = ap.parse_args()

    samples = _HERE / args.samples

    step([str(_HERE / 'gen_alloc_capacity_samples.py'), str(samples)],
         '1/4 生成样本集')
    gcc_cmd = ['--gcc', args.gcc] if args.gcc else []
    step([str(_HERE / 'compile_samples.py'), str(samples)] + gcc_cmd,
         '2/4 编译样本 (O0)')

    for objs in ('plain', 'packed'):
        out = 'results_' + objs
        step([str(_HERE / 'scan_runner.py'), str(samples),
              '--objs', objs, '--out', out],
             f'3/4 扫描 {objs}')
        step([str(_HERE / 'collect_results.py'), str(samples),
              '--results', out],
             f'4/4 汇总 {objs}')

    # 打印主结果 (plain/O0)
    rep = json.loads(
        (_HERE / 'results_plain' / 'report.json').read_text(encoding='utf-8'))
    print('\n==== ACPE vs 基线 (O0 产物) ====')
    print(json.dumps({
        'baseline': rep['baseline'],
        'acpe': rep['acpe'],
        'fp_reduction_pct': rep['fp_reduction_pct'],
        'alert_reduction_pct': rep['alert_reduction_pct'],
    }, ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
