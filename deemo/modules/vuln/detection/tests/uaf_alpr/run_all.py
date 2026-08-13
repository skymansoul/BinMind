"""一键 UAF 回归: 生成样本 → 编译 → 扫描(plain/packed) → 汇总指标.

创建: 2024-12-09
用法:
  python run_all.py [--gcc <path>]
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def step(cmd, desc: str) -> None:
    print(f'\n=== {desc} ===')
    subprocess.run([sys.executable] + cmd, cwd=_HERE)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--gcc', default='')
    args = ap.parse_args()
    samples = _HERE / 'samples'
    gcc = ['--gcc', args.gcc] if args.gcc else []

    step([str(_HERE / 'gen_uaf_samples.py'), str(samples)], '1/4 生成样本集')
    step([str(_HERE / 'compile_samples.py'), str(samples)] + gcc,
         '2/4 编译样本')
    for objs in ('plain', 'packed'):
        out = 'results_' + objs
        step([str(_HERE / 'scan_runner.py'), str(samples),
              '--objs', objs, '--out', out], f'3/4 扫描 {objs}')
        step([str(_HERE / 'collect_results.py'), str(samples),
              '--results', out], f'4/4 汇总 {objs}')

    rep = json.loads((_HERE / 'results_plain' / 'report.json')
                     .read_text(encoding='utf-8'))
    print('\n==== ALPR vs 基线 (O0 产物) ====')
    print(json.dumps({'baseline': rep['baseline'], 'alpr': rep['alpr'],
                      'fp_reduction_pct': rep['fp_reduction_pct']},
                     ensure_ascii=False, indent=2))


if __name__ == '__main__':
    main()
