"""一键回归入口 — 编译 → 扫描 → 收集 → 汇总报告.

  - 串联三个独立模块, 各自产物落盘, 便于单独重跑.
  - --quick 跳过重编译, --no-scan 仅生成报告.
"""

import argparse
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent
_OUT = _HERE / 'out'
_OUT.mkdir(exist_ok=True)


def run(script: str, *args: str, timeout: int = 300) -> int:
    cmd = [sys.executable, str(_HERE / script)] + list(args)
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    tail = (proc.stdout + proc.stderr)[-3000:]
    print(tail)
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description='ACFPC 一键回归')
    ap.add_argument('--quick', action='store_true')
    ap.add_argument('--no-scan', action='store_true')
    ap.add_argument('--timeout', type=int, default=60)
    args = ap.parse_args()

    if not args.no_scan:
        rc = run('compile_samples.py', *(('--quick',) if args.quick else ()),
                 '--json', str(_OUT / 'compile.json'))
        if rc != 0:
            print('编译存在失败, 继续扫描可用样本')
        rc = run('scan_scheduler.py', '--timeout', str(args.timeout),
                 '--json', str(_OUT / 'scan_results.json'))
        if rc != 0:
            print('扫描异常')
    else:
        print('跳过扫描, 复用既有结果')

    rc = run('result_collector.py', str(_OUT / 'scan_results.json'),
             '--json', str(_OUT / 'eval_report.json'),
             '--csv', str(_OUT / 'eval_report.csv'))
    report = json.loads((_OUT / 'eval_report.json').read_text(encoding='utf-8'))
    print('\n' + '=' * 64)
    print(f"BASE  : {report['base']}")
    print(f"ACFPC : {report['acfpc']}")
    print(f"误报降低: {report['fp_reduction_pct']}%  "
          f"召回变化: {report['recall_delta']}")
    print('=' * 64)
    return 0


if __name__ == '__main__':
    sys.exit(main())
