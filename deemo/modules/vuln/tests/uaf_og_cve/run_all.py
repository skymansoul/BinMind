"""UAF-OG 一键回归入口 — 编译 → 扫描 → 收集.

  - 串联三个独立模块, 产物落盘 tests/uaf_og_cve/out/.
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
    print((proc.stdout + proc.stderr)[-3000:])
    return proc.returncode


def main():
    ap = argparse.ArgumentParser(description='UAF-OG 一键回归')
    ap.add_argument('--skip-compile', action='store_true')
    args = ap.parse_args()
    if not args.skip_compile:
        run('compile_samples.py', '--json', str(_OUT / 'compile.json'))
    run('scan_scheduler.py', '--json', str(_OUT / 'scan_results.json'))
    run('result_collector.py', str(_OUT / 'scan_results.json'),
        '--json', str(_OUT / 'eval_report.json'),
        '--csv', str(_OUT / 'eval_report.csv'))
    report = json.loads((_OUT / 'eval_report.json').read_text(encoding='utf-8'))
    print('\n' + '=' * 60)
    print(f"BASE   : {report['base']}")
    print(f"UAF-OG : {report['og']}")
    print(f"误报降低: {report['fp_reduction_pct']}%  "
          f"召回变化: {report['recall_delta']}")
    print('=' * 60)
    return 0


if __name__ == '__main__':
    sys.exit(main())
