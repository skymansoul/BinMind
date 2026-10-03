"""堆溢出回归测试套件 — 一键编译→扫描→收集→报告.

创建: 2024-09-02
用途: compile → scan → collect 全流程, 单条命令执行完整回归测试.

运行模式:
  python regression_suite.py          # 全流程
  python regression_suite.py --quick  # 跳过编译 (已有二进制)
  python regression_suite.py --clean  # 清理编译产物
  python regression_suite.py --report # 仅生成报告 (需要已有 scan_results.json)
"""

import os
import sys
import json
import time
import subprocess
from pathlib import Path


SAMPLE_DIR = Path(__file__).resolve().parent


def run_step(name: str, script: str, args: list = None) -> bool:
    """执行单个回归步骤."""
    script_path = SAMPLE_DIR / script
    if not script_path.exists():
        print(f'  [SKIP] {script} not found')
        return False

    print(f'\n{"="*50}')
    print(f'  STEP: {name}')
    print(f'{"="*50}')
    cmd = [sys.executable, str(script_path)] + (args or [])
    r = subprocess.run(cmd, cwd=str(SAMPLE_DIR))
    return r.returncode == 0


def main():
    import argparse
    ap = argparse.ArgumentParser(
        description='Heap Overflow Regression Suite — One-Click Pipeline')
    ap.add_argument('--quick', action='store_true', help='Skip compilation')
    ap.add_argument('--clean', action='store_true', help='Clean build artifacts')
    ap.add_argument('--report', action='store_true', help='Generate report only')
    ap.add_argument('--json', type=str, default=None,
                    help='Copy results to specified JSON path for benchmark runner')
    args = ap.parse_args()

    t0 = time.perf_counter()

    if args.clean:
        print('Cleaning build artifacts...')
        run_step('Clean', 'compile_samples.py', ['--clean'])
        return

    report_only = args.report

    if report_only:
        run_step('Report', 'collect_results.py')
        # 不 return — 继续处理 --json 输出 (供 benchmark runner 使用)
    elif not args.quick:
        # 编译
        if not run_step('Compile samples', 'compile_samples.py'):
            print('Compilation failed — aborting.')
            return

    if not report_only:
        # 扫描
        if not run_step('Run scanner', 'run_scanner.py'):
            print('Scan failed — aborting.')
            return

        # 收集结果 + 报告
        run_step('Collect results', 'collect_results.py')

        elapsed = time.perf_counter() - t0
        print(f'\n{"="*50}')
        print(f'  Regression suite complete in {elapsed:.1f}s')
        print(f'{"="*50}')

    # 打印摘要
    results_file = SAMPLE_DIR / 'scan_results.json'
    if results_file.exists():
        r = json.loads(results_file.read_text(encoding='utf-8'))
        tp = r.get('tp', 0)
        tn = r.get('tn', 0)
        fp = r.get('fp', 0)
        fn = r.get('fn', 0)
        print(f'  TP={tp} TN={tn} FP={fp} FN={fn}  F1={r.get("f1", 0):.3f}')

        # 如果指定了 --json, 输出标准格式供 benchmark runner 使用
        if args.json:
            per_sample = r.get('per_sample', {})
            results_list = []
            for name, info in per_sample.items():
                results_list.append({
                    'sample_id': name,
                    'expected': info.get('expected', ''),
                    'verdict': info.get('verdict', ''),
                    'detected': info.get('detected', False),
                    'elapsed_sec': info.get('time_ms', 0) / 1000,
                    'n_findings': info.get('n_findings', 0),
                })
            benchmark_json = {
                'n_samples': len(per_sample),
                'metrics': {
                    'recall': r.get('recall', 0),
                    'precision': r.get('precision', 0),
                    'f1': r.get('f1', 0),
                    'tp': tp, 'tn': tn, 'fp': fp, 'fn': fn,
                    'avg_time_ms': r.get('avg_time_ms', 0),
                },
                'results': results_list,
            }
            json_path = Path(args.json)
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(json.dumps(benchmark_json, indent=2, ensure_ascii=False))
            print(f'Benchmark JSON saved: {json_path}')


if __name__ == '__main__':
    main()
