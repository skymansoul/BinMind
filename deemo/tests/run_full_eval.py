# 全自动评估流水线 —— 编译→扫描→统计→对比, 一键运行。
# 用法: python tests/run_full_eval.py
import os, sys, json, time
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

def main():
    print('='*60)
    print('BinMind 全自动评估流水线')
    print('='*60)

    # 阶段1: 编译
    print('[1/4] Compiling samples...')
    from tests.compile_samples import compile_all
    bins = compile_all()
    ok = sum(1 for v in bins.values() if isinstance(v, dict) and v.get('success'))
    total = len([v for v in bins.values() if isinstance(v, dict)])
    print(f'  Compiled: {ok}/{total}')

    # 阶段2: 扫描
    print('[2/4] Running scans...')
    from tests.run_scanner import run_all as scan_all
    results = scan_all(bins, timeout_sec=120)
    print(f'  Scanned: {len(results)} samples')

    # 阶段3: 统计
    print('[3/4] Collecting results...')
    from tests.collect_results import collect, print_summary
    report = collect(results)
    print_summary(report)

    # 阶段4: 保存
    with open(os.path.join(os.path.dirname(__file__), 'full_eval_report.json'), 'w') as f:
        json.dump(report, f, indent=2, ensure_ascii=False)
    print(f'[4/4] Report saved to tests/full_eval_report.json')
    return report

if __name__ == '__main__':
    main()
