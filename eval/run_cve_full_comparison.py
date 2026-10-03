"""
CVE堆溢出多工具对比实验 — 在14个编译成功的CVE样本上运行:
  1. BinMind Full Pipeline (约束求解+后向值流+路径条件后向值流) — 源码分析
  2. Angr — CFG + 危险函数调用点
  3. Ghidra — headless分析
  4. QEMU — 用户模式执行

所有CVE样本ground truth = VULN (True).
输出: JSON / CSV / 图表 / LaTeX
"""
import os, sys, time
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
CVE_ROOT = os.path.join(BASE, 'samples', 'cve_heap_overflow')
EVAL_DIR = os.path.join(BASE, 'eval')
RESULTS_DIR = os.path.join(EVAL_DIR, 'results')

from eval.cve_full_comparison_tools import (
    run_binmind_pipeline, run_angr, run_ghidra, run_qemu, compute_metrics,
)
from eval.cve_full_comparison_chart import save_outputs


def main():
    print('=' * 72)
    print('CVE Heap Overflow: Multi-Tool Comparison (Full Pipeline)')
    print('=' * 72)

    samples = []
    for d in sorted(Path(CVE_ROOT).iterdir()):
        if not d.is_dir():
            continue
        c_files = list(d.glob('*.c'))
        if not c_files:
            continue
        name = d.name
        binname = name.replace('cve_', '')
        binpath = str(d / (binname + '.exe'))
        if not os.path.isfile(binpath):
            binpath = str(d / binname)
        if not os.path.isfile(binpath):
            continue
        samples.append({'name': name, 'src': str(c_files[0]), 'bin': binpath})

    print(f'\n{len(samples)} samples with compiled binaries')
    tools = ['BinMind-Full', 'Angr', 'Ghidra', 'QEMU']
    all_results = {t: [] for t in tools}

    for i, s in enumerate(samples):
        name = s['name']
        with open(s['src'], encoding='utf-8', errors='replace') as f:
            source = f.read()

        r1 = run_binmind_pipeline(source, name)
        r2 = run_angr(s['bin'], name)
        r3 = run_ghidra(s['bin'], name)
        r4 = run_qemu(s['bin'], name)

        all_results['BinMind-Full'].append(r1)
        all_results['Angr'].append(r2)
        all_results['Ghidra'].append(r3)
        all_results['QEMU'].append(r4)

        markers = ['!' if r1.get('detected') else ' ',
                    '!' if r2.get('detected') else ' ',
                    '!' if r3.get('detected') else ' ',
                    '!' if r4.get('detected') else ' ']
        print(f'  [{i+1:2d}/{len(samples)}] '
              f'BM={markers[0]} Angr={markers[1]} '
              f'Ghidra={markers[2]} QEMU={markers[3]} {name}')

    # 计算指标
    print(f'\n{"=" * 72}')
    print('Results')
    print(f'{"=" * 72}')
    header = (f'{"Tool":<18s} {"TP":>4s} {"FN":>4s} '
              f'{"Recall":>7s} {"Prec":>7s} {"F1":>7s} {"Avg ms":>8s}')
    print(header)
    print('-' * len(header))

    all_metrics = {}
    for tool in tools:
        m = compute_metrics(all_results[tool])
        all_metrics[tool] = m
        avg_ms = int(sum(r.get('duration_ms', 0) for r in all_results[tool])
                     / max(len(all_results[tool]), 1))
        print(f'{tool:<18s} {m["TP"]:>4d} {m["FN"]:>4d} '
              f'{m["recall"]:>6.1%} {m["precision"]:>6.1%} '
              f'{m["f1"]:>7.4f} {avg_ms:>7d}')

    # 保存输出
    ts = time.strftime('%Y%m%d_%H%M%S')
    save_outputs(all_metrics, all_results, ts, samples, RESULTS_DIR)
    return all_metrics


if __name__ == '__main__':
    main()
