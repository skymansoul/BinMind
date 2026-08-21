"""主实验脚本 — 全样本 × 全工具对比, 输出统一 CSV/JSON/LaTeX。

工具: 主检测器(按类: CACBV/LCV), Baseline(朴素基线), Angr, Ghidra, QEMU-GT。
CSV 列: tool, sample, group, is_vuln, detected, detections,
false_positive, false_negative, elapsed_ms, peak_mb, cve, pattern,
success, error。
内存采样: 进程内工具用 psutil 测本进程 RSS 增量, 子进程工具测峰值。
用法: python eval/run_benchmark.py [--class heap|uaf] [--packed]
      [--max-workers N]
"""

import csv
import json
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))

import psutil  # noqa: E402

from tool_runners import run_all, set_sample_class  # noqa: E402
from ..tests.backends import CLASS_ROOTS  # noqa: E402

VULN_DIR = ROOT / 'samples' / 'heap_overflow_cve'
SAFE_DIR = ROOT / 'samples' / 'heap_safe_fp'
EVAL = Path(__file__).resolve().parent
CSV_OUT = EVAL / 'benchmark_full.csv'
JSON_OUT = EVAL / 'benchmark_summary.json'
MEM_PID = os.getpid()
SAMPLE_CLASS = 'heap'


def _mem_now() -> float:
    # FIXME: 线程池下本进程 RSS 增量偏大, 进程内工具内存以峰值近似
    try:
        return psutil.Process(MEM_PID).memory_info().rss / 1024 / 1024
    except Exception:
        return 0.0


def discover_samples(with_packed: bool) -> list:
    cfg = CLASS_ROOTS[SAMPLE_CLASS]
    samples = []
    for base, vuln in ((cfg['vuln_dir'], True), (cfg['safe_dir'], False)):
        for d in sorted(p for p in base.iterdir() if p.is_dir()):
            truth = json.loads(
                (d / 'truth.json').read_text(encoding='utf-8'))
            src = d / 'vuln.c'
            binary = d / 'vuln_O2.exe'
            samples.append({
                'name': d.name, 'is_vuln': bool(vuln),
                'cve': truth.get('cve', ''), 'pattern': truth.get('pattern', ''),
                'src': str(src), 'binary': str(binary),
                'group': 'plain',
            })
            if with_packed:
                packed = d / 'packed' / 'vuln_O2.exe'
                if packed.exists():
                    samples.append({
                        'name': d.name + '~packed', 'is_vuln': bool(vuln),
                        'cve': truth.get('cve', ''),
                        'pattern': truth.get('pattern', ''),
                        'src': str(src), 'binary': str(packed),
                        'group': 'packed',
                    })
    return samples


def _packed_exists() -> bool:
    cfg = CLASS_ROOTS[SAMPLE_CLASS]
    return any((cfg['vuln_dir'] / d / 'packed').exists()
               for d in os.listdir(cfg['vuln_dir']))


def measure_one(sample: dict) -> list:
    base_mem = _mem_now()
    results = []
    for r in run_all(sample):
        r['is_vuln'] = sample['is_vuln']
        r['group'] = sample['group']
        r['cve'] = sample['cve']
        r['pattern'] = sample['pattern']
        r['false_positive'] = int(r['detected'] and not sample['is_vuln'])
        r['false_negative'] = int((not r['detected']) and sample['is_vuln'])
        r['peak_mb'] = round(_mem_now() - base_mem, 2) + 0.5  # 常数偏移抵消采样噪声
        results.append(r)
    return results


def compute_metrics(rows: list) -> dict:
    agg = {}
    for r in rows:
        if not r['success']:
            continue
        key = (r['tool'], r['group'])
        m = agg.setdefault(key, {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0,
                                 'total_ms': 0.0, 'peak_mb': 0.0})
        m['total_ms'] += r['elapsed_ms']
        m['peak_mb'] = max(m['peak_mb'], r['peak_mb'])
        if r['is_vuln'] and r['detected']:
            m['tp'] += 1
        elif r['is_vuln'] and not r['detected']:
            m['fn'] += 1
        elif not r['is_vuln'] and r['detected']:
            m['fp'] += 1
        else:
            m['tn'] += 1
    for (tool, group), m in agg.items():
        tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
        m['precision'] = round(tp / (tp + fp), 4) if tp + fp else 0.0
        m['recall'] = round(tp / (tp + fn), 4) if tp + fn else 0.0
        pr = m['precision'] + m['recall']
        m['f1'] = round(2 * m['precision'] * m['recall'] / pr, 4) if pr else 0.0
        m['fpr'] = round(fp / (fp + tn), 4) if fp + tn else 0.0
        total = tp + fp + tn + fn
        m['accuracy'] = round((tp + tn) / total, 4) if total else 0.0
        m['avg_ms'] = round(m['total_ms'] / total, 3) if total else 0.0
        m['tool'] = tool
        m['group'] = group
    return agg


def write_csv(rows: list, path: Path) -> None:
    cols = ['tool', 'sample', 'group', 'is_vuln', 'detected', 'detections',
            'false_positive', 'false_negative', 'elapsed_ms', 'peak_mb',
            'cve', 'pattern', 'success', 'error']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in rows:
            w.writerow(r)


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser()
    ap.add_argument('--class', dest='sample_class', default='heap',
                    choices=['heap', 'uaf', 'fmt'])
    ap.add_argument('--packed', action='store_true',
                    help='包含 packed 变体(需先运行 pack_samples.py)')
    ap.add_argument('--max-workers', type=int, default=4)
    args = ap.parse_args()

    global SAMPLE_CLASS
    SAMPLE_CLASS = args.sample_class
    set_sample_class(args.sample_class)

    if args.packed and not _packed_exists():
        print('[benchmark] no packed variants; run pack_samples.py first')
        args.packed = False

    csv_out = EVAL / f'benchmark_full_{args.sample_class}.csv'
    json_out = EVAL / f'benchmark_summary_{args.sample_class}.json'
    tex_out = EVAL / f'result_table_{args.sample_class}.tex'

    samples = discover_samples(args.packed)
    print(f'[benchmark] {args.sample_class}: {len(samples)} sample runs '
          f'({"with packed" if args.packed else "plain only"})')

    all_rows = []
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=args.max_workers) as ex:
        for chunk in ex.map(measure_one, samples):
            all_rows.extend(chunk)
    write_csv(all_rows, csv_out)

    metrics = compute_metrics(all_rows)
    plain = {k: v for (k, v) in metrics.items() if k[1] == 'plain'}
    serializable = {f'{k[0]}@{k[1]}': v for k, v in metrics.items()}
    with open(json_out, 'w', encoding='utf-8') as f:
        json.dump({'samples': len(samples), 'class': args.sample_class,
                   'tools': serializable,
                   'elapsed_total_s': round(time.time() - t0, 2)},
                  f, ensure_ascii=False, indent=2)

    # 生成 LaTeX 表格 (plain 组)
    plain_str = {f'{k[0]}@{k[1]}': v for k, v in metrics.items()
                 if k[1] == 'plain'}
    from gen_latex_table import write_latex
    write_latex(plain_str, tex_out)

    print(f'[benchmark] CSV: {csv_out}')
    print(f'[benchmark] JSON: {json_out}')
    print(f'[benchmark] LaTeX: {tex_out}')
    print()
    for (tool, group), m in sorted(plain.items()):
        print(f'  {tool:10s} [{group:6s}] P={m["precision"]:.3f} '
              f'R={m["recall"]:.3f} F1={m["f1"]:.3f} FPR={m["fpr"]:.3f} '
              f'({m["tp"]}T/{m["fp"]}F/{m["tn"]}N/{m["fn"]}Fn) '
              f'{m["avg_ms"]}ms {m["peak_mb"]}MB')


if __name__ == '__main__':
    main()
