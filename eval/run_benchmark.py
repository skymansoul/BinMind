"""
统一多工具对比实验 — 对全部CVE样本调用BinMind/Angr/Ghidra, 输出CSV/JSON/LaTeX.
覆盖: 16 CVE堆溢出样本 + 15 cve_gapsbv 样本 + FP测试样本.
工具: BinMind-Full(源码级仿射边界验证-约束求解), BinMind-baseline(IR级), Angr, Ghidra.
输出: benchmark_full.csv, benchmark_summary.json, result_table.tex
"""
from __future__ import annotations
import csv, json, os, re, sys, time
from pathlib import Path
from typing import Any, Dict, List

EVAL_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.dirname(EVAL_DIR)


def discover_cve_samples() -> List[Dict]:
    """发现所有CVE样本目录(含源码和描述)."""
    samples = []
    roots = [
        ('heap_overflow', os.path.join(
            PROJECT_ROOT, 'tests', 'cve_samples', 'heap_overflow')),
        ('cve_heap', os.path.join(PROJECT_ROOT, 'samples', 'cve_heap_overflow')),
        ('cve_gapsbv', os.path.join(PROJECT_ROOT, 'samples', 'cve_gapsbv')),
        ('cve_general', os.path.join(PROJECT_ROOT, 'samples', 'cve')),
    ]
    seen = set()
    for category, root_dir in roots:
        if not os.path.isdir(root_dir):
            continue
        for entry in sorted(Path(root_dir).iterdir()):
            if not entry.is_dir() or entry.name in seen:
                continue
            src = entry / 'vuln.c'
            if not src.exists():
                c_files = list(entry.glob('*.c'))
                src = c_files[0] if c_files else None
            if not src:
                continue
            seen.add(entry.name)
            gt = _load_ground_truth_heap(entry, root_dir)
            samples.append({
                'name': entry.name, 'category': category,
                'source': str(src), 'binary': str(entry / 'vuln.exe'),
                **gt,
            })
    return samples


def _load_ground(sample_dir: Path, gt_file: Path) -> Dict | None:
    """从ground_truth.json加载单样本标签."""
    if not gt_file.exists():
        return None
    try:
        with open(gt_file, encoding='utf-8') as f:
            gt_data = json.load(f)
        samples = gt_data.get('samples', {})
        if sample_dir.name in samples:
            info = samples[sample_dir.name]
            return {'is_vuln': info.get('expected_vuln', True),
                    'vuln_type': 'heap_overflow' if info.get('expected_vuln') else 'safe',
                    'pattern': info.get('pattern', ''), 'heap_relevant': True}
    except (json.JSONDecodeError, KeyError):
        pass
    return None


def _infer_ground(sample_dir: Path) -> Dict:
    """从目录名推断标签(无ground_truth.json时的回退)."""
    cve_match = re.search(r'CVE[_-]?\d{4}[_-]?\d{4,}', sample_dir.name, re.IGNORECASE)
    cve_id = cve_match.group(0).upper().replace('_', '-') if cve_match else ''
    is_safe = 'safe' in sample_dir.name.lower()
    return {'is_vuln': not is_safe, 'vuln_type': 'safe' if is_safe else 'heap_overflow',
            'pattern': '', 'heap_relevant': True, 'cve_id': cve_id}


def _load_ground_truth_heap(sample_dir: Path, root_dir: str) -> Dict:
    gt = _load_ground(sample_dir, Path(root_dir) / 'ground_truth.json')
    return gt if gt else _infer_ground(sample_dir)


def compute_metrics(results: List[Dict]) -> Dict[str, Dict]:
    """计算逐工具TP/FP/TN/FN/Precision/Recall/F1/FPR."""
    tools: Dict[str, Dict] = {}
    for r in results:
        tool = r.get('tool', '')
        if not tool or not r.get('success'):
            continue
        if tool not in tools:
            tools[tool] = {'tp': 0, 'fp': 0, 'tn': 0, 'fn': 0, 'total_ms': 0.0}
        gt = r.get('ground_truth')
        if gt is None:
            continue
        predicted = r['verdict'] == 'OVERFLOW'
        tools[tool]['total_ms'] += r.get('elapsed_ms', 0)
        if gt and predicted:
            tools[tool]['tp'] += 1
        elif gt and not predicted:
            tools[tool]['fn'] += 1
        elif not gt and predicted:
            tools[tool]['fp'] += 1
        else:
            tools[tool]['tn'] += 1
    _finalize_metrics(tools)
    return tools


def _finalize_metrics(tools: Dict[str, Dict]):
    """计算precision/recall/f1/fpr/accuracy."""
    for m in tools.values():
        tp, fp, tn, fn = m['tp'], m['fp'], m['tn'], m['fn']
        m['precision'] = round(tp / (tp + fp), 4) if (tp + fp) else 0.0
        m['recall'] = round(tp / (tp + fn), 4) if (tp + fn) else 0.0
        pr = m['precision'] + m['recall']
        m['f1'] = round(2 * m['precision'] * m['recall'] / pr, 4) if pr else 0.0
        m['fpr'] = round(fp / (fp + tn), 4) if (fp + tn) else 0.0
        total = tp + fp + tn + fn
        m['accuracy'] = round((tp + tn) / total, 4) if total else 0.0
        m['avg_ms'] = round(m['total_ms'] / max(total, 1), 1)


def write_csv(results: List[Dict], path: str):
    """输出统一CSV."""
    cols = ['sample', 'category', 'cve_id', 'ground_truth', 'tool',
            'verdict', 'detections', 'elapsed_ms', 'success', 'error']
    with open(path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=cols, extrasaction='ignore')
        w.writeheader()
        for r in results:
            w.writerow(r)


def write_json(metrics: Dict, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)


def write_latex(metrics: Dict, path: str):
    """输出LaTeX对比表格."""
    lines = [
        '% Auto-generated: BinMind multi-tool benchmark',
        '% Generated: ' + time.strftime('%Y-%m-%d'), '',
        r'\begin{table}[htbp]', r'\centering',
        r'\caption{Multi-Tool Heap Overflow Detection Comparison}',
        r'\label{tab:multi-tool}',
        r'\begin{tabular}{lrrrrrrrr}', r'\toprule',
        r'\textbf{Tool} & \textbf{TP} & \textbf{FP} & \textbf{TN} & \textbf{FN} & \textbf{Prec} & \textbf{Recall} & \textbf{F1} & \textbf{FPR} \\',
        r'\midrule',
    ]
    for tool, m in sorted(metrics.items()):
        lines.append(
            f'{tool} & {m["tp"]} & {m["fp"]} & {m["tn"]} & {m["fn"]} & '
            f'{m["precision"]*100:.1f}\\% & {m["recall"]*100:.1f}\\% & '
            f'{m["f1"]:.4f} & {m["fpr"]*100:.1f}\\% \\\\'
        )
    lines.extend([r'\bottomrule', r'\end{tabular}', r'\end{table}'])
    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def _run_all_tools(sample: Dict, gt: bool) -> List[Dict]:
    """对单个样本运行全部工具, 返回结果列表."""
    from benchmark_tool_runners import (
        run_binmind_full, run_binmind_hosv, run_binmind_baseline,
        run_angr_cf, run_ghidra,
    )
    results = []
    meta = {'sample': sample['name'], 'category': sample['category'],
            'cve_id': sample.get('cve_id', ''), 'ground_truth': gt}

    for r_fn, arg in [
        (run_binmind_full, (sample['source'], sample['binary'])),
        (run_binmind_hosv, (sample['source'],)),
        (run_binmind_baseline, (sample['source'],)),
    ]:
        r = r_fn(*arg)
        r.update(meta)
        results.append(r)

    if os.path.isfile(sample['binary']):
        for r_fn, arg in [(run_angr_cf, (sample['binary'],)),
                          (run_ghidra, (sample['binary'],))]:
            r = r_fn(*arg)
            r.update(meta)
            results.append(r)
    return results


def main():
    print('[benchmark] discovering CVE samples...')
    samples = discover_cve_samples()
    print(f'[benchmark] found {len(samples)} samples')

    all_results = []
    for s in samples:
        gt = s['is_vuln'] and s.get('heap_relevant', True)
        print(f'  scanning {s["name"]}...', end=' ')
        all_results.extend(_run_all_tools(s, gt))
        print('done')

    csv_path = os.path.join(EVAL_DIR, 'benchmark_full.csv')
    json_path = os.path.join(EVAL_DIR, 'benchmark_summary.json')
    tex_path = os.path.join(EVAL_DIR, 'result_table.tex')
    write_csv(all_results, csv_path)
    metrics = compute_metrics(all_results)
    write_json(metrics, json_path)
    write_latex(metrics, tex_path)

    print(f'\n[benchmark] CSV: {csv_path}')
    print(f'[benchmark] JSON: {json_path}')
    print(f'[benchmark] LaTeX: {tex_path}')
    print(f'\n{"="*60}')
    for tool, m in sorted(metrics.items()):
        print(f'  {tool:20s} P={m["precision"]:.4f} R={m["recall"]:.4f} '
              f'F1={m["f1"]:.4f} FPR={m["fpr"]:.4f} '
              f'({m["tp"]}T/{m["fp"]}F/{m["tn"]}N/{m["fn"]}Fn) {m["avg_ms"]:.0f}ms')
    print(f'{"="*60}')


if __name__ == '__main__':
    main()
