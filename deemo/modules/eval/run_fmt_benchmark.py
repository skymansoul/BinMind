"""
格式化字符串多工具基准 — 统一 CSV 输出.

对 samples/format_string 下每个样本运行:
  1. BinMind-FMT (伪 IR 级检测器)
  2. angr exploration (若安装)
  3. qemu 运行时追踪 (若可用)
  4. ghidra 无头分析 (含 objdump 降级)
输出 CSV: 工具名, 样本ID, 检出数, 误报数, 漏报数, 耗时.
ground truth: 漏洞样本 (VULN/LEAK 检出) vs 安全对照.
"""

import argparse
import csv
import json
import subprocess
import sys
import time
import tracemalloc
from pathlib import Path
from typing import Dict, List, Optional

ROOT = Path(__file__).resolve().parent
BASE = ROOT.parent
SAMPLE_ROOT = BASE / 'samples' / 'format_string'
RESULTS = BASE / 'results'

sys.path.insert(0, str(BASE))

from hfp.hfp_fmt import detect_from_asm  # noqa: E402

FMT_SAFE = {'safe_01_static_fmt', 'safe_02_param_fmt',
            'safe_03_snprintf'}


def run_fmt(binary: str) -> Dict:
    """BinMind-FMT 检测, 统计检出与耗时."""
    t0 = time.perf_counter()
    proc = subprocess.run(['objdump', '-d', '-M', 'intel', binary],
                          capture_output=True, text=True, timeout=60)
    findings = detect_from_asm(proc.stdout)
    detected = any(f.verdict in ('VULN', 'LEAK') for f in findings)
    elapsed = (time.perf_counter() - t0) * 1000
    return {'detected': 1 if detected else 0, 'elapsed_ms': round(elapsed, 2)}


def run_external(tool: str, binary: str, sample: str) -> Dict:
    """调用外部工具脚本, 容错降级."""
    script = {
        'angr': 'angr_explorer.py',
        'qemu': 'qemu_tracer.py',
        'ghidra': 'ghidra_headless.py',
    }[tool]
    t0 = time.perf_counter()
    try:
        proc = subprocess.run(
            [sys.executable, str(ROOT / script), binary],
            capture_output=True, text=True, timeout=600)
        elapsed = (time.perf_counter() - t0) * 1000
        if proc.returncode != 0:
            return {'available': False, 'error': 'exit %d' % proc.returncode,
                    'detected': 0, 'elapsed_ms': round(elapsed, 2)}
        data = json.loads(proc.stdout)
        return {'available': bool(data.get('success')),
                'detected': int(data.get('findings', 0)),
                'elapsed_ms': round(elapsed, 2)}
    except Exception as e:
        return {'available': False, 'error': str(e)[:120],
                'detected': 0,
                'elapsed_ms': round((time.perf_counter() - t0) * 1000, 2)}


def classify(sample: str, detected: int) -> str:
    """按 ground truth 归类 TP/FP/FN/TN."""
    vuln = sample not in FMT_SAFE
    has = detected > 0
    if vuln and has:
        return 'TP'
    if vuln and not has:
        return 'FN'
    if not vuln and has:
        return 'FP'
    return 'TN'


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description='fmt multi-tool benchmark')
    ap.add_argument('--out', default=str(RESULTS / 'benchmark_fmt.csv'))
    args = ap.parse_args(argv)

    rows: List[Dict] = []
    samples = sorted(
        d for d in SAMPLE_ROOT.iterdir()
        if d.is_dir() and (d / 'vuln.exe').exists())

    for sdir in samples:
        name = sdir.name
        binary = str(sdir / 'vuln.exe')
        gt = 'VULN' if name not in FMT_SAFE else 'SAFE'

        tracemalloc.start()
        fmt = run_fmt(binary)
        _, peak = tracemalloc.get_traced_memory()
        tracemalloc.stop()
        verdict = classify(name, fmt['detected'])
        rows.append({
            'tool': 'BinMind-FMT', 'sample': name, 'ground_truth': gt,
            'detected': fmt['detected'],
            'fp': 1 if verdict == 'FP' else 0,
            'fn': 1 if verdict == 'FN' else 0,
            'elapsed_ms': fmt['elapsed_ms'],
            'peak_memory_kb': round(peak / 1024, 1),
            'verdict': verdict,
        })

        for tool in ('angr', 'qemu', 'ghidra'):
            ext = run_external(tool, binary, name)
            if not ext['available']:
                rows.append({
                    'tool': tool, 'sample': name, 'ground_truth': gt,
                    'detected': 0, 'fp': 0, 'fn': 0,
                    'elapsed_ms': ext['elapsed_ms'],
                    'peak_memory_kb': 0, 'verdict': 'UNAVAILABLE',
                })
                continue
            verdict = classify(name, ext['detected'])
            rows.append({
                'tool': tool, 'sample': name, 'ground_truth': gt,
                'detected': ext['detected'],
                'fp': 1 if verdict == 'FP' else 0,
                'fn': 1 if verdict == 'FN' else 0,
                'elapsed_ms': ext['elapsed_ms'],
                'peak_memory_kb': 0, 'verdict': verdict,
            })

    out = Path(args.out)
    out.parent.mkdir(parents=True, exist_ok=True)
    with open(out, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    summary = _summarize(rows)
    Path(RESULTS / 'benchmark_fmt_summary.json').write_text(
        json.dumps(summary, indent=2, ensure_ascii=False), encoding='utf-8')
    print(json.dumps(summary, indent=2, ensure_ascii=False))
    return 0


def _summarize(rows: List[Dict]) -> Dict:
    """按工具聚合召回率/误报率."""
    out = {}
    for tool in ('BinMind-FMT', 'angr', 'qemu', 'ghidra'):
        tool_rows = [r for r in rows if r['tool'] == tool]
        if not tool_rows:
            continue
        avail = [r for r in tool_rows if r['verdict'] != 'UNAVAILABLE']
        if not avail:
            out[tool] = {'status': 'unavailable'}
            continue
        vuln = [r for r in avail if r['ground_truth'] == 'VULN']
        safe = [r for r in avail if r['ground_truth'] == 'SAFE']
        tp = sum(1 for r in vuln if r['verdict'] == 'TP')
        fn = sum(1 for r in vuln if r['verdict'] == 'FN')
        fp = sum(1 for r in safe if r['verdict'] == 'FP')
        tn = sum(1 for r in safe if r['verdict'] == 'TN')
        out[tool] = {
            'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
            'recall': round(tp / (tp + fn), 4) if (tp + fn) else 0.0,
            'fpr': round(fp / (fp + tn), 4) if (fp + tn) else 0.0,
            'avg_time_ms': round(
                sum(r['elapsed_ms'] for r in avail) / len(avail), 2),
        }
    return out


if __name__ == '__main__':
    sys.exit(main())