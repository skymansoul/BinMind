"""Fmt-OG 对比实验 — 基线 vs Fmt-OG vs Angr 统一 CSV."""

import csv
import json
import pathlib
import sys
import time
from pathlib import Path

VULN_ROOT = Path(__file__).resolve().parents[1]
SRC = VULN_ROOT / 'src'
EVAL_DIR = Path(__file__).resolve().parent
SAMPLES_DIR = VULN_ROOT / 'tests' / 'fmt_fp_cve' / 'samples'
OUT_DIR = EVAL_DIR / 'fmt_results'
OUT_DIR.mkdir(parents=True, exist_ok=True)
for _p in (str(SRC), str(EVAL_DIR), str(VULN_ROOT / 'tests'),
           str(SRC / 'format' / 'fmtog')):
    if _p not in sys.path:
        sys.path.insert(0, _p)

TOOLS = ('BASE', 'Fmt-OG', 'Angr')


def load_truth() -> dict:
    truth = {}
    for d in sorted(SAMPLES_DIR.iterdir()):
        if d.is_dir():
            tj = d / 'truth.json'
            if tj.exists():
                truth[d.name] = json.loads(tj.read_text(encoding='utf-8')) \
                    .get('class', '')
    return truth


def run_fmt(binary: Path) -> dict:
    from _common.disasm import (disassemble, parse_asm, main_range,
                                range_from_addr)
    from rdata_strings import extract_rdata_strings
    from fmt_compressor import FmtCompressor
    t0 = time.time()
    from heap.acfpc.pe_imports import build_import_map
    asm_text = disassemble(str(binary))
    lines, addrs, labels = parse_asm(asm_text)
    ur = main_range(labels, len(lines))
    if ur is None:
        addr_file = binary.parent / 'main_addr.txt'
        if addr_file.exists():
            ur = range_from_addr(addrs, int(addr_file.read_text(
                encoding='utf-8').strip(), 16))
    rdata = extract_rdata_strings(str(binary))
    import_map = build_import_map(str(binary), asm_text)
    comp = FmtCompressor().compress(lines, addrs, labels, rdata,
                                    user_range=ur,
                                    import_map=import_map)
    dt = round((time.time() - t0) * 1000, 1)
    return {'base': {'detected': comp.stats.in_range > 0,
                     'n': comp.stats.in_range, 'elapsed_ms': dt},
            'og': {'detected': len(comp.kept) > 0,
                   'n': len(comp.kept), 'elapsed_ms': dt}}


def run_angr(binary: Path) -> dict:
    try:
        import angr_compat as ae
    except ImportError:
        return {'detected': False, 'n': 0, 'elapsed_ms': 0.0,
                'mode': 'ERROR'}
    t0 = time.time()
    r = ae.scan(binary)
    return {'detected': r.detected, 'n': r.num_findings,
            'elapsed_ms': round((time.time() - t0) * 1000, 1),
            'mode': r.mode}


def main():
    import argparse
    ap = argparse.ArgumentParser(description='Fmt-OG 对比实验')
    ap.add_argument('--samples', type=str, default=str(SAMPLES_DIR))
    ap.add_argument('--csv', type=str, default=str(OUT_DIR / 'benchmark_fmt.csv'))
    ap.add_argument('--json', type=str, default=str(OUT_DIR / 'benchmark_fmt.json'))
    args = ap.parse_args()
    samples_dir = pathlib.Path(args.samples)
    truth = load_truth()
    rows = []
    for d in sorted(samples_dir.iterdir()):
        if not d.is_dir():
            continue
        binary = d / 'vuln.exe'
        if not binary.exists():
            binary = d / 'vuln'
        if not binary.exists():
            continue
        cls = truth.get(d.name, '?')
        r = run_fmt(binary)
        ra = run_angr(binary)
        for tool, det, n in (('BASE', r['base']['detected'], r['base']['n']),
                             ('Fmt-OG', r['og']['detected'], r['og']['n']),
                             ('Angr', ra['detected'], ra['n'])):
            rows.append({
                'tool': tool, 'sample': d.name, 'cls': cls,
                'detected': int(det),
                'tp': int(det and cls == 'TP'),
                'fp': int(det and cls == 'TN'),
                'fn': int((not det) and cls == 'TP'),
                'elapsed_ms': (r['og']['elapsed_ms']
                               if tool == 'Fmt-OG' else
                               r['base']['elapsed_ms']
                               if tool == 'BASE' else ra['elapsed_ms']),
                'peak_mb': 0.0,
                'mode': ('REAL' if tool != 'Angr' else ra['mode']),
            })
    csv_path = args.csv
    with open(csv_path, 'w', newline='', encoding='utf-8') as f:
        w = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        w.writeheader()
        w.writerows(rows)
    summary = {}
    for tool in TOOLS:
        tr = [r for r in rows if r['tool'] == tool]
        tp = sum(r['tp'] for r in tr)
        fp = sum(r['fp'] for r in tr)
        fn = sum(r['fn'] for r in tr)
        tn = sum(1 for r in tr if r['cls'] == 'TN' and not r['detected'])
        precision = tp / max(1, tp + fp)
        recall = tp / max(1, tp + fn)
        f1 = 2 * precision * recall / max(1, precision + recall)
        summary[tool] = {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
                         'precision': round(precision, 4),
                         'recall': round(recall, 4),
                         'f1': round(f1, 4),
                         'avg_ms': round(sum(r['elapsed_ms'] for r in tr)
                                         / max(1, len(tr)), 1)}
    report = {'rows': rows, 'summary': summary}
    pathlib.Path(args.json).write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'{"Tool":10s} {"TP":>3s} {"FP":>3s} {"TN":>3s} {"FN":>3s} '
          f'{"Prec":>7s} {"Rec":>7s} {"F1":>6s} {"AvgMs":>8s}')
    for tool, m in summary.items():
        print(f'{tool:10s} {m["tp"]:3d} {m["fp"]:3d} {m["tn"]:3d} {m["fn"]:3d} '
              f'{m["precision"] * 100:6.1f}% {m["recall"] * 100:6.1f}% '
              f'{m["f1"]:6.3f} {m["avg_ms"]:8.1f}')
    print('saved:', csv_path)


if __name__ == '__main__':
    main()
