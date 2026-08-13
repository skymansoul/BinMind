"""FPE 格式字符串回归 — 编译/收集/一键 与 FPE 单元测试.

创建: 2025-01-13
"""

import argparse
import csv
import json
import subprocess
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def find_gcc(preferred: str = "") -> str:
    import shutil
    if preferred and Path(preferred).exists():
        return preferred
    for cand in ('gcc', 'x86_64-w64-mingw32-gcc', 'cc'):
        p = shutil.which(cand)
        if p:
            return p
    return ''


def compile_one(gcc: str, src: Path, out: Path, opt: str) -> bool:
    out.parent.mkdir(parents=True, exist_ok=True)
    flags = [gcc, opt, '-fno-pic', '-fno-stack-protector']
    if opt == '-O2':
        flags += ['-fno-tree-dce', '-fno-tree-dse', '-fno-inline',
                  '-fno-builtin']
    flags += [str(src), '-o', str(out)]
    try:
        proc = subprocess.run(flags, capture_output=True, text=True,
                              timeout=60, encoding='utf-8', errors='replace')
        return proc.returncode == 0
    except Exception:
        return False


def compile_all(root: Path, gcc: str) -> None:
    if not gcc:
        print('[compile] gcc not found — skipping')
        return
    # 按 manifest 的 source 字段解析每个样本的源文件, 规避残留 .c
    manifest = root / 'manifest.json'
    sources = {}
    if manifest.exists():
        for d in json.loads(manifest.read_text(encoding='utf-8')):
            sources[d['id']] = root / d['source']
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        src = sources.get(d.name) or next(d.glob('*.c'), None)
        if src is None or not src.exists():
            continue
        name = src.stem
        compile_one(gcc, src, d / 'bin' / 'plain' / f'{name}.exe', '-O0')
        compile_one(gcc, src, d / 'bin' / 'packed' / f'{name}.exe', '-O2')
    print('[compile] done')


def load_results(results_dir: Path) -> list:
    rows = []
    for f in sorted(results_dir.glob('*.json')):
        if f.name.startswith('_'):
            continue
        try:
            rows.append(json.loads(f.read_text(encoding='utf-8')))
        except (json.JSONDecodeError, OSError):
            continue
    return rows


def expected_map(root: Path) -> dict:
    manifest = root / 'manifest.json'
    if not manifest.exists():
        return {}
    return {d['id']: d['expected']
            for d in json.loads(manifest.read_text(encoding='utf-8'))}


def metrics(detected: dict, expected: dict) -> dict:
    tp = fp = tn = fn = 0
    for sid, exp in expected.items():
        d = detected.get(sid, False)
        if exp == 'vuln':
            tp += int(d)
            fn += int(not d)
        else:
            fp += int(d)
            tn += int(not d)
    recall = tp / (tp + fn) if (tp + fn) else 0.0
    precision = tp / (tp + fp) if (tp + fp) else 0.0
    f1 = (2 * precision * recall / (precision + recall)
          if (precision + recall) else 0.0)
    fp_rate = fp / (fp + tn) if (fp + tn) else 0.0
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn,
            'recall': round(recall, 4), 'precision': round(precision, 4),
            'f1': round(f1, 4), 'fp_rate': round(fp_rate, 4)}


def collect(root: Path, results_dir: Path) -> dict:
    rows = load_results(results_dir)
    expected = expected_map(root)
    fpe_det, base_det = {}, {}
    for r in rows:
        sid = r.get('id', '')
        fpe_det[sid] = r.get('fpe', {}).get('detected', False)
        base_det[sid] = r.get('baseline', {}).get('detected', False)
    fpe_m = metrics(fpe_det, expected)
    base_m = metrics(base_det, expected)
    fp_red = ((base_m['fp'] - fpe_m['fp']) / base_m['fp'] * 100
              if base_m['fp'] else 0.0)
    report = {
        'sample_count': len(expected),
        'baseline': base_m,
        'fpe': fpe_m,
        'fp_reduction_pct': round(fp_red, 2),
        'per_sample': [
            {'id': sid, 'expected': expected.get(sid, 'vuln'),
             'fpe_detected': fpe_det.get(sid, False),
             'baseline_detected': base_det.get(sid, False)}
            for sid in sorted(expected)
        ],
    }
    (results_dir / 'report.json').write_text(
        json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
    with open(results_dir / 'report.csv', 'w', newline='',
              encoding='utf-8-sig') as f:
        w = csv.DictWriter(f, fieldnames=[
            'id', 'expected', 'fpe_detected', 'baseline_detected'])
        w.writeheader()
        for p in report['per_sample']:
            w.writerow(p)
    print(json.dumps({'baseline': report['baseline'], 'fpe': report['fpe'],
                      'fp_reduction_pct': report['fp_reduction_pct']},
                     ensure_ascii=False, indent=2))


def run_all(gcc: str) -> None:
    samples = _HERE / 'samples'
    print('\n=== 1/4 生成样本集 ===')
    subprocess.run([sys.executable, str(_HERE / 'gen_fmt_samples.py'),
                    str(samples)], cwd=_HERE)
    print('\n=== 2/4 编译样本 ===')
    compile_all(samples, find_gcc(gcc))
    for objs in ('plain', 'packed'):
        out = 'results_' + objs
        print(f'\n=== 3/4 扫描 {objs} ===')
        subprocess.run([sys.executable, str(_HERE / 'scan_runner.py'),
                        str(samples), '--objs', objs, '--out', out], cwd=_HERE)
        print(f'\n=== 4/4 汇总 {objs} ===')
        collect(samples, _HERE / out)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--gcc', default='')
    args = ap.parse_args()
    run_all(args.gcc)


if __name__ == '__main__':
    main()
