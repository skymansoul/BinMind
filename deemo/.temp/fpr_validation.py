"""SRC-IR Bridge FPR验证 — 在70个合成样本(38VULN+32SAFE)上运行三通道检测."""
import os, sys, re, json
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import run_binmind_pipeline


def parse_ground_truth(sample_dir):
    """从README解析Expected Verdict."""
    readme = sample_dir / 'README.md'
    if not readme.exists():
        return None
    raw = readme.read_text(encoding='utf-8', errors='replace')
    lines = raw.split('\n')
    for i, line in enumerate(lines):
        if 'Expected Verdict' in line or 'Expected Detection' in line:
            if i + 1 < len(lines):
                v = lines[i + 1]
                if 'VULN' in v or 'True Positive' in v:
                    return True
                if 'SAFE' in v or 'NOT VULN' in v or 'True Negative' in v:
                    return False
                if 'Filter Resistance' in v:
                    if '_overflow' in sample_dir.name:
                        return True
                    return False
    if '_overflow' in sample_dir.name:
        return True
    if '_safe' in sample_dir.name:
        return False
    return None


def main():
    root = Path(BASE) / 'tests' / 'cve_samples' / 'heap_overflow'
    samples = []
    for d in sorted(root.iterdir()):
        if not d.is_dir() or not re.match(r'^cve_\d', d.name):
            continue
        c_files = list(d.glob('*.c'))
        if not c_files:
            continue
        gt = parse_ground_truth(d)
        if gt is None:
            continue
        samples.append({'name': d.name, 'src': str(c_files[0]), 'vuln': gt})

    tp = fp = tn = fn = 0
    fp_list = []
    fn_list = []
    ch_stats = {'HOSV': 0, 'CSA': 0, 'IR': 0}

    for s in samples:
        with open(s['src'], encoding='utf-8', errors='replace') as f:
            source = f.read()
        r = run_binmind_pipeline(source, s['name'])
        detected = r.get('detected', False)
        bridge = r.get('pipeline_stats', {}).get('source', '')
        if 'HOSV' in bridge:
            ch_stats['HOSV'] += 1
        if 'CSA' in bridge:
            ch_stats['CSA'] += 1
        if r.get('pipeline_stats_bridge') == 'IR-fallback':
            ch_stats['IR'] += 1

        if s['vuln'] and detected:
            tp += 1
        elif s['vuln'] and not detected:
            fn += 1
            fn_list.append(s['name'])
        elif not s['vuln'] and detected:
            fp += 1
            fp_list.append(s['name'])
        else:
            tn += 1

    total = len(samples)
    precision = tp / max(tp + fp, 1)
    recall = tp / max(tp + fn, 1)
    fpr = fp / max(fp + tn, 1)
    f1 = 2 * precision * recall / max(precision + recall, 0.001)

    print('=' * 60)
    print('SRC-IR Bridge FPR Validation on Synthetic Samples')
    print('=' * 60)
    print(f'Total: {total} (VULN={tp+fn}, SAFE={tn+fp})')
    print(f'TP={tp} FP={fp} TN={tn} FN={fn}')
    print(f'Precision={precision:.4f} Recall={recall:.4f} F1={f1:.4f}')
    print(f'FPR={fpr:.4f} ({fp}/{fp+tn})')
    print(f'Channel hits: {ch_stats}')
    if fp_list:
        print(f'\nFalse Positives ({len(fp_list)}):')
        for n in fp_list:
            print(f'  {n}')
    if fn_list:
        print(f'\nFalse Negatives ({len(fn_list)}):')
        for n in fn_list:
            print(f'  {n}')
    if not fp_list and not fn_list:
        print('\n*** ZERO FP, ZERO FN — F1=1.0, FPR=0.0 ***')


if __name__ == '__main__':
    main()
