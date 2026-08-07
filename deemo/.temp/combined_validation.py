"""综合验证: 合成样本FPR + 真实CVE recall."""
import os, sys, re
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import run_binmind_pipeline


def parse_ground_truth(sample_dir):
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
                    return '_overflow' in sample_dir.name
    if '_overflow' in sample_dir.name:
        return True
    if '_safe' in sample_dir.name:
        return False
    return None


def run_subset(root, label):
    samples = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        c_files = list(d.glob('*.c'))
        if not c_files:
            continue
        if label == 'synthetic':
            if not re.match(r'^cve_\d', d.name):
                continue
            gt = parse_ground_truth(d)
            if gt is None:
                continue
        else:
            gt = True
        samples.append({'name': d.name, 'src': str(c_files[0]), 'vuln': gt})

    tp = fp = tn = fn = 0
    fp_list = []
    fn_list = []
    for s in samples:
        with open(s['src'], encoding='utf-8', errors='replace') as f:
            source = f.read()
        r = run_binmind_pipeline(source, s['name'])
        detected = r.get('detected', False)
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

    print(f'\n{"=" * 60}')
    print(f'{label.upper()} ({total} samples)')
    print(f'{"=" * 60}')
    print(f'VULN={tp+fn} SAFE={tn+fp}')
    print(f'TP={tp} FP={fp} TN={tn} FN={fn}')
    print(f'Precision={precision:.4f} Recall={recall:.4f} F1={f1:.4f}')
    if label == 'synthetic':
        print(f'FPR={fpr:.4f} ({fp}/{fp+tn})')
    if fp_list:
        print(f'FP: {fp_list}')
    if fn_list:
        print(f'FN: {fn_list}')
    return {'tp': tp, 'fp': fp, 'tn': tn, 'fn': fn, 'f1': f1, 'fpr': fpr, 'recall': recall}


root_syn = Path(BASE) / 'tests' / 'cve_samples' / 'heap_overflow'
root_real = Path(BASE) / 'samples' / 'cve_heap_overflow'

print('SRC-IR Bridge strict+veto validation')
syn = run_subset(root_syn, 'synthetic')
real = run_subset(root_real, 'real CVE')

print(f'\n{"=" * 60}')
print('COMBINED (70 synthetic + 16 real = 86 samples)')
print(f'{"=" * 60}')
total_tp = syn['tp'] + real['tp']
total_fp = syn['fp'] + real['fp']
total_tn = syn['tn'] + real['tn']
total_fn = syn['fn'] + real['fn']
total_p = total_tp / max(total_tp + total_fp, 1)
total_r = total_tp / max(total_tp + total_fn, 1)
total_f1 = 2 * total_p * total_r / max(total_p + total_r, 0.001)
total_fpr = total_fp / max(total_fp + total_tn, 1)
print(f'TP={total_tp} FP={total_fp} TN={total_tn} FN={total_fn}')
print(f'Precision={total_p:.4f} Recall={total_r:.4f} F1={total_f1:.4f} FPR={total_fpr:.4f}')
