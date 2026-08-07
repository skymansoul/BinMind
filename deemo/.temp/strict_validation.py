"""验证strict模式在合成样本上的效果."""
import os, sys, re
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import _run_hosv_source, _run_csa_source


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


def run_strict(source, name):
    h = _run_hosv_source(source, name)
    c = _run_csa_source(source, name)
    detected = h.get('n_vuln', 0) > 0 or c.get('n_overflow', 0) > 0
    if not detected:
        try:
            from eval.cve_full_comparison_tools import c_to_ir
            from core.heap_overflow_pipeline import detect_heap_overflows_full
            ir_lines = c_to_ir(source)
            candidates, _ = detect_heap_overflows_full(ir_lines, source)
            detected = len(candidates) > 0
        except Exception:
            pass
    return detected, h, c


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
for s in samples:
    with open(s['src'], encoding='utf-8', errors='replace') as f:
        source = f.read()
    detected, h, c = run_strict(source, s['name'])
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

precision = tp / max(tp + fp, 1)
recall = tp / max(tp + fn, 1)
fpr = fp / max(fp + tn, 1)
f1 = 2 * precision * recall / max(precision + recall, 0.001)

print(f'STRICT mode (only VULN + hard overflow)')
print(f'Total: {len(samples)} (VULN={tp+fn}, SAFE={tn+fp})')
print(f'TP={tp} FP={fp} TN={tn} FN={fn}')
print(f'Precision={precision:.4f} Recall={recall:.4f} F1={f1:.4f}')
print(f'FPR={fpr:.4f} ({fp}/{fp+tn})')
if fp_list:
    print(f'\nFP ({len(fp_list)}):')
    for n in fp_list:
        print(f'  {n}')
if fn_list:
    print(f'\nFN ({len(fn_list)}):')
    for n in fn_list:
        print(f'  {n}')
