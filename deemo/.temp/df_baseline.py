"""Baseline benchmark for existing double-free detector on all 31 samples."""
import os, sys, json

SAMPLES = os.path.join(os.path.dirname(__file__), '..', 'tests', 'cve_samples')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

from analysis.double_free_src_verifier import DoubleFreeSrcVerifier

# Ground truth: double_free_01~15 (14 VULN + 1 SAFE) + df_adv_16~31
GT = {}
for i in range(1, 16):
    name = f'double_free_{i:02d}'
    GT[name] = 0 if i == 7 else 1

adv_safe = {17, 18, 21, 24, 27, 29}  # 0-indexed from 16
for i in range(16, 32):
    name = f'df_adv_{i}'
    GT[name] = 0 if (i in adv_safe) else 1

verifier = DoubleFreeSrcVerifier()
results = {}
for name, expected in sorted(GT.items()):
    src_path = os.path.join(SAMPLES, name, 'vuln.c')
    if not os.path.isfile(src_path):
        print(f'MISSING: {name}')
        continue
    with open(src_path, 'r', encoding='utf-8', errors='replace') as f:
        source = f.read()
    findings = verifier.verify(source)
    detected = 1 if findings else 0
    results[name] = {
        'expected': expected,
        'detected': detected,
        'tp': detected == 1 and expected == 1,
        'fp': detected == 1 and expected == 0,
        'fn': detected == 0 and expected == 1,
        'tn': detected == 0 and expected == 0,
        'findings': [{'verdict': r.verdict.value, 'line': r.free_line,
                       'var': r.var_name, 'reason': r.reason,
                       'confidence': r.confidence} for r in findings]
    }

tp = sum(1 for v in results.values() if v['tp'])
fp = sum(1 for v in results.values() if v['fp'])
fn = sum(1 for v in results.values() if v['fn'])
tn = sum(1 for v in results.values() if v['tn'])
precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0

print(f'\n=== Baseline DFSV Results (31 samples) ===')
print(f'TP={tp} FP={fp} FN={fn} TN={tn}')
print(f'Precision={precision:.3f} Recall={recall:.3f} F1={f1:.3f} FPR={fpr:.3f}')
print(f'\n--- Details ---')
for name in sorted(results):
    r = results[name]
    status = 'TP' if r['tp'] else 'FP' if r['fp'] else 'FN' if r['fn'] else 'TN'
    extra = ''
    if r['findings']:
        first = r['findings'][0]
        extra = f' L{first["line"]} var={first["var"]} conf={first["confidence"]:.2f}'
    print(f'{name}: exp={r["expected"]} det={r["detected"]} [{status}]{extra}')

output = {
    'precision': precision, 'recall': recall, 'f1': f1, 'fpr': fpr,
    'tp': tp, 'fp': fp, 'fn': fn, 'tn': tn,
    'results': results
}
out_path = os.path.join(os.path.dirname(__file__), 'results', 'df_baseline_31.json')
os.makedirs(os.path.dirname(out_path), exist_ok=True)
with open(out_path, 'w') as f:
    json.dump(output, f, indent=2)
print(f'\nResults saved to {out_path}')
