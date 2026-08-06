"""回归测试结果评估 -- 读取扫描输出, 统计检出/误报/漏报。"""
import json, os, sys, glob
from collections import defaultdict

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), 'samples')
RESULTS_DIR = os.path.join(os.path.dirname(__file__), 'results')

def load_truth(sample_dir):
    for fname in ['truth.json', 'ground_truth.json']:
        path = os.path.join(sample_dir, fname)
        if os.path.exists(path):
            with open(path) as f:
                return json.load(f)
    return {}

def eval_findings(findings, truth):
    expected = truth.get('vuln_type', truth.get('type', 'unknown'))
    expected_count = truth.get('expected_findings', 1)
    n_found = len(findings) if isinstance(findings, list) else 0

    if n_found >= expected_count:
        return 'tp'  # true positive
    elif n_found > 0:
        return 'fp'  # false positive (wrong type or too many)
    elif expected_count > 0:
        return 'fn'  # false negative
    return 'tn'

def main():
    samples = [d for d in os.listdir(SAMPLES_DIR)
               if os.path.isdir(os.path.join(SAMPLES_DIR, d))]
    if not samples:
        print("No sample directories found"); return 1

    stats = defaultdict(lambda: {'tp': 0, 'fp': 0, 'fn': 0, 'tn': 0})
    for sample in sorted(samples):
        sd = os.path.join(SAMPLES_DIR, sample)
        truth = load_truth(sd)
        # Try to load scan results
        result_path = os.path.join(RESULTS_DIR, f'{sample}.json')
        if not os.path.exists(result_path):
            continue
        with open(result_path) as f:
            data = json.load(f)
        findings = data.get('findings', data.get('results', []))
        result = eval_findings(findings, truth)
        stats['all'][result] += 1

    for cat, s in sorted(stats.items()):
        total = s['tp'] + s['fp'] + s['fn'] + s['tn']
        if total == 0:
            continue
        prec = s['tp'] / max(s['tp'] + s['fp'], 1)
        rec = s['tp'] / max(s['tp'] + s['fn'], 1)
        f1 = 2 * prec * rec / max(prec + rec, 0.001)
        print(f'{cat}: P={prec:.2f} R={rec:.2f} F1={f1:.2f} ({total} samples)')

    out = {'stats': {k: dict(v) for k, v in stats.items()}}
    out_path = os.path.join(RESULTS_DIR, 'eval_summary.json')
    os.makedirs(RESULTS_DIR, exist_ok=True)
    with open(out_path, 'w') as f:
        json.dump(out, f, indent=2)
    print(f'\nSummary: {out_path}')

if __name__ == '__main__':
    sys.exit(main())
