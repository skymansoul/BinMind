"""逐通道误报分析 — 区分HOSV/CSA/IR各自贡献的FP."""
import os, sys, re
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import _run_hosv_source, _run_csa_source, c_to_ir


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

    # 只关注SAFE样本
    safe_samples = [s for s in samples if not s['vuln']]
    print(f'Analyzing {len(safe_samples)} SAFE samples for FP channel attribution\n')
    print(f'{"Sample":<40s} {"HOSV":>6s} {"CSA":>6s} {"H_detail":>20s} {"C_detail":>20s}')
    print('-' * 100)

    hosv_fp = 0
    csa_fp = 0
    both_fp = 0

    for s in safe_samples:
        with open(s['src'], encoding='utf-8', errors='replace') as f:
            source = f.read()
        h = _run_hosv_source(source, s['name'])
        c = _run_csa_source(source, s['name'])

        h_det = h.get('detected', False)
        c_det = c.get('detected', False)
        h_detail = f"V={h.get('n_vuln',0)}/U={h.get('n_uncertain',0)}"
        c_detail = f"O={c.get('n_overflow',0)}/U={c.get('n_uncertain',0)}/T={c.get('n_total',0)}"

        is_fp = h_det or c_det
        marker = 'FP' if is_fp else 'ok'
        if h_det and c_det:
            both_fp += 1
        elif h_det:
            hosv_fp += 1
        elif c_det:
            csa_fp += 1

        print(f'{s["name"]:<40s} {str(h_det):>6s} {str(c_det):>6s} {h_detail:>20s} {c_detail:>20s} {marker}')

    print(f'\nHOSV-only FP: {hosv_fp}')
    print(f'CSA-only FP:  {csa_fp}')
    print(f'Both FP:      {both_fp}')
    print(f'Total FP:     {hosv_fp + csa_fp + both_fp}')


if __name__ == '__main__':
    main()
