"""真实CVE样本: 检查CSA通道overflow vs uncertain的分布."""
import os, sys
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import _run_hosv_source, _run_csa_source

root = Path(BASE) / 'samples' / 'cve_heap_overflow'
samples = []
for d in sorted(root.iterdir()):
    if not d.is_dir():
        continue
    c_files = list(d.glob('*.c'))
    if not c_files:
        continue
    samples.append({'name': d.name, 'src': str(c_files[0])})

print(f'{"Sample":<40s} {"H_V":>4s} {"H_U":>4s} {"C_O":>4s} {"C_U":>4s} {"C_T":>4s}  strict  relaxed')
print('-' * 90)

strict_tp = 0
relaxed_tp = 0
for s in samples:
    with open(s['src'], encoding='utf-8', errors='replace') as f:
        source = f.read()
    h = _run_hosv_source(source, s['name'])
    c = _run_csa_source(source, s['name'])

    h_vuln = h.get('n_vuln', 0)
    h_unc = h.get('n_uncertain', 0)
    c_ovf = c.get('n_overflow', 0)
    c_unc = c.get('n_uncertain', 0)
    c_total = c.get('n_total', 0)

    # strict: only hard VULN or overflow
    strict = h_vuln > 0 or c_ovf > 0
    # relaxed: UNCERTAIN also counts
    relaxed = h_vuln > 0 or h_unc > 0 or c_ovf > 0 or c_unc > 0

    if strict:
        strict_tp += 1
    if relaxed:
        relaxed_tp += 1

    print(f'{s["name"]:<40s} {h_vuln:>4d} {h_unc:>4d} {c_ovf:>4d} {c_unc:>4d} {c_total:>4d}  '
          f'{"TP" if strict else "FN":>6s}  {"TP" if relaxed else "FN":>6s}')

print(f'\nStrict (VULN/overflow only):  {strict_tp}/{len(samples)}')
print(f'Relaxed (UNCERTAIN counts):   {relaxed_tp}/{len(samples)}')
print(f'\nSamples only detected in relaxed mode:')
for s in samples:
    with open(s['src'], encoding='utf-8', errors='replace') as f:
        source = f.read()
    h = _run_hosv_source(source, s['name'])
    c = _run_csa_source(source, s['name'])
    strict = h.get('n_vuln', 0) > 0 or c.get('n_overflow', 0) > 0
    relaxed = h.get('n_vuln', 0) > 0 or h.get('n_uncertain', 0) > 0 or \
              c.get('n_overflow', 0) > 0 or c.get('n_uncertain', 0) > 0
    if relaxed and not strict:
        print(f'  {s["name"]}: H_V={h.get("n_vuln",0)} H_U={h.get("n_uncertain",0)} '
              f'C_O={c.get("n_overflow",0)} C_U={c.get("n_uncertain",0)}')
