"""分析真实CVE的HOSV完整verdict分布(含SAFE)."""
import os, sys
from pathlib import Path

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_types import HoVerdict

root = Path(BASE) / 'samples' / 'cve_heap_overflow'
print(f'{"Sample":<40s} {"VULN":>5s} {"UNC":>5s} {"SAFE":>5s}  all_safe')
print('-' * 70)

for d in sorted(root.iterdir()):
    if not d.is_dir():
        continue
    c_files = list(d.glob('*.c'))
    if not c_files:
        continue
    src = c_files[0].read_text(encoding='utf-8', errors='replace')
    v = HeapOverflowSrcVerifier()
    results = v.verify(src)
    n_vuln = sum(1 for r in results if r.verdict == HoVerdict.VULN)
    n_unc = sum(1 for r in results if r.verdict == HoVerdict.UNCERTAIN)
    n_safe = sum(1 for r in results if r.verdict == HoVerdict.SAFE)
    all_safe = n_safe > 0 and n_vuln == 0 and n_unc == 0
    print(f'{d.name:<40s} {n_vuln:>5d} {n_unc:>5d} {n_safe:>5d}  {str(all_safe):>5s}')
