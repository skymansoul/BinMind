"""Diagnose cve_08 regression and cve_23/cve_28 issues."""
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from pathlib import Path
from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier

SAMPLE_DIR = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow')

def diagnose(name):
    src = (SAMPLE_DIR / name / list((SAMPLE_DIR / name).glob('*.c'))[0].name).read_text(encoding='utf-8')
    v = HeapOverflowSrcVerifier()
    results = v.verify(src)
    print(f"\n=== {name} ===")
    for r in results:
        print(f"  L{r.alloc_line}-L{r.write_line} var={r.var_name} "
              f"verdict={r.verdict.value} conf={r.confidence:.2f} "
              f"alloc={r.alloc_size} write={r.write_size}")
        print(f"    {r.reason[:120]}")

for name in ['cve_08_calloc_overflow', 'cve_19_same_offset_accumulate',
             'cve_23_fm_boundary_overflow', 'cve_28_guarded_loop_safe']:
    diagnose(name)
