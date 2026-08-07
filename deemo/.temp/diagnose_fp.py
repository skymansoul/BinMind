"""Diagnose FP cases: cve_26 (realloc_grow_safe) and cve_28 (guarded_loop_safe)."""
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier

# cve_26: realloc grow safe — expected SAFE, got VULN
src26 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_26_realloc_grow_safe\realloc_grow.c', encoding='utf-8').read()
v = HeapOverflowSrcVerifier()
results26 = v.verify(src26)
print("=== CVE-26 (realloc_grow_safe) — expected SAFE ===")
for r in results26:
    print(f"  line={r.alloc_line}-{r.write_line} var={r.var_name} "
          f"verdict={r.verdict.value} conf={r.confidence:.2f}")
    print(f"  reason: {r.reason}")
    print(f"  alloc_size={r.alloc_size} write_size={r.write_size}")
print()

# cve_28: guarded loop safe — expected SAFE, got VULN
src28 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_28_guarded_loop_safe\guarded_loop.c', encoding='utf-8').read()
results28 = v.verify(src28)
print("=== CVE-28 (guarded_loop_safe) — expected SAFE ===")
for r in results28:
    print(f"  line={r.alloc_line}-{r.write_line} var={r.var_name} "
          f"verdict={r.verdict.value} conf={r.confidence:.2f}")
    print(f"  reason: {r.reason}")
    print(f"  alloc_size={r.alloc_size} write_size={r.write_size}")
