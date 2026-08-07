"""Full diagnostic for cve_26 and cve_28."""
import sys, json
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier

v = HeapOverflowSrcVerifier()

# cve_26
src26 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_26_realloc_grow_safe\realloc_grow.c', encoding='utf-8').read()
results26 = v.verify(src26)
print("=== CVE-26 ===")
for r in results26:
    verdict_str = r.verdict.value
    print(f"  L{r.alloc_line}-L{r.write_line} var={r.var_name} "
          f"verdict={verdict_str} conf={r.confidence:.2f} "
          f"alloc={r.alloc_size} write={r.write_size}")
    print(f"    {r.reason}")
    if verdict_str == 'VULN':
        print("    *** THIS IS THE FP ***")

print()

# cve_28
src28 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_28_guarded_loop_safe\guarded_loop.c', encoding='utf-8').read()
results28 = v.verify(src28)
print("=== CVE-28 ===")
for r in results28:
    verdict_str = r.verdict.value
    print(f"  L{r.alloc_line}-L{r.write_line} var={r.var_name} "
          f"verdict={verdict_str} conf={r.confidence:.2f} "
          f"alloc={r.alloc_size} write={r.write_size}")
    print(f"    {r.reason}")
    if verdict_str == 'VULN':
        print("    *** THIS IS THE FP ***")
