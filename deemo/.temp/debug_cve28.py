"""Debug cve_28 loop_bound detection."""
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier

src28 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_28_guarded_loop_safe\guarded_loop.c', encoding='utf-8').read()
lines = src28.splitlines()
# write_line=26, target='buf'
lb = HeapOverflowSrcVerifier._find_loop_bound(lines, 26, 'buf')
print(f"loop_bound: {lb}")

# Also check guard bounds for n
gb = HeapOverflowSrcVerifier._find_guard_bounds('n', lines, 26)
print(f"guard_bounds for n: {gb}")

# Print lines around write
for i in range(15, min(len(lines), 30)):
    print(f"  L{i+1}: {lines[i].strip()}")
