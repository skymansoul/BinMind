"""Test which regex patterns match cve_23 and cve_27."""
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from analysis.heap_overflow_src_patterns import (
    _PTR_WRITE_RE, _PTR_VAR_OFFSET_RE, _STRUCT_ARRAY_WRITE_RE,
)
from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_types import HeapAllocSite, HeapWriteSite

# cve_23: *(int *)(buf + m) = 0x43434343;
line23 = "*(int *)(buf + m) = 0x43434343;"
print("=== cve_23: *(int *)(buf + m) = ===")
m1 = _PTR_WRITE_RE.search(line23)
m2 = _PTR_VAR_OFFSET_RE.search(line23)
print(f"  _PTR_WRITE_RE:      {m1}")
print(f"  _PTR_VAR_OFFSET_RE: {m2}")
if m2:
    print(f"    groups: {m2.groups()}")

# cve_27: arr[8].val = 42;
line27 = "arr[8].val = 42;"
print("\n=== cve_27: arr[8].val = ===")
m3 = _STRUCT_ARRAY_WRITE_RE.search(line27)
print(f"  _STRUCT_ARRAY_WRITE_RE: {m3}")
if m3:
    print(f"    groups: {m3.groups()}")

# cve_25: buf[i * 10 + j] = 'A';
line25 = "buf[i * 10 + j] = 'A';"
print("\n=== cve_25: buf[i * 10 + j] = ===")
import re
vm = re.search(r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=', line25)
print(f"  vm (single word idx): {vm}")
# Try expression index
vm2 = re.search(r'(\w[\w]*)\s*\[\s*([^\]]+)\s*\]\s*=', line25)
print(f"  vm2 (expr idx): {vm2}")
if vm2:
    print(f"    groups: {vm2.groups()}")

# Now test full find_allocs + find_writes for each sample
src23 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_23_fm_boundary_overflow\fm_boundary_overflow.c', encoding='utf-8').read()
lines23 = src23.splitlines()
allocs23 = find_allocs(lines23, set(range(1, len(lines23)+1)))
writes23 = find_writes(lines23, allocs23, set(range(1, len(lines23)+1)))
print(f"\n=== cve_23 full pipeline ===")
print(f"  allocs: {[(a.line, a.var, a.size_const) for a in allocs23]}")
print(f"  writes: {[(w.line, w.target, w.kind, w.write_size, w.offset, getattr(w, 'src_var', '')) for w in writes23]}")

src27 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_27_struct_array_overflow\struct_array.c', encoding='utf-8').read()
lines27 = src27.splitlines()
allocs27 = find_allocs(lines27, set(range(1, len(lines27)+1)))
writes27 = find_writes(lines27, allocs27, set(range(1, len(lines27)+1)))
print(f"\n=== cve_27 full pipeline ===")
print(f"  allocs: {[(a.line, a.var, a.size_const) for a in allocs27]}")
print(f"  writes: {[(w.line, w.target, w.kind, w.write_size, w.offset, getattr(w, 'src_var', '')) for w in writes27]}")

src25 = open(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow\cve_25_nested_loop_overflow\nested_loop.c', encoding='utf-8').read()
lines25 = src25.splitlines()
allocs25 = find_allocs(lines25, set(range(1, len(lines25)+1)))
writes25 = find_writes(lines25, allocs25, set(range(1, len(lines25)+1)))
print(f"\n=== cve_25 full pipeline ===")
print(f"  allocs: {[(a.line, a.var, a.size_const) for a in allocs25]}")
print(f"  writes: {[(w.line, w.target, w.kind, w.write_size, w.offset, getattr(w, 'src_var', '')) for w in writes25]}")
