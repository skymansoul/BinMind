"""诊断cve_50和cve_52"""
import sys, re
from pathlib import Path

sys.path.insert(0, str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")))

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_src_patterns import _skip_block_comments, _base_var
from analysis.heap_overflow_src_apas import build_alias_closure, resolve_alias, eval_compound_offset, resolve_write_offset, extract_field_access

SAMPLE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow")

# cve_50
print("=== cve_50 ===")
d = SAMPLE_DIR / "cve_50_compound_offset_overflow"
source = (d / "compound_offset_overflow.c").read_text(encoding="utf-8")
lines = source.splitlines()
valid = {ln for ln, _ in _skip_block_comments(lines)}

allocs = find_allocs(lines, valid)
alloc_vars = {a.var for a in allocs}
print(f"alloc_vars: {alloc_vars}")
alias_map = build_alias_closure(lines, alloc_vars)
print(f"alias_map: {alias_map}")

writes = find_writes(lines, allocs, valid)
for w in writes:
    w.target = resolve_alias(w.target, alias_map)
print("Writes:")
for w in writes:
    print(f"  L{w.line}: {w.kind} target={w.target} size={w.write_size} offset={w.offset}")

# Check what memcpy looks like
for i, line in enumerate(lines, start=1):
    if 'memcpy' in line:
        print(f"  memcpy at L{i}: {line.strip()}")
        # Check the offset resolution
        from analysis.heap_overflow_types import HeapWriteSite
        dummy_w = HeapWriteSite(line=i, target='buf', kind='memcpy', write_size=8, offset=0)
        off = resolve_write_offset(dummy_w, lines)
        print(f"  resolved offset: {off}")

# Check eval_compound_offset for 'off' variable
print(f"\neval_compound_offset('off', lines, 28) = {eval_compound_offset('off', lines, 28)}")
# Check guard bounds for base and stride
from analysis.heap_overflow_src_guards import find_guard_bounds
print(f"guard_bounds('base', lines, 28) = {find_guard_bounds('base', lines, 28)}")
print(f"guard_bounds('stride', lines, 28) = {find_guard_bounds('stride', lines, 28)}")
print(f"guard_bounds('off', lines, 28) = {find_guard_bounds('off', lines, 28)}")

# The issue: off = base * stride; is a variable assignment
# memcpy(buf + off, src, 8) — off is a variable, not base*stride
# eval_compound_offset('off', ...) should search for off = base*stride and evaluate that
# But it only searches for off = <number>
# Let's check what off is assigned to
for i, line in enumerate(lines, start=1):
    if 'off' in line and '=' in line:
        print(f"  L{i}: {line.strip()}")

# cve_52
print("\n=== cve_52 ===")
d = SAMPLE_DIR / "cve_52_struct_field_offset_overflow"
source = (d / "struct_field_offset_overflow.c").read_text(encoding="utf-8")
lines = source.splitlines()
valid = {ln for ln, _ in _skip_block_comments(lines)}

allocs = find_allocs(lines, valid)
print(f"allocs: {[(a.var, a.size_const) for a in allocs]}")

writes = find_writes(lines, allocs, valid)
print("Writes:")
for w in writes:
    print(f"  L{w.line}: {w.kind} target={w.target} size={w.write_size} offset={w.offset}")

# The problem: memcpy(buf->b, src, 32) is detected as struct_write
# but _base_var("buf->b") = "b", not "buf"
# So find_writes doesn't match it because "b" is not in alloc_vars
# And the struct_write detection regex: sf = re.search(r'(\w[\w]*)\s*(?:->|\.)\s*\w[\w]*\s*=', text)
# sf.group(1) = "buf", sbase = _base_var("buf") = "buf" → should match!
# But wait, memcpy(buf->b, ...) is both a memcpy AND a struct field access

for i, line in enumerate(lines, start=1):
    if 'memcpy' in line:
        print(f"  memcpy L{i}: {line.strip()}")
        from analysis.heap_overflow_src_patterns import _MEMCPY_HEAP_RE
        for m in _MEMCPY_HEAP_RE.finditer(line.strip()):
            dst = m.group(1).strip()
            print(f"    dst='{dst}' base_var='{_base_var(dst)}'")
