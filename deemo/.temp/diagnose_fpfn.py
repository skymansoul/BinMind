"""详细诊断每个FN/FP的根因"""
import sys, re
from pathlib import Path

sys.path.insert(0, str(Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")))

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_src_patterns import _skip_block_comments

SAMPLE_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow")

cases = [
    "cve_44_alias_chain_overflow",
    "cve_46_cast_alias_overflow",
    "cve_50_compound_offset_overflow",
    "cve_52_struct_field_offset_overflow",
    "cve_53_factory_cross_guard_safe",
    "cve_55_returned_ptr_overflow",
]

v = HeapOverflowSrcVerifier()

for name in cases:
    d = SAMPLE_DIR / name
    c_files = list(d.glob("*.c"))
    source = c_files[0].read_text(encoding="utf-8")
    lines = source.splitlines()
    raw = lines
    valid = {ln for ln, _ in _skip_block_comments(raw)}

    print(f"\n{'='*60}")
    print(f"  {name}")
    print(f"{'='*60}")

    allocs = find_allocs(lines, valid)
    from analysis.heap_overflow_src_interproc import resolve_factory_allocs, resolve_cross_func_writes
    allocs.extend(resolve_factory_allocs(lines, allocs))

    writes = find_writes(lines, allocs, valid)
    writes.extend(resolve_cross_func_writes(lines, allocs, writes))

    print(f"Allocs found:")
    for a in allocs:
        print(f"  L{a.line}: {a.func}({a.size_expr}) -> {a.var} (const={a.size_const}, kind={a.kind})")

    print(f"Writes found:")
    for w in writes:
        print(f"  L{w.line}: {w.kind} target={w.target} size={w.write_size} offset={w.offset} src_var={w.src_var}")

    results = v.verify(source)
    print(f"Results:")
    for r in results:
        print(f"  [{r.verdict.value}] alloc=L{r.alloc_line} write=L{r.write_line} var={r.var_name}")
        print(f"    reason: {r.reason}")
