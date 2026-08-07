#!/usr/bin/env python3
"""诊断源级验证器对每个失败样本的输出."""
import sys, os
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_types import HoVerdict

BASE = r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow"
FAIL_SAMPLES = [
    "cve_03_int_overflow_calc",
    "cve_07_realloc_overflow",
    "cve_08_calloc_overflow",
    "cve_09_safe_but_triggers_fp",
    "cve_11_memcpy_arith_size",
    "cve_13_struct_field_pattern",
    "cve_15_constrained_input",
    "cve_16_real_world_pattern",
    "cve_17_multi_field_struct",
]

v = HeapOverflowSrcVerifier()

for s in FAIL_SAMPLES:
    d = os.path.join(BASE, s)
    c_files = [f for f in os.listdir(d) if f.endswith('.c')]
    if not c_files:
        print(f"\n=== {s}: NO .C FILE ===")
        continue
    src = open(os.path.join(d, c_files[0]), encoding='utf-8', errors='replace').read()
    results = v.verify(src)
    
    print(f"\n=== {s} ({c_files[0]}) ===")
    print(f"  Results: {len(results)}")
    for r in results:
        print(f"    [{r.verdict.value}] L{r.alloc_line}→L{r.write_line} "
              f"var={r.var_name} alloc={r.alloc_size} write={r.write_size} "
              f"conf={r.confidence:.2f}")
        print(f"      reason: {r.reason}")
    
    # Also dump what find_allocs and find_writes detected
    from analysis.heap_overflow_src_phases import find_allocs, find_writes
    from analysis.heap_overflow_src_patterns import _skip_block_comments
    lines = src.splitlines()
    clean = _skip_block_comments(lines)
    valid = {ln for ln, _ in clean}
    allocs = find_allocs(lines, valid)
    writes = find_writes(lines, allocs, valid)
    print(f"  Allocs: {[(a.line, a.func, a.var, a.size_expr, a.size_const) for a in allocs]}")
    print(f"  Writes: {[(w.line, w.target, w.kind, w.write_size, w.offset) for w in writes]}")
