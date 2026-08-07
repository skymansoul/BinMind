#!/usr/bin/env python3
"""调试剩余13个失败样本."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import (
    extract_candidates_v3, _extract_allocs, _extract_writes,
    _extract_guard_limits, _extract_clamp_limits, _extract_loop_bounds,
    _extract_modulo_protections, _extract_cross_function_writes,
    _extract_reallocs,
)

fail_names = {
    'cve_04', 'cve_10', 'cve_16', 'cve_18', 'cve_25',
    'cve_27', 'cve_31', 'cve_34', 'cve_36', 'cve_37',
    'cve_38', 'cve_39', 'cve_55',
}

from eval.asip_cve_samples import ALL_SAMPLES
for name, source, expected in ALL_SAMPLES:
    if name not in fail_names:
        continue
    lines = source.strip().split('\n')
    allocs = _extract_allocs(lines)
    guards = _extract_guard_limits(lines)
    clamps = _extract_clamp_limits(lines)
    loops = _extract_loop_bounds(lines)
    reallocs = _extract_reallocs(lines)
    modulos = _extract_modulo_protections(lines)
    cross = _extract_cross_function_writes(lines)
    cands = extract_candidates_v3(source)
    
    print(f"\n=== {name} (expected={expected}) ===")
    print(f"  allocs: {[(a.result_var, a.size_arg, a.size_is_dynamic) for a in allocs]}")
    print(f"  guards: {guards}, clamps: {clamps}")
    print(f"  loops: {loops}, reallocs: {reallocs}")
    print(f"  modulos: {modulos}")
    print(f"  cross_writes: {list(cross.keys())}")
    for a in allocs:
        ws = _extract_writes(lines, a)
        print(f"  writes for {a.result_var}: {[(s.mnemonic, s.offset, s.offset_is_dynamic, s.store_size, sz) for s, sz in ws]}")
    print(f"  candidates: {len(cands)}")
    for c in cands:
        print(f"    {c.description}")
