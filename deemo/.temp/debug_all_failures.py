#!/usr/bin/env python3
"""逐个分析17个失败样本的根因."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.asip_source_detector import (
    extract_candidates_v2, _extract_allocs, _extract_writes,
    _extract_clamps, _extract_guards, _extract_loop_bounds,
    _extract_reallocs,
)

from eval.asip_cve_samples import ALL_SAMPLES

# 失败样本
fail_names = {
    'cve_02', 'cve_03', 'cve_04', 'cve_06', 'cve_09', 'cve_10',
    'cve_27', 'cve_28', 'cve_31', 'cve_34', 'cve_37',
    'cve_50', 'cve_51', 'cve_52', 'cve_53', 'cve_54', 'cve_55',
}

for name, source, expected in ALL_SAMPLES:
    if name not in fail_names:
        continue
    lines = source.strip().split('\n')
    allocs = _extract_allocs(lines)
    clamps = _extract_clamps(lines)
    guards = _extract_guards(lines)
    loops = _extract_loop_bounds(lines)
    reallocs = _extract_reallocs(lines)
    cands = extract_candidates_v2(source)

    print(f"\n=== {name} (expected={expected}) ===")
    print(f"  allocs={allocs}")
    print(f"  clamps={clamps}, guards={guards}, loops={loops}, reallocs={reallocs}")
    for a in allocs:
        writes = _extract_writes(lines, a)
        print(f"  writes for {a.result_var}: {writes}")
    print(f"  candidates: {len(cands)}")
    for c in cands:
        print(f"    {c.description}")
