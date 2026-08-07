#!/usr/bin/env python3
"""全量诊断: 所有CVE样本的候选提取和求解结果."""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import extract_candidates_from_code
from core.cj_solver import solve_candidate
from core.cj_constraint_types import SolverVerdict

SAMPLES_DIR = os.path.join(r"C:\Users\Administrator\Desktop\BinMind\deemo\samples\cve_gapsbv")

with open(os.path.join(SAMPLES_DIR, 'ground_truth.json'), 'r', encoding='utf-8') as f:
    gt = json.load(f)

for name, info in gt.items():
    vuln_c = os.path.join(SAMPLES_DIR, name, 'vuln.c')
    if not os.path.exists(vuln_c):
        continue
    code = open(vuln_c, 'r', encoding='utf-8', errors='replace').read()
    candidates, ir_lines = extract_candidates_from_code(code)
    
    verdicts = []
    reasons = []
    for c in candidates:
        res, _ = solve_candidate(c, ir_lines, code)
        v = 'OVERFLOW' if res.verdict == SolverVerdict.PROVEN_OVERFLOW else \
            'SAFE' if res.verdict == SolverVerdict.PROVEN_SAFE else 'INC'
        verdicts.append(v)
        reasons.append(res.reason[:60] if res.reason else '')
    
    detected = 'OVERFLOW' in verdicts
    status = 'OK' if (info.get('is_vuln', True) == detected) else 'MISS'
    print(f"[{status}] {name}: {len(candidates)} cands, verdicts={verdicts}")
    for j, c in enumerate(candidates):
        print(f"  [{j}] alloc={c.alloc_site.alloc_func}({c.alloc_site.size_arg}) "
              f"var={c.alloc_site.result_var} write={c.overflow_store.mnemonic} "
              f"offset={c.overflow_store.offset} -> {verdicts[j]} {reasons[j]}")
