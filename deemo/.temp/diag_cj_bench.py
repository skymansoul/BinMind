#!/usr/bin/env python3
"""诊断CJ基准测试: 新提取器对各CVE样本的候选提取结果."""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import extract_candidates_from_code
from core.cj_solver import solve_candidate
from core.cj_constraint_types import SolverVerdict

SAMPLES_DIR = os.path.join(r"C:\Users\Administrator\Desktop\BinMind\deemo\samples\cve_gapsbv")

with open(os.path.join(SAMPLES_DIR, 'ground_truth.json'), 'r', encoding='utf-8') as f:
    gt = json.load(f)

for name, info in list(gt.items())[:5]:
    vuln_c = os.path.join(SAMPLES_DIR, name, 'vuln.c')
    if not os.path.exists(vuln_c):
        continue
    code = open(vuln_c, 'r', encoding='utf-8', errors='replace').read()
    candidates, ir_lines = extract_candidates_from_code(code)
    print(f"\n=== {name} === (is_vuln={info.get('is_vuln', True)})")
    print(f"  Candidates extracted: {len(candidates)}")
    for j, c in enumerate(candidates):
        print(f"  [{j}] alloc={c.alloc_site.alloc_func}({c.alloc_site.size_arg}) "
              f"var={c.alloc_site.result_var} write={c.overflow_store.mnemonic} "
              f"offset={c.overflow_store.offset} offset_dyn={c.overflow_store.offset_is_dynamic} "
              f"desc={c.description}")
        # 求解
        res, _ = solve_candidate(c, ir_lines, code)
        print(f"      verdict={res.verdict} reason={res.reason[:80] if res.reason else 'N/A'}")
