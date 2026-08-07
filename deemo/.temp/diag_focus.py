#!/usr/bin/env python3
"""重点诊断: sudo/0185/libssh2等堆溢出样本的约束追踪."""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import extract_candidates_from_code
from core.cj_solver import solve_candidate
from core.cj_constraint_types import SolverVerdict
from core.cj_constraint_collector import collect_constraints

SAMPLES_DIR = os.path.join(r"C:\Users\Administrator\Desktop\BinMind\deemo\samples\cve_gapsbv")

# 重点样本: sudo(数组索引), 0185(双段memcpy), libssh2(大小不一致)
focus = ['cve_2021_3156_sudo', 'cve_2022_0185_kernel', 'cve_2019_1010298_libssh2',
         'cve_2020_10713_grub2']

with open(os.path.join(SAMPLES_DIR, 'ground_truth.json'), 'r', encoding='utf-8') as f:
    gt = json.load(f)

for name in focus:
    vuln_c = os.path.join(SAMPLES_DIR, name, 'vuln.c')
    if not os.path.exists(vuln_c):
        continue
    code = open(vuln_c, 'r', encoding='utf-8', errors='replace').read()
    candidates, ir_lines = extract_candidates_from_code(code)
    
    print(f"\n{'='*60}")
    print(f"=== {name} ===")
    print(f"{'='*60}")
    for j, c in enumerate(candidates):
        print(f"\nCandidate [{j}]:")
        print(f"  alloc: {c.alloc_site.alloc_func}({c.alloc_site.size_arg}) var={c.alloc_site.result_var}")
        print(f"  store: {c.overflow_store.mnemonic} offset={c.overflow_store.offset}")
        
        sys_obj = collect_constraints(c, ir_lines, code)
        print(f"  alloc_var={sys_obj.alloc_var} alloc_size={sys_obj.alloc_size}")
        print(f"  copy_var={sys_obj.copy_var} copy_size={sys_obj.copy_size}")
        print(f"  offset_var={sys_obj.offset_var} offset_val={sys_obj.offset_val}")
        print(f"  loop_var={sys_obj.loop_var} loop_bound={sys_obj.loop_bound}")
        print(f"  constraints={len(sys_obj.constraints)}")
        for k, con in enumerate(sys_obj.constraints):
            print(f"    [{k}] {con.description}")
        
        res, _ = solve_candidate(c, ir_lines, code)
        print(f"  verdict={res.verdict} reason={res.reason[:100]}")
