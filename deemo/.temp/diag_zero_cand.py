#!/usr/bin/env python3
"""诊断0候选CVE样本."""
import sys, os, re
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.source_level_candidate_extractor import (
    extract_candidates_from_code, _extract_alloc_sites, _is_heap_var
)

SAMPLES_DIR = os.path.join(r"C:\Users\Administrator\Desktop\BinMind\deemo\samples\cve_gapsbv")
zero_cand = ['cve_2015_0235_ghost', 'cve_2017_1000252_kvm', 
             'cve_2017_11176_mq_notify', 'cve_2018_6552_kernel',
             'cve_2023_2235_kernel']

for name in zero_cand:
    vuln_c = os.path.join(SAMPLES_DIR, name, 'vuln.c')
    if not os.path.exists(vuln_c):
        print(f"\n=== {name}: FILE NOT FOUND ===")
        continue
    code = open(vuln_c, 'r', encoding='utf-8', errors='replace').read()
    
    # 预处理
    code_clean = re.sub(r'/\*.*?\*/', '', code, flags=re.DOTALL)
    code_clean = re.sub(r'//[^\n]*', '', code_clean)
    lines = code_clean.strip().split('\n')
    ir = [l.strip() for l in lines if l.strip()]
    
    print(f"\n=== {name} ===")
    # 检查malloc/calloc/realloc
    for i, line in enumerate(ir):
        if re.search(r'malloc\s*\(', line):
            print(f"  Line {i}: [MALLOC] {line[:80]}")
        if re.search(r'calloc\s*\(', line):
            print(f"  Line {i}: [CALLOC] {line[:80]}")
        if re.search(r'realloc\s*\(', line):
            print(f"  Line {i}: [REALLOC] {line[:80]}")
        # 写入
        if re.search(r'memcpy\s*\(', line):
            print(f"  Line {i}: [MEMCPY] {line[:80]}")
        if re.search(r'strcpy\s*\(', line):
            print(f"  Line {i}: [STRCPY] {line[:80]}")
        if re.search(r'memset\s*\(', line):
            print(f"  Line {i}: [MEMSET] {line[:80]}")
        if re.search(r'\w+\s*\[\s*\w+\s*\]\s*=', line):
            print(f"  Line {i}: [ARRAY_IDX] {line[:80]}")
    
    struct_defs = {}
    code_joined = ' '.join(ir)
    for sm in re.finditer(r'typedef\s+struct\s*\{([^}]*)\}\s*(\w+)', code_joined):
        struct_defs[sm.group(2)] = sm.group(1)
    
    alloc_sites = _extract_alloc_sites(ir, struct_defs)
    print(f"  Alloc sites: {len(alloc_sites)}")
    for a in alloc_sites:
        print(f"    pc={a['pc']} func={a['func']} var={a['var']} size={a['size_arg']} is_dyn={a['is_dyn']}")
    
    candidates, _ = extract_candidates_from_code(code)
    print(f"  Candidates: {len(candidates)}")
