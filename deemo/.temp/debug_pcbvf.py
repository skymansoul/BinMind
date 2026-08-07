#!/usr/bin/env python3
"""调试PC-BVF失败case: 打印IR/候选/约束/判定结果."""
import sys, os, json
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from pathlib import Path
from core.cj_solver import solve_candidate
from core.cj_constraint_types import SolverVerdict
from core.cj_pcbvf_constraints import extract_path_constraints
from core.cj_pcbvf_correlator import correlate_with_constraints
from core.cj_bvf_tracer import BackwardValueFlow, SymbolicExpr
from core.cj_bvf_types import CorrelationResult
from tests.bvf_candidate_extractor import extract_candidates_from_code

PCBVF_SAMPLES_DIR = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo\tests\pcbvf_samples")

FAIL_NAMES = ['pcbvf_02', 'pcbvf_04', 'pcbvf_07', 'pcbvf_10', 'pcbvf_12']

for name in FAIL_NAMES:
    sample_dir = PCBVF_SAMPLES_DIR / name
    vuln_c = sample_dir / 'vuln.c'
    code = vuln_c.read_text(encoding='utf-8', errors='replace')
    candidates, ir_lines = extract_candidates_from_code(code)

    print(f"\n{'='*70}")
    print(f"=== {name} ===")
    print(f"{'='*70}")
    print(f"Source:\n{code}")
    print(f"\nIR lines ({len(ir_lines)}):")
    for i, line in enumerate(ir_lines):
        print(f"  [{i}] {line}")

    print(f"\nCandidates: {len(candidates)}")
    for ci, c in enumerate(candidates):
        print(f"\n  Candidate {ci}:")
        print(f"    alloc_func={c.alloc_site.alloc_func}, size_arg={c.alloc_site.size_arg}, size_is_dynamic={c.alloc_site.size_is_dynamic}")
        print(f"    overflow_store: mnemonic={c.overflow_store.mnemonic}, store_size={c.overflow_store.store_size}, pc={c.overflow_store.pc}")
        print(f"    offset={c.overflow_store.offset}, offset_is_dynamic={c.overflow_store.offset_is_dynamic}")
        
        # Run solve_candidate
        result, detail = solve_candidate(c, ir_lines, code)
        print(f"    solve_candidate verdict={result.verdict}, reason={result.reason[:120]}")
        print(f"    proof_chain:")
        for pc in result.proof_chain:
            print(f"      - {pc[:120]}")

        # Debug: manually extract constraints
        bounds = extract_path_constraints(ir_lines, c.overflow_store.pc, window=60)
        print(f"\n    PC-BVF extracted bounds: { {k: str(v) for k, v in bounds.items()} }")

        # Debug: manually trace alloc/write
        bvf = BackwardValueFlow()
        alloc = c.alloc_site
        alloc_expr = bvf.trace_alloc_size(
            ir_lines, alloc.alloc_func,
            alloc.size_expr if alloc.size_is_dynamic else str(alloc.size_arg),
            alloc.pc)
        if alloc.size_arg > 0 and not alloc.size_is_dynamic:
            alloc_expr = SymbolicExpr(const=float(alloc.size_arg), origin=f"const_alloc:{alloc.size_arg}")
        print(f"    alloc_expr = {alloc_expr}")

        store = c.overflow_store
        if store.mnemonic in ('strcpy', 'strcat'):
            write_expr = None
            print(f"    write_expr = None (strcpy/strcat)")
        elif store.store_size > 0:
            write_expr = SymbolicExpr(const=float(store.store_size), origin=f"store_size:{store.store_size}")
            print(f"    write_expr = {write_expr}")
        elif store.mnemonic in ('memcpy', 'memmove', 'strncpy', 'memset', 'strncat'):
            write_expr = bvf.trace_write_size(ir_lines, store.pc, store.mnemonic, store.store_size)
            print(f"    write_expr = {write_expr}")
        else:
            write_expr = SymbolicExpr(const=float(store.store_size if store.store_size > 0 else 4))
            print(f"    write_expr = {write_expr}")

        if not store.offset_is_dynamic and store.offset >= 0:
            offset_expr = SymbolicExpr(const=float(store.offset))
        elif store.offset_is_dynamic:
            offset_expr = bvf.trace_var(ir_lines, "offset", store.pc)
        else:
            offset_expr = SymbolicExpr(const=0.0)
        print(f"    offset_expr = {offset_expr}")

        # Run correlate_with_constraints directly
        if bounds and write_expr:
            with_offset = offset_expr.eval_const() if offset_expr else 0.0
            print(f"    offset_val = {with_offset}")
            corr_result = correlate_with_constraints(alloc_expr, write_expr, offset_expr, bounds)
            print(f"    correlate result: proven_safe={corr_result.proven_safe}, proven_overflow={corr_result.proven_overflow}")
            print(f"    correlate reason: {corr_result.reason[:200]}")
            print(f"    shared_vars: {corr_result.shared_vars}")
