#!/usr/bin/env python3
"""快速诊断: CJ求解器对CVE样本的检测效果."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.cj_solver import solve_candidate
from core.cj_constraint_types import SolverVerdict
from core.heap_overflow_detector import HeapAllocSite, HeapStore, HeapOverflowCandidate

# 测试几个关键模式
test_cases = [
    # (name, alloc_size, write_size, expected)
    ("simple_overflow", 32, 64, True),       # malloc(32)+memcpy(64) → OVERFLOW
    ("simple_safe", 64, 32, False),            # malloc(64)+memcpy(32) → SAFE
    ("boundary_safe", 32, 32, False),           # malloc(32)+memcpy(32) → SAFE
]

for name, alloc_sz, write_sz, expected_overflow in test_cases:
    alloc = HeapAllocSite(pc=0, alloc_func='malloc', size_arg=alloc_sz,
                          size_is_dynamic=False, result_var='buf')
    store = HeapStore(pc=1, base_var='buf', offset=0,
                      offset_is_dynamic=False, store_size=write_sz,
                      mnemonic='memcpy')
    cand = HeapOverflowCandidate(alloc_site=alloc, overflow_store=store,
                                 confidence=0.80, description=name)
    
    result = solve_candidate(cand)
    verdict = result.verdict if hasattr(result, 'verdict') else str(result)
    is_overflow = (verdict == SolverVerdict.PROVEN_OVERFLOW)
    ok = (is_overflow == expected_overflow)
    
    print(f"  [{'PASS' if ok else 'FAIL'}] {name}: verdict={verdict}, "
          f"overflow={is_overflow}, expected={expected_overflow}")
