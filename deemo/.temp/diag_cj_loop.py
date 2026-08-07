#!/usr/bin/env python3
"""诊断循环溢出CJ误判: malloc(32) + for(i<64) buf[i]='A'."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from core.cj_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem, SolverVerdict,
)
from core.cj_constraint_collector import collect_constraints
from core.cj_solver import ConstraintJoinSolver

# 模拟 malloc(32) + for(i=0;i<64;i++) buf[i]='A'
from core.heap_overflow_detector import HeapAllocSite, HeapStore, HeapOverflowCandidate

alloc = HeapAllocSite(
    pc=2,
    alloc_func="malloc",
    size_arg=32,
    size_is_dynamic=False,
)

store = HeapStore(
    pc=10,
    base_var="buf",
    offset=0,
    offset_is_dynamic=True,
    store_size=1,
    mnemonic="store",
)

candidate = HeapOverflowCandidate(
    alloc_site=alloc,
    overflow_store=store,
    confidence=0.50,
    description="loop write overflow",
)

ir_lines = [
    "main:",
    "  push rbp",
    "  mov rdi, 32",
    "  call malloc",          # pc=2
    "  mov buf, rax",
    "  xor i, i",             # i=0
    "loop_start:",
    "  cmp i, 64",            # pc=7
    "  jge loop_end",
    "  mov byte [buf + i], 0x41",  # pc=10 (write)
    "  inc i",
    "  jmp loop_start",
    "loop_end:",
    "  free(buf)",
    "  ret",
]

decompiled = """
char *buf = malloc(32);
for (int i = 0; i < 64; i++) {
    buf[i] = 'A';
}
free(buf);
"""

sys_obj = collect_constraints(candidate, ir_lines, decompiled)

print("=== ConstraintSystem ===")
print(f"alloc_var={sys_obj.alloc_var!r}, alloc_size={sys_obj.alloc_size}")
print(f"copy_var={sys_obj.copy_var!r}, copy_size={sys_obj.copy_size}")
print(f"offset_var={sys_obj.offset_var!r}, offset_val={sys_obj.offset_val}")
print(f"loop_var={sys_obj.loop_var!r}, loop_bound={sys_obj.loop_bound}")
print(f"mnemonic={sys_obj.mnemonic!r}, store_size={sys_obj.store_size}")
print(f"var_names={sys_obj.var_names}")
print(f"\nConstraints ({len(sys_obj.constraints)}):")
for i, c in enumerate(sys_obj.constraints):
    print(f"  [{i}] {c.coefficients} + {c.constant} {c.operator} 0  // {c.description}")

print("\n=== Solving ===")
solver = ConstraintJoinSolver("x86_64")
result = solver.solve(sys_obj)
print(f"Verdict: {result.verdict}")
print(f"Reason: {result.reason}")
print(f"Delta: {result.confidence_delta}")
for step in result.proof_chain:
    print(f"  {step}")

# 现在追踪 simplify 逻辑
print("\n=== Simplify trace ===")
simplified = solver._simplify(sys_obj)
print(f"Simplified constraints ({len(simplified.constraints)}):")
for i, c in enumerate(simplified.constraints):
    print(f"  [{i}] {c.coefficients} + {c.constant} {c.operator} 0  // {c.description}")

# 追踪 _compute_write_end
from core.cj_safety_prover import _compute_write_end, _evaluate_constant_write_end, _compute_usable_size
write_end_expr, desc = _compute_write_end(simplified)
print(f"\n_compute_write_end: expr={write_end_expr}, desc={desc}")
write_end_val = _evaluate_constant_write_end(simplified)
print(f"_evaluate_constant_write_end: {write_end_val}")
usable = _compute_usable_size(simplified, "x86_64")
print(f"_compute_usable_size: {usable}")
