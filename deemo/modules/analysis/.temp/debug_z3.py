import sys, json
from pathlib import Path
PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
sys.path.insert(0, str(PROJECT_ROOT))
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.demand_smt_solver import PathConstraintCollector, DemandDrivenSMTSolver
from modules.analysis.static.heap_constraint import Interval
from modules.analysis.static.value_range import ValueRange
from modules.analysis.static.sym_size_correlator import SymExpr

binary = str(PROJECT_ROOT / 'modules/analysis/benchmark/samples/cve_2021_3156_sudo/cve_2021_3156_sudo_heap_O0.exe')
ins, fmt, main_addr, ranges = disassemble_binary(binary)

write_addr = 0x1400017c8
constants = {}

# Collect path constraints
collector = PathConstraintCollector()
pcs = collector.collect(ins, write_addr, constants)
print(f"Path constraints collected: {len(pcs)}")
for pc in pcs:
    print(f"  {pc}")

# Run Z3 solver manually
solver = DemandDrivenSMTSolver()
print(f"\nZ3 available: {solver.z3_available}")
print(f"Has _z3_solve: {hasattr(solver, '_z3_solve')}")

# Test with specific intervals
alloc_vr = ValueRange(64, 64)
write_vr = ValueRange(0, 256)
result = solver.verify_overflow(
    ins, write_addr, None, None, alloc_vr, write_vr, constants)
print(f"\nverify_overflow result: {result}")
print(f"Stats: {solver.stats}")
