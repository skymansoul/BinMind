# 调试SAWCE Stage 9/10在same_source样本上的行为
import sys, json
from pathlib import Path

PROJECT_ROOT = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.symbolic_size_expr import SymbolicSizeTracker
from modules.analysis.static.symbolic_correlator import SymbolicCorrelator
from modules.analysis.static.loop_write_accumulator import LoopWriteAccumulator

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_same_source\sawce_same_source_O0.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)
print(f"Format: {fmt}, {len(ins)} instructions, {len(ranges)} ranges")

det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
det.set_min_user_addr(main_addr)
det.set_user_func_ranges(ranges)
det.pre_analyze(ins)
for i in ins:
    det.analyze_instruction(i)

print(f"\nRaw findings: {len(det._raw_findings)}")
for f in det._raw_findings:
    print(f"  addr=0x{f.get('write_addr',0):x} alloc={f.get('alloc_size',0)} write={f.get('write_size',0)} "
          f"ptr={f.get('ptr_operand','')} size_reg={f.get('size_operand','')}")
    print(f"    _snapshot_alloc_addr={f.get('_snapshot_alloc_addr','')}")
    print(f"    _write_sym_expr={f.get('_write_sym_expr','')}")

# 运行Stage 9
tracker = SymbolicSizeTracker()
tracker.set_instructions(ins)
tracker.reset()
for i in ins:
    tracker.process(i)

print(f"\n--- SymbolicSizeTracker state ---")
print(f"  _regs: {dict(tracker._regs)}" if hasattr(tracker, '_regs') else "  no _regs")
print(f"  _allocs: {dict(tracker._allocs)}" if hasattr(tracker, '_allocs') else "  no _allocs")

corr = SymbolicCorrelator()
results = corr.correlate(tracker, det._alloc_tracker)
print(f"\n--- Correlate results: {len(results)} ---")
for r in results:
    print(f"  {r}")

# filter_finding per raw finding
for f in det._raw_findings:
    reason = corr.filter_finding(f, results)
    print(f"\n  Finding @0x{f.get('write_addr',0):x}: filter_reason={reason}")

# Run full finalize
findings = det.finalize(ins)
print(f"\n--- Finalize: {len(findings)} findings ---")
for f in findings:
    print(f"  addr=0x{f.get('write_addr',0):x} alloc={f.get('alloc_size',0)} write={f.get('write_size',0)}")
    print(f"    fp_stage={f.get('fp_stage','')} fp_reason={f.get('fp_reason','')}")
    print(f"    dangerous_func={f.get('dangerous_func','')}")

print(f"\n--- Stats ---")
print(json.dumps(det.stats, indent=2, default=str))
