# 调试多个SAWCE样本
import sys, json
from pathlib import Path

PROJECT_ROOT = Path(r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, str(PROJECT_ROOT))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.loop_write_accumulator import LoopWriteAccumulator

samples = {
    "derived_boundary": r"samples_sawce\sawce_derived_boundary\sawce_derived_boundary_O0.exe",
    "loop_accumulate": r"samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_O0.exe",
    "arithmetic": r"samples_sawce\sawce_arithmetic\sawce_arithmetic_O0.exe",
}

base = PROJECT_ROOT / "modules" / "analysis" / "benchmark"

for name, rel in samples.items():
    binary = str(base / rel)
    print(f"\n{'='*60}")
    print(f"Sample: {name}")
    print(f"{'='*60}")
    
    ins, fmt, main_addr, ranges = disassemble_binary(binary)
    
    det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
    det.set_min_user_addr(main_addr)
    det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    findings = det.finalize(ins)
    
    print(f"Raw findings: {len(det._raw_findings)}")
    for f in det._raw_findings:
        print(f"  addr=0x{f.get('write_addr',0):x} alloc={f.get('alloc_size',0)} "
              f"write={f.get('write_size',0)} ptr={f.get('ptr_operand','')} "
              f"size_reg={f.get('size_operand','')} func={f.get('dangerous_func','')}")
    
    print(f"Final findings: {len(findings)}")
    for f in findings:
        print(f"  addr=0x{f.get('write_addr',0):x} alloc={f.get('alloc_size',0)} "
              f"write={f.get('write_size',0)} fp_stage={f.get('fp_stage','')} "
              f"func={f.get('dangerous_func','')}")
    
    # Check loop accumulator
    la = LoopWriteAccumulator()
    lf = la.analyze(ins, det._alloc_tracker)
    print(f"Loop findings: {len(lf)}")
    print(f"  stats: {la.stats}")
    
    print(f"Stats: {json.dumps(det.stats, indent=2, default=str)}")
