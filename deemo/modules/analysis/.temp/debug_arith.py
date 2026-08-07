import sys, json
from pathlib import Path
PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
sys.path.insert(0, str(PROJECT_ROOT))
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

base = PROJECT_ROOT / 'modules/analysis/benchmark/samples_sawce'

for name in ['sawce_arithmetic', 'sawce_derived_boundary']:
    binary = str(base / name / f'{name}_O0.exe')
    print(f"\n{'='*50}")
    print(f"Sample: {name}")
    print(f"{'='*50}")
    ins, fmt, main_addr, ranges = disassemble_binary(binary)
    det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi='pei' in fmt.lower())
    det.set_min_user_addr(main_addr)
    det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    
    print(f"Raw findings: {len(det._raw_findings)}")
    for f in det._raw_findings:
        print(f"  write_addr=0x{f.get('write_addr',0):x} alloc={f.get('alloc_size',0)} write={f.get('write_size',0)}")
        print(f"  size_reg={f.get('size_operand','')} ptr={f.get('ptr_operand','')}")
        print(f"  _snapshot_alloc_addr={f.get('_snapshot_alloc_addr','')}")
        print(f"  _write_sym_expr={f.get('_write_sym_expr','')}")
    
    # Check sym_snapshots
    print(f"  sym_snapshots: {det._sym_snapshots}")
    
    findings = det.finalize(ins)
    print(f"Final: {len(findings)}")
    for f in findings:
        print(f"  fp_stage={f.get('fp_stage','')} fp_reason={f.get('fp_reason','')}")
    print(f"DDSSC: {json.dumps(det.stats['ddssc_coordinator'], indent=2)}")
    print(f"SAWCE: {json.dumps(det.stats['sawce_correlator'], indent=2)}")
