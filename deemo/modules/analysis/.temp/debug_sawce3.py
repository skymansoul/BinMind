import sys, json
from pathlib import Path
PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
sys.path.insert(0, str(PROJECT_ROOT))
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

base = PROJECT_ROOT / 'modules/analysis/benchmark/samples_sawce'
for name in ['sawce_derived_boundary', 'sawce_arithmetic', 'sawce_same_source']:
    binary = str(base / name / (name + '_O0.exe'))
    ins, fmt, main_addr, ranges = disassemble_binary(binary)
    det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi='pei' in fmt.lower())
    det.set_min_user_addr(main_addr)
    det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    findings = det.finalize(ins)
    print(f'{name}: raw={len(det._raw_findings)} final={len(findings)}')
    for f in det._raw_findings:
        wa = f.get("write_addr",0)
        al = f.get("alloc_size",0)
        wr = f.get("write_size",0)
        print(f'  RAW: addr=0x{wa:x} alloc={al} write={wr}')
    for f in findings:
        wa = f.get("write_addr",0)
        al = f.get("alloc_size",0)
        wr = f.get("write_size",0)
        fp = f.get("fp_stage","")
        print(f'  FIN: addr=0x{wa:x} alloc={al} write={wr} fp={fp}')
    smt = det.stats.get("ddssc_coordinator",{}).get("smt_solver",{})
    print(f'  z3_available: {smt.get("z3_available","?")}')
