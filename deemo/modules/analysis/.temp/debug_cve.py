import sys, json
from pathlib import Path
PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
sys.path.insert(0, str(PROJECT_ROOT))
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

# Test a CVE sample
binary_dir = PROJECT_ROOT / 'modules/analysis/benchmark/samples'
cve_dir = binary_dir / 'cve_2021_3156_sudo'
exes = sorted(cve_dir.glob('*heap*.exe'))
if not exes:
    exes = sorted(cve_dir.glob('*heap*'))
for exe in exes:
    binary = str(exe)
    print(f"\n{'='*60}")
    print(f"Binary: {exe.name}")
    print(f"{'='*60}")
    ins, fmt, main_addr, ranges = disassemble_binary(binary)
    print(f"Format: {fmt}, {len(ins)} ins, {len(ranges)} ranges")
    
    det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi='pei' in fmt.lower())
    det.set_min_user_addr(main_addr)
    det.set_user_func_ranges(ranges)
    det.pre_analyze(ins)
    for i in ins:
        det.analyze_instruction(i)
    
    print(f"Raw findings: {len(det._raw_findings)}")
    for f in det._raw_findings:
        print(f"  RAW: addr=0x{f.get('write_addr',0):x} alloc={f.get('alloc_size',0)} "
              f"write={f.get('write_size',0)} size_reg={f.get('size_operand','')} "
              f"ptr={f.get('ptr_operand','')}")
        print(f"    _write_sym_expr={f.get('_write_sym_expr','')}")
        print(f"    _snapshot_alloc_addr={f.get('_snapshot_alloc_addr','')}")
    
    findings = det.finalize(ins)
    print(f"Final findings: {len(findings)}")
    for f in findings:
        print(f"  FIN: addr=0x{f.get('write_addr',0):x} fp_stage={f.get('fp_stage','')}")
    
    stats = det.stats
    print(f"\nDDSSC stats: {json.dumps(stats['ddssc_coordinator'], indent=2)}")
    print(f"DDSSC filter stats: {json.dumps(stats['ddssc_filter'], indent=2)}")
    break  # just first one
