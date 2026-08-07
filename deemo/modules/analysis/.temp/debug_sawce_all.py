import sys, json
from pathlib import Path
PROJECT_ROOT = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo')
sys.path.insert(0, str(PROJECT_ROOT))
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

base = PROJECT_ROOT / 'modules/analysis/benchmark/samples_sawce'
# Test all 5 O0 samples
for name in ['sawce_same_source', 'sawce_derived_boundary', 'sawce_loop_accumulate',
             'sawce_nested_call', 'sawce_arithmetic']:
    for opt in ['O0', 'O2', 'Os']:
        binary = str(base / name / f'{name}_{opt}.exe')
        if not Path(binary).exists():
            continue
        ins, fmt, main_addr, ranges = disassemble_binary(binary)
        det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi='pei' in fmt.lower())
        det.set_min_user_addr(main_addr)
        det.set_user_func_ranges(ranges)
        det.pre_analyze(ins)
        for i in ins:
            det.analyze_instruction(i)
        findings = det.finalize(ins)
        n_raw = len(det._raw_findings)
        n_fin = len(findings)
        smt = det.stats.get("ddssc_coordinator",{}).get("smt_solver",{})
        z3 = smt.get("z3_available","?")
        stage8 = det.stats.get("ddssc_filter",{}).get("stage8_smt_filtered",0)
        # Determine the correct expected result
        manifest = json.loads(Path(base / "sawce_manifest.json").read_text(encoding="utf-8-sig"))
        entry = [e for e in manifest if e["name"] == name and e["opt"] == opt][0]
        expected = entry["expected_vulnerable"]
        result = "TP" if (n_fin > 0 and expected) else "FN" if (n_fin == 0 and expected) else "FP" if (n_fin > 0 and not expected) else "TN"
        print(f'{name}_{opt}: raw={n_raw} final={n_fin} z3={z3} s8={stage8} exp={expected} -> {result}')
