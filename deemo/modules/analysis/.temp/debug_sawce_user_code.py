# 调试具体FP finding的来源 — 看哪些finding的write_addr在用户函数范围内
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

SAWCE_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmark", "samples_sawce")

FP_PATTERNS = ["sawce_derived_boundary", "sawce_nested_call", "sawce_arithmetic"]
OPTS = ["O0", "O2", "Os"]

for pattern in FP_PATTERNS:
    for opt in OPTS:
        exe = os.path.join(SAWCE_DIR, pattern, f"{pattern}_{opt}.exe")
        if not os.path.exists(exe):
            continue

        ins, fmt, main_addr, ranges = disassemble_binary(exe)
        win64 = "pei" in fmt.lower()

        detector = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi=win64)
        if main_addr:
            detector.set_min_user_addr(main_addr)
        if ranges:
            detector.set_user_func_ranges(ranges)
        detector.pre_analyze(ins)
        for i in ins:
            detector.analyze_instruction(i)
        findings = detector.finalize(ins)

        print(f"\n{'='*60}")
        print(f"{pattern} ({opt}) — main=0x{main_addr:x} ranges={len(ranges)}")
        for lo, hi in ranges[:5]:
            print(f"  range: 0x{lo:x}-0x{hi:x}")
        for f in findings:
            wa = f.get("write_addr", 0)
            in_user = detector._is_user_code(wa)
            alloc_addr = f.get("_snapshot_alloc_addr", f.get("alloc_addr", 0))
            in_user_alloc = detector._is_user_code(alloc_addr)
            print(f"  finding: write=0x{wa:x} alloc=0x{alloc_addr:x} "
                  f"alloc_sz={f.get('alloc_size',0)} write_sz={f.get('write_size',0)} "
                  f"note={f.get('note','')} "
                  f"write_in_user={in_user} alloc_in_user={in_user_alloc}")
            # 看附近指令
            for i_idx, i in enumerate(ins):
                ia = i.get("address", 0)
                if abs(ia - wa) < 0x20:
                    print(f"    0x{ia:x} {i.get('mnemonic','')} {i.get('operands',[])}")
