# SAWCE FP调试脚本 — 检查符号表达式追踪状态
import sys, os, json
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", ".."))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.symbolic_size_expr import SymbolicSizeTracker

SAWCE_DIR = os.path.join(os.path.dirname(__file__), "..", "benchmark", "samples_sawce")

FP_PATTERNS = ["sawce_derived_boundary", "sawce_nested_call", "sawce_arithmetic"]
OPTS = ["O0", "O2", "Os"]

for pattern in FP_PATTERNS:
    for opt in OPTS:
        exe = os.path.join(SAWCE_DIR, pattern, f"{pattern}_{opt}.exe")
        if not os.path.exists(exe):
            print(f"[SKIP] {exe}")
            continue

        ins, fmt, main_addr, ranges = disassemble_binary(exe)
        win64 = "pei" in fmt.lower()

        # 运行检测器获取findings
        detector = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi=win64)
        if main_addr:
            detector.set_min_user_addr(main_addr)
        if ranges:
            detector.set_user_func_ranges(ranges)
        detector.pre_analyze(ins)
        for i in ins:
            detector.analyze_instruction(i)
        findings = detector.finalize(ins)

        # 运行SymbolicSizeTracker获取表达式
        tracker = SymbolicSizeTracker()
        tracker.set_instructions(ins)
        tracker.reset()
        for i in ins:
            tracker.process(i)

        print(f"\n{'='*70}")
        print(f"Pattern: {pattern} ({opt}) — win64={win64}")
        print(f"  Findings: {len(findings)}")
        for f in findings:
            print(f"    write_addr=0x{f.get('write_addr',0):x} "
                  f"alloc_size={f.get('alloc_size',0)} "
                  f"write_size={f.get('write_size',0)} "
                  f"note={f.get('note','')} "
                  f"fp_stage={f.get('fp_stage','')} "
                  f"fp_reason={f.get('fp_reason','')}")
        print(f"  Alloc exprs: {len(tracker.alloc_exprs)}")
        for a_addr, a_func, a_expr in tracker.alloc_exprs:
            print(f"    addr=0x{a_addr:x} func={a_func} expr={a_expr.to_str()}")
        print(f"  Write exprs: {len(tracker.write_exprs)}")
        for w_addr, w_func, w_expr in tracker.write_exprs:
            print(f"    addr=0x{w_addr:x} func={w_func} expr={w_expr.to_str()}")

        # 检查correlator结果
        from modules.analysis.static.symbolic_correlator import SymbolicCorrelator
        corr = SymbolicCorrelator()
        results = corr.correlate(tracker, detector._alloc_tracker)
        print(f"  Correlator results: {len(results)}")
        for r in results:
            print(f"    verdict={r.verdict} reason={r.reason}")

        # 检查寄存器状态(最后一个call之前)
        print(f"  Reg state sample (first 10 regs):")
        for reg, expr in list(tracker._regs.items())[:10]:
            if not expr.is_unknown():
                print(f"    {reg} = {expr.to_str()}")
