#!/usr/bin/env python3
"""CVE_09 调试 — 逐Stage追踪finding被过滤的位置."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_09\vuln_CVE_09.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)

for ins in instructions:
    detector.analyze_instruction(ins)

print(f"Raw findings: {len(detector._raw_findings)}")
for rf in detector._raw_findings:
    print(f"  note={rf.get('note','')}")
    print(f"  alloc_size={rf.get('alloc_size')}")
    print(f"  size_operand={rf.get('size_operand')}")

# 手动逐Stage测试
deduped = detector._dedup_by_alloc(detector._raw_findings)
print(f"\nAfter dedup: {len(deduped)}")

# Stage4
s4 = []
for f in deduped:
    ret = detector._stage4_path_sensitive_check(f)
    print(f"  Stage4: {ret} (note={f.get('note','')}, alloc_sz={f.get('alloc_size',0)})")
    if ret:
        s4.append(f)
print(f"After Stage4: {len(s4)}")

# Stage5
s5 = []
for f in s4:
    ret = detector._stage5_struct_field_check(f)
    print(f"  Stage5: {ret} (ptr_operand={f.get('ptr_operand','')}, write_size={f.get('write_size',0)})")
    if ret:
        s5.append(f)
print(f"After Stage5: {len(s5)}")

# Stage1-2-3 (HeapFPFilter)
s123 = detector._fp_filter.filter(s5, instructions, detector._alloc_tracker)
print(f"After Stage1-2-3: {len(s123)}")
for f in s123:
    print(f"  surviving: write_addr=0x{f.get('write_addr',0):x}")

# DDSSC Stage6/7/8
sym_expr_map = detector._build_sym_expr_map(s123)
s678 = detector._ddssc_filter.filter(
    s123, instructions, detector._alloc_tracker,
    detector._known_constants, sym_expr_map)
print(f"After DDSSC Stage6/7/8: {len(s678)}")

# SAWCE Stage9
detector._struct_size_tracker.set_instructions(instructions)
detector._struct_size_tracker.reset()
for ins in instructions:
    detector._struct_size_tracker.process(ins)
corr_results = detector._symbolic_correlator.correlate(
    detector._struct_size_tracker, detector._alloc_tracker)
s9 = []
for f in s678:
    filter_reason = detector._symbolic_correlator.filter_finding(f, corr_results)
    print(f"  Stage9 filter_reason: {filter_reason}")
    if filter_reason:
        continue
    s9.append(f)
print(f"After Stage9: {len(s9)}")

# Stage10 Loop
loop_findings = detector._loop_accumulator.analyze(
    instructions, detector._alloc_tracker, use_win64_abi=True)
print(f"\nStage10 loop_findings: {len(loop_findings)}")
print(f"  loops_detected={detector._loop_accumulator.stats.get('loops_detected')}")
print(f"  accumulations_tracked={detector._loop_accumulator.stats.get('accumulations_tracked')}")

# Final
findings = detector.finalize(instructions)
print(f"\nFinal findings: {len(findings)}")
