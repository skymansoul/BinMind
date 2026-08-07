#!/usr/bin/env python3
"""CVE_09 调试 — 追踪raw finding被过滤的stage."""
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
    print(f"  alloc_addr=0x{rf.get('alloc_addr',0):x}")
    print(f"  write_addr=0x{rf.get('write_addr',0):x}")
    print(f"  alloc_size={rf.get('alloc_size')}")
    print(f"  alloc_size_range={rf.get('alloc_size_range')}")
    print(f"  write_size={rf.get('write_size')}")
    print(f"  size_operand={rf.get('size_operand')}")
    print(f"  ptr_operand={rf.get('ptr_operand')}")
    print(f"  _write_sym_expr={rf.get('_write_sym_expr')}")
    print(f"  _snapshot_alloc_addr=0x{rf.get('_snapshot_alloc_addr',0):x}")

# 调用finalize，但先看dedup和stage4
deduped = detector._dedup_by_alloc(detector._raw_findings)
print(f"\nDeduped: {len(deduped)}")

for f in deduped:
    size_op = f.get("size_operand", "")
    alloc_sz = f.get("alloc_size", 0)
    write_addr = f.get("write_addr", 0)
    print(f"\n  Stage4 check: size_op={size_op}, alloc_sz={alloc_sz}, write_addr=0x{write_addr:x}")
    narrowed = detector._ps_vra.narrow_for_bounds_check(
        detector._instructions, write_addr, size_op)
    print(f"  narrowed={narrowed}")
    if narrowed:
        print(f"  narrowed.hi={narrowed.hi} <= alloc_sz={alloc_sz}? {narrowed.hi <= alloc_sz}")

findings = detector.finalize(instructions)
print(f"\nFinal findings: {len(findings)}")
