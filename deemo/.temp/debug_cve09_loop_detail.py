#!/usr/bin/env python3
"""CVE_09 LoopAccumulation 详细信息."""
import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\tests\regression_heap")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.import_resolver import resolve_call_targets
from modules.analysis.static.loop_write_accumulator import LoopWriteAccumulator

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\vuln\sample_bins\heap_overflow_cve\CVE_09\vuln_CVE_09.exe"
instructions, file_format, main_addr, user_ranges = disassemble_binary(binary)
instructions = resolve_call_targets(binary, instructions, file_format)

detector = HeapOverflowDetector(allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)
for ins in instructions:
    detector.analyze_instruction(ins)

# 直接访问内部
loop_acc = LoopWriteAccumulator(use_win64_abi=True)
loop_acc._loops = loop_acc._detect_loops(instructions)
for loop in loop_acc._loops:
    s_idx = loop_acc._resolver.find_func_start(instructions, loop.header_addr)
    e_idx = loop_acc._resolver.find_func_end(instructions, loop.back_edge_addr)
    accum = loop_acc._trace_loop_writes(instructions, loop, detector._alloc_tracker)
    if accum:
        loop_acc._accumulations.extend(accum)

for accum in loop_acc._accumulations:
    alloc = detector._alloc_tracker._allocations.get(accum.alloc_addr)
    raw_size = getattr(alloc, 'raw_alloc_size', alloc.alloc_size) if alloc else None
    print(f"alloc_addr=0x{accum.alloc_addr:x}")
    print(f"  ptr_reg={accum.ptr_reg}")
    print(f"  single_write_size={accum.single_write_size}")
    print(f"  write_count={accum.write_count}")
    print(f"  loop.trip_count={accum.loop.trip_count}")
    print(f"  loop.is_known_count={accum.loop.is_known_count}")
    print(f"  loop.counter_reg={accum.loop.counter_reg}")
    print(f"  loop.header=0x{accum.loop.header_addr:x}")
    print(f"  loop.back_edge=0x{accum.loop.back_edge_addr:x}")
    print(f"  raw_size={raw_size}")
    if raw_size:
        total = accum.single_write_size * accum.loop.trip_count
        print(f"  total_write={total} vs alloc_size={raw_size.hi}")
        print(f"  overflow: {total - raw_size.hi}")
