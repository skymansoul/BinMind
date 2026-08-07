# 深度调试 loop_accumulate 的 accumulator 状态
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.loop_write_accumulator import LoopWriteAccumulator

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_O0.exe'
instrs, fmt, main_addr, user_ranges = disassemble_binary(binary)

detector = HeapOverflowDetector(
    allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instrs)
for ins in instrs:
    detector.analyze_instruction(ins)

# 在finalize之前手动运行loop accumulator来调试
loop_acc = LoopWriteAccumulator(use_win64_abi=True)
loop_acc._loops = loop_acc._detect_loops(instrs)
print(f"Loops detected: {len(loop_acc._loops)}")

# 找到 vuln 函数的循环
for loop in loop_acc._loops:
    if 0x140001760 <= loop.header_addr <= 0x1400017da:
        print(f"\n  Loop in vuln func: header=0x{loop.header_addr:x} back=0x{loop.back_edge_addr:x}")
        print(f"  body=[0x{loop.body_start:x}, 0x{loop.body_end:x}]")
        print(f"  trip_count={loop.trip_count} counter={loop.counter_reg} known={loop.is_known_count}")
        
        accum = loop_acc._trace_loop_writes(instrs, loop, detector._alloc_tracker)
        print(f"  accumulations: {len(accum)}")
        for a in accum:
            print(f"    alloc_addr=0x{a.alloc_addr:x} ptr={a.ptr_reg} single_write={a.single_write_size} count={a.write_count}")
            # check alloc size
            alloc = detector._alloc_tracker._allocations.get(a.alloc_addr)
            if alloc:
                raw = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
                print(f"    alloc raw_size={raw} alloc_size={alloc.alloc_size}")
                total = a.single_write_size * loop.trip_count
                print(f"    total_write={total} vs alloc_size_hi={raw.hi} → overflow={total > raw.hi}")
            else:
                print(f"    alloc NOT FOUND in tracker")

# 也检查 safe 函数
print("\n--- Safe function loops ---")
for loop in loop_acc._loops:
    if 0x1400017da <= loop.header_addr <= 0x140001854:
        print(f"\n  Loop in safe func: header=0x{loop.header_addr:x} back=0x{loop.back_edge_addr:x}")
        print(f"  trip_count={loop.trip_count} counter={loop.counter_reg} known={loop.is_known_count}")
        accum = loop_acc._trace_loop_writes(instrs, loop, detector._alloc_tracker)
        print(f"  accumulations: {len(accum)}")
        for a in accum:
            print(f"    alloc_addr=0x{a.alloc_addr:x} single_write={a.single_write_size} count={a.write_count}")
            alloc = detector._alloc_tracker._allocations.get(a.alloc_addr)
            if alloc:
                raw = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
                print(f"    alloc raw_size={raw} alloc_size={alloc.alloc_size}")
                total = a.single_write_size * loop.trip_count
                print(f"    total_write={total} vs alloc_size_hi={raw.hi} → overflow={total > raw.hi}")

# 检查alloc_tracker中所有allocations
print("\n--- All allocations in tracker ---")
for addr, alloc in detector._alloc_tracker._allocations.items():
    raw = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
    print(f"  addr=0x{addr:x} raw_size={raw} alloc_size={alloc.alloc_size} ptr_reg={alloc.ptr_reg}")
