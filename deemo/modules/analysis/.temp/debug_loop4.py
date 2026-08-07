# 检查 alloc_tracker._ptr_to_alloc 的最终状态
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_sawce\sawce_loop_accumulate\sawce_loop_accumulate_O0.exe'
instrs, fmt, main_addr, user_ranges = disassemble_binary(binary)

detector = HeapOverflowDetector(
    allocator=AllocatorFamily.GLIBC, use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instrs)
for ins in instrs:
    detector.analyze_instruction(ins)

ptr_map = detector._alloc_tracker._ptr_to_alloc
print("ptr_to_alloc mappings:")
for k, v in ptr_map.items():
    print(f"  {k} -> 0x{v:x}")

print("\nallocations:")
for addr, alloc in detector._alloc_tracker._allocations.items():
    raw = getattr(alloc, 'raw_alloc_size', alloc.alloc_size)
    print(f"  0x{addr:x}: raw={raw} alloc_size={alloc.alloc_size}")

print("\nknown_constants (first 20):")
for k, v in list(detector._known_constants.items())[:20]:
    print(f"  {k} = {v}")

# 找到 malloc 调用地址
print("\nSearching for malloc calls and their tracking:")
for i, ins in enumerate(instrs):
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops and "malloc" in str(ops[0]).lower():
        addr = ins.get("address", 0)
        is_user = any(lo <= addr < hi for lo, hi in user_ranges)
        if is_user:
            # 检查前一条 mov ecx, 0x100
            prev = instrs[i-1] if i > 0 else {}
            prev_mnem = prev.get("mnemonic", "")
            prev_ops = prev.get("operands", [])
            print(f"  malloc at 0x{addr:x}: prev_ins={prev_mnem} {prev_ops}")
            # 检查 known_constants 中 ecx/rcx 的值
            ec = detector._known_constants.get("ecx", "NOT SET")
            rc = detector._known_constants.get("rcx", "NOT SET")
            print(f"    known: ecx={ec} rcx={rc}")
