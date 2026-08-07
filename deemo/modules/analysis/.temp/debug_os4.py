import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind")
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily
from modules.analysis.static.heap_fp_filter import HeapFPFilter
from modules.analysis.static.heap_slice_trace import BackwardSliceTracer, SourceKind

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples\cve_2015_0235_ghost\cve_2015_0235_ghost_heap_overflow_Os.exe"
ins, fmt, main_addr, ranges = disassemble_binary(binary)

det = HeapOverflowDetector(AllocatorFamily.GLIBC, use_win64_abi="pei" in fmt.lower())
det.set_min_user_addr(main_addr)
det.set_user_func_ranges(ranges)
det.pre_analyze(ins)
for i in ins:
    det.analyze_instruction(i)

deduped = det._dedup_by_alloc(det._raw_findings)
stage4 = [f for f in deduped if det._stage4_path_sensitive_check(f)]
stage5 = [f for f in stage4 if det._stage5_struct_field_check(f)]

print(f"Findings entering fp_filter: {len(stage5)}")
for f in stage5:
    print(f"  type={f.get('type')} size_op={f.get('size_operand')} ptr_op={f.get('ptr_operand')}")
    print(f"  alloc_size={f.get('alloc_size')} write_size={f.get('write_size', 'MISSING')} write_size_range={f.get('write_size_range', 'MISSING')}")

    # Stage 1
    tracer = BackwardSliceTracer()
    size_op = f.get("size_operand", "")
    alloc_sz = f.get("alloc_size", 0)
    if size_op:
        src = tracer.trace(ins, size_op, max_depth=30)
        print(f"  Stage1: trace({size_op}) -> kind={src.kind.name} val={src.value} desc={src.description}")
        if src.kind == SourceKind.CONSTANT and src.value <= alloc_sz:
            print(f"  Stage1 FILTERS (constant {src.value} <= alloc {alloc_sz})")
        else:
            print(f"  Stage1 passes")
    else:
        print(f"  Stage1 passes (no size_op)")

    # Stage 2
    if size_op:
        src2 = tracer.trace(ins, size_op, max_depth=40)
        if src2.kind == SourceKind.BOUNDS_CHECKED:
            print(f"  Stage2 FILTERS (bounds checked)")
        else:
            print(f"  Stage2 passes")
    else:
        print(f"  Stage2 passes (no size_op)")

    # Stage 3
    ptr_reg = f.get("ptr_operand", "")
    alloc_addr = det._alloc_tracker._ptr_to_alloc.get(ptr_reg)
    print(f"  Stage3: ptr_reg={ptr_reg} alloc_addr={alloc_addr}")
    if alloc_addr is not None:
        alloc = det._alloc_tracker._allocations.get(alloc_addr)
        if alloc is not None:
            write_sz = f.get("write_size", 0)
            print(f"    alloc_size={alloc.alloc_size.lo}-{alloc.alloc_size.hi} singleton={alloc.alloc_size.is_singleton} write_sz={write_sz}")
            if alloc.alloc_size.is_singleton and write_sz <= alloc.alloc_size.lo:
                print(f"    Stage3 FILTERS (write_sz {write_sz} <= alloc {alloc.alloc_size.lo})")
            else:
                print(f"    Stage3 passes")
        else:
            print(f"    Stage3 passes (no alloc obj)")
    else:
        print(f"    Stage3 passes (ptr not in _ptr_to_alloc)")
    print()
