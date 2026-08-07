# 调试 binder_uaf O2 FN: 分析检测器内部状态
import sys, os, subprocess
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.uaf_detect import UAFDetector

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2019_2215_binder_uaf_O2.exe"

instructions, fmt, main_addr, user_ranges = disassemble_binary(binary)
print(f"Instructions: {len(instructions)}, main_addr: {hex(main_addr) if main_addr else 'None'}")
print(f"User func ranges: {[(hex(a), hex(b)) for a,b in user_ranges]}")

# 打印 init/cleanup/use/main 区域的关键指令
for ins in instructions:
    addr = ins.get("address", 0)
    if 0x140001760 <= addr <= 0x1400017c0 or 0x140009700 <= addr <= 0x140009730:
        mnem = ins.get("mnemonic", "")
        ops = ins.get("operands", [])
        print(f"  {hex(addr)}: {mnem} {', '.join(ops)}")

print("\n--- Running detector ---")
detector = UAFDetector(use_win64_abi=True)
detector.set_user_func_ranges(user_ranges)
detector.pre_analyze(instructions)

for ins in instructions:
    detector.analyze_instruction(ins)

print(f"\nObjects: {len(detector._objects)}")
for oid, obj in detector._objects.items():
    print(f"  obj#{oid}: alloc={hex(obj.alloc_addr)}, freed_at={[hex(a) for a in obj.freed_at]}, "
          f"uaf_at={[hex(a) for a in obj.use_after_free_at]}, "
          f"nulled={obj.nulled_after_free}, nulled_at={hex(obj.nulled_at) if obj.nulled_at else 'None'}")

print(f"\n_addr_to_obj: {[(hex(a), oid) for a, oid in detector._addr_to_obj.items()]}")

print(f"\nFindings (raw): {len(detector._findings)}")
for f in detector._findings:
    print(f"  {f}")

print(f"\nPathAnalyzer branch scopes:")
if hasattr(detector._path_analyzer, '_branch_scopes'):
    for k, v in detector._path_analyzer._branch_scopes.items():
        print(f"  {hex(k)}: {v}")

# 检查 use() 函数中 jmp __mingw_printf 时的检测器状态
print(f"\n--- Analyzing use() function step-by-step ---")
detector2 = UAFDetector(use_win64_abi=True)
detector2.set_user_func_ranges(user_ranges)
detector2.pre_analyze(instructions)

for ins in instructions:
    addr = ins.get("address", 0)
    mnem = ins.get("mnemonic", "")
    ops = ins.get("operands", [])
    
    # 在 use() 之前重建状态
    if addr == 0x1400017a0:
        print(f"\n  Before use():")
        print(f"    _reg_to_obj: {dict(detector2._reg_to_obj)}")
        print(f"    _addr_to_obj: {dict(detector2._addr_to_obj)}")
        for oid, obj in detector2._objects.items():
            print(f"    obj#{oid}: freed_at={[hex(a) for a in obj.freed_at]}, "
                  f"nulled={obj.nulled_after_free}, nulled_at={hex(obj.nulled_at) if obj.nulled_at else 'None'}")

    detector2.analyze_instruction(ins)

    if 0x1400017a0 <= addr <= 0x1400017c0:
        print(f"  {hex(addr)}: {mnem} {', '.join(ops)}")
        print(f"    _reg_to_obj: {dict(detector2._reg_to_obj)}")
        # 检查 _check_call_args_uaf 是否会被触发
        if mnem == "jmp" and ops:
            func = ops[0]
            print(f"    jmp target: {func}")
            # 模拟 _handle_jmp_tailcall 的行为
            from modules.analysis.static.disasm_util import extract_func_name
            fname = extract_func_name(func)
            print(f"    extracted func: {fname}")
            print(f"    is_dangerous: {fname in detector2._DANGEROUS_CALLS}")
            print(f"    is_free_like: {detector2._interproc.is_free_like(fname)}")
            print(f"    in summaries: {fname in detector2._interproc._summaries}")

findings = detector.finalize(instructions)
print(f"\nFinalized findings: {len(findings)}")
for f in findings:
    print(f"  {f}")
