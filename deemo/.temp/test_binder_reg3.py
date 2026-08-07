import sys, os
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from modules.analysis.static.disasm_util import disassemble_binary
from modules.analysis.static.uaf_detect import UAFDetector

path = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\reg_cve_2019_2215_binder_uaf_O2.exe"
instructions, fmt, main_addr, user_ranges = disassemble_binary(path)

det = UAFDetector(use_win64_abi=True)
det.set_user_func_ranges(user_ranges)
det.pre_analyze(instructions)

# Check what user ranges the detector has
print(f"detector user_func_ranges: {len(det._user_func_ranges)} ranges")
for lo, hi in det._user_func_ranges:
    print(f"  0x{lo:x} - 0x{hi:x}")

# Find malloc/free calls and check if they're user code
for ins in instructions:
    mnem = ins.get("mnemonic", "").lower()
    ops = ins.get("operands", [])
    if mnem == "call" and ops:
        from modules.analysis.static.disasm_util import extract_func_name
        func = extract_func_name(ops[0])
        if func in ("malloc", "free"):
            addr = ins["address"]
            is_user = det._is_user_code(addr)
            print(f"  {func} at 0x{addr:x}: user_code={is_user}")

for ins in instructions:
    det.analyze_instruction(ins)
findings = det.finalize(instructions)
print(f"\nobjects={len(det._objects)} findings={len(findings)}")
for oid, obj in det._objects.items():
    print(f"  obj {oid}: alloc=0x{obj.alloc_addr:x} freed_at={[hex(a) for a in obj.freed_at]}")
for f in findings:
    print(f"  {f.get('type')}: addr=0x{f['address']:x} freed_at=0x{f.get('freed_at',0):x}")
