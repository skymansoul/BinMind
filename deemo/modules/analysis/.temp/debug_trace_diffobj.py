"""逐指令追踪 different_object_vuln 的对象映射变化."""
import sys, subprocess, re
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
from modules.analysis.static.uaf_detect import UAFDetector
from modules.analysis.static.disasm_util import extract_stack_slot, norm_reg

def disasm(binary):
    out = subprocess.run(["objdump", "-d", "-M", "intel", binary],
                         capture_output=True, text=True, timeout=30).stdout
    insns = []
    for line in out.split("\n"):
        parts = line.strip().split("\t")
        if len(parts) >= 3:
            try:
                addr = int(parts[0].strip().rstrip(":"), 16)
                mnem_parts = parts[2].split()
                mnem = mnem_parts[0] if mnem_parts else ""
                ops = [o.strip() for o in " ".join(mnem_parts[1:]).split(",") if o.strip()] if len(mnem_parts) > 1 else []
                insns.append({"address": addr, "mnemonic": mnem, "operands": ops})
            except ValueError:
                pass
    return insns

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_vuln_O0.exe"
insns = disasm(binary)

# 只看 trigger_diffobj_vuln 函数 (0x140001760 - 0x1400017a5)
func_insns = [i for i in insns if 0x140001760 <= i["address"] <= 0x1400017a5]

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

print("=== User func ranges ===")
for lo, hi in det._user_func_ranges:
    print(f"  [0x{lo:x}, 0x{hi:x})")

print(f"\n=== Tracing {len(func_insns)} instructions ===")
for ins in func_insns:
    addr = ins["address"]
    mnem = ins["mnemonic"]
    ops = ins["operands"]
    
    # 检查地址是否在user code范围
    is_uc = det._is_user_code(addr)
    
    det.analyze_instruction(ins)
    
    # 关键状态
    reg_obj = {k: v for k, v in det._reg_to_obj.items() if v is not None}
    stack_obj = dict(det._stack_to_obj) if hasattr(det, '_stack_to_obj') else {}
    
    # 检查这条指令的操作数是否涉及[rax]
    ops_str = ", ".join(ops)
    marker = ""
    if any("[" in o.lower() for o in ops):
        marker = " <<<< MEMORY OP"
        # 检查extract_stack_slot
        for op in ops:
            slot = extract_stack_slot(op)
            if slot:
                marker += f" slot={slot}"
    
    print(f"  0x{addr:x} {mnem:6s} {ops_str:40s} uc={is_uc} reg={reg_obj} st={stack_obj}{marker}")

print(f"\n=== Findings: {det._findings} ===")
print(f"=== Objects: ===")
for oid, obj in det._objects.items():
    print(f"  obj{oid}: alloc=0x{obj.alloc_addr:x} freed={obj.freed_at} uaf={obj.use_after_free_at} nulled={obj.nulled_after_free}")
