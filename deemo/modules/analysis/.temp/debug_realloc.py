"""调试 realloc_semantics_vuln 的路径分析和对象追踪."""
import sys, subprocess
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
from modules.analysis.static.uaf_detect import UAFDetector

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

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\realloc_semantics_vuln_O0.exe"
insns = disasm(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 检查PathAnalyzer
pa = det._path_analyzer
print(f"Total scopes: {len(pa._scopes)}")

# 关键地址
realloc_addr = 0x140001791  # call realloc (frees old)
use_addr = 0x1400017a5      # mov BYTE PTR [rax], 0x58

# 检查这两个地址覆盖的scopes
for label, addr in [("realloc/free", realloc_addr), ("use(saved)", use_addr)]:
    scopes_at = pa._addr_to_scopes.get(addr, [])
    innermost = pa._find_innermost_scope(addr)
    print(f"\n{label} at 0x{addr:x}:")
    print(f"  scopes in _addr_to_scopes: {len(scopes_at)}")
    for s in scopes_at:
        print(f"    jcc=0x{s.jcc_addr:x} target=0x{s.target:x} ft=0x{s.fallthrough:x} merge=0x{s.merge_addr:x}")
    if innermost:
        print(f"  innermost: jcc=0x{innermost.jcc_addr:x} target=0x{innermost.target:x} ft=0x{innermost.fallthrough:x} merge=0x{innermost.merge_addr:x}")
    else:
        print(f"  innermost: None")

# 检查互斥判定
me = pa.are_mutually_exclusive(realloc_addr, use_addr)
print(f"\nare_mutually_exclusive(0x{realloc_addr:x}, 0x{use_addr:x}) = {me}")

# 逐指令追踪
func_insns = [i for i in insns if 0x140001760 <= i["address"] <= 0x1400017bb]
print(f"\n=== Tracing {len(func_insns)} instructions ===")
for ins in func_insns:
    addr = ins["address"]
    mnem = ins["mnemonic"]
    ops = ins["operands"]
    det.analyze_instruction(ins)
    reg_obj = {k: v for k, v in det._reg_to_obj.items() if v is not None}
    stack_obj = dict(det._stack_to_obj)
    findings_now = len(det._findings)
    ops_str = ", ".join(ops)
    print(f"  0x{addr:x} {mnem:6s} {ops_str:45s} reg={reg_obj} st={stack_obj} findings={findings_now}")

print(f"\n=== Objects ===")
for oid, obj in det._objects.items():
    print(f"  obj{oid}: alloc=0x{obj.alloc_addr:x} freed={obj.freed_at} uaf={obj.use_after_free_at} nulled={obj.nulled_after_free} realloc={obj.realloc_count}")

findings = det.finalize(insns)
print(f"\nFinal findings: {len(findings)}")
for f in findings:
    print(f"  {f}")
