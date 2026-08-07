"""精确调试 different_object 的 DerefChecker 和 PathAnalyzer."""
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

binary = r"C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf_safe\build\different_object_vuln_O0.exe"
insns = disasm(binary)

det = UAFDetector(use_win64_abi=True)
det.pre_analyze(insns)

# 先检查 path_analyzer 在 free_addr 和 use_addr 的判定
free_addr = 0x14000178b
use_addr = 0x140001794

pa = det._path_analyzer
print(f"PathAnalyzer scopes total: {len(pa._scopes)}")

# 检查覆盖 free_addr 的 scopes
free_scopes_addr = pa._addr_to_scopes.get(free_addr, [])
use_scopes_addr = pa._addr_to_scopes.get(use_addr, [])
print(f"\nScopes at free_addr 0x{free_addr:x}: {len(free_scopes_addr)}")
for s in free_scopes_addr:
    print(f"  jcc=0x{s.jcc_addr:x} target=0x{s.target:x} ft=0x{s.fallthrough:x} merge=0x{s.merge_addr:x} "
          f"taken_range={s.taken_range} ft_range={s.fallthrough_range}")

print(f"\nScopes at use_addr 0x{use_addr:x}: {len(use_scopes_addr)}")
for s in use_scopes_addr:
    print(f"  jcc=0x{s.jcc_addr:x} target=0x{s.target:x} ft=0x{s.fallthrough:x} merge=0x{s.merge_addr:x} "
          f"taken_range={s.taken_range} ft_range={s.fallthrough_range}")

# 手动调用 are_mutually_exclusive
result = pa.are_mutually_exclusive(free_addr, use_addr)
print(f"\nare_mutually_exclusive(0x{free_addr:x}, 0x{use_addr:x}) = {result}")

# 手动找 innermost scopes
free_scope = pa._find_innermost_scope(free_addr)
use_scope = pa._find_innermost_scope(use_addr)
print(f"\nfree innermost scope: {free_scope}")
if free_scope:
    print(f"  jcc=0x{free_scope.jcc_addr:x} target=0x{free_scope.target:x} ft=0x{free_scope.fallthrough:x} merge=0x{free_scope.merge_addr:x}")
print(f"use innermost scope: {use_scope}")
if use_scope:
    print(f"  jcc=0x{use_scope.jcc_addr:x} target=0x{use_scope.target:x} ft=0x{use_scope.fallthrough:x} merge=0x{use_scope.merge_addr:x}")

if free_scope and use_scope:
    print(f"  same jcc? {free_scope.jcc_addr == use_scope.jcc_addr}")
    free_in_taken = pa._in_taken_path(free_addr, free_scope)
    use_in_taken = pa._in_taken_path(use_addr, use_scope)
    print(f"  free_in_taken={free_in_taken} use_in_taken={use_in_taken}")
    print(f"  mutually_exclusive = {free_in_taken != use_in_taken}")

# 运行检测器
for ins in insns:
    det.analyze_instruction(ins)
findings = det.finalize(insns)
print(f"\nFindings: {len(findings)}")
for f in findings:
    print(f"  {f}")

# 检查 DerefChecker 是否被调用了
print(f"\nobj1 freed_at: {det._objects[1].freed_at}")
print(f"obj1 use_after_free_at: {det._objects[1].use_after_free_at}")
print(f"obj1 nulled: {det._objects[1].nulled_after_free}")

# 手动模拟 DerefChecker.check_deref 对 0x140001794 的检查
dc = det._deref_checker
ops = ["BYTE PTR [rax]", "0x58"]
addr = 0x140001794
print(f"\n--- Manual DerefChecker simulation at 0x{addr:x} ---")
print(f"  ops = {ops}")
print(f"  is_user_code = {det._is_user_code(addr)}")
for op in ops:
    op_s = op.strip().lower()
    print(f"  op_s = '{op_s}'")
    for prefix in dc._PTR_PREFIXES:
        if op_s.startswith(prefix):
            op_s = op_s[len(prefix):]
            print(f"    stripped prefix → '{op_s}'")
            break
    if not (op_s.startswith("[") and "]" in op_s):
        print(f"    no [..] pattern, skip")
        continue
    inner = op_s[op_s.find("[") + 1:op_s.rfind("]")]
    base = inner.split("+")[0].split("-")[0].split("*")[0].strip()
    print(f"    inner='{inner}' base='{base}'")
    oid = det._reg_to_obj.get(base)
    print(f"    reg_to_obj['{base}'] = {oid}")
    if oid is not None and oid in det._objects:
        obj = det._objects[oid]
        print(f"    obj{oid} freed_at={obj.freed_at} nulled={obj.nulled_after_free}")
        if obj.freed_at and not obj.nulled_after_free:
            me = pa.are_mutually_exclusive(obj.freed_at[-1], addr)
            print(f"    are_mutually_exclusive({obj.freed_at[-1]}, {addr}) = {me}")
            if me:
                print(f"    → SUPPRESSED by path analyzer!")
            else:
                cp = dc._is_cleanup_pattern(oid, addr)
                print(f"    is_cleanup_pattern = {cp}")
                if cp:
                    print(f"    → SUPPRESSED by cleanup pattern!")
                else:
                    print(f"    → SHOULD REPORT UAF!")
