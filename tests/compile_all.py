"""一键编译所有堆溢出CVE样本。"""
import subprocess, os, sys
SAMPLES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_samples")
OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cve_binaries")
os.makedirs(OUT, exist_ok=True)
cc = "gcc"
try: subprocess.run([cc,"--version"],capture_output=True,timeout=5)
except: cc = "clang"
count=0; ok=0
for d in sorted(os.listdir(SAMPLES)):
    dp = os.path.join(SAMPLES,d)
    if not os.path.isdir(dp): continue
    vc = os.path.join(dp,"vuln.c")
    if not os.path.isfile(vc): continue
    out = os.path.join(OUT,f"{d}.elf")
    # -z execstack 和 -no-pie 在 MinGW/Windows 上不可用
    r = subprocess.run([cc,vc,"-o",out,"-fno-stack-protector","-g","-O0"],
                       capture_output=True,text=True,timeout=30)
    count+=1
    if r.returncode==0 and os.path.isfile(out): ok+=1; print(f"  OK: {d}")
    else: print(f"  FAIL: {d} — {r.stderr[:80]}")
print(f"\nCompiled: {ok}/{count}")
