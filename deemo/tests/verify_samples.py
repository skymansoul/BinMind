# 验证所有样本可编译 + 可执行 (入口检查)
import os, subprocess, sys

BASE = os.path.dirname(os.path.abspath(__file__))
SAMPLES = os.path.join(BASE, 'cve_samples')

ok_compile = ok_run = fail = 0
for d in sorted(os.listdir(SAMPLES)):
    dpath = os.path.join(SAMPLES, d)
    if not os.path.isdir(dpath): continue
    src = os.path.join(dpath, 'vuln.c')
    out = os.path.join(dpath, 'vuln')
    if not os.path.isfile(src): continue
    # Compile
    r = subprocess.run(['gcc', src, '-o', out, '-w'], capture_output=True, text=True, timeout=15)
    if r.returncode != 0:
        print(f'COMPILE FAIL: {d}'); fail += 1; continue
    ok_compile += 1
    # Run (most samples crash by design, just check they start)
    try:
        r2 = subprocess.run([out], capture_output=True, text=True, timeout=3)
        ok_run += 1
    except subprocess.TimeoutExpired:
        ok_run += 1  # timeout counts as "runs"
    except Exception:
        pass  # crash on purpose is OK for vuln samples

print(f'Compile: {ok_compile} OK, {fail} FAIL')
print(f'Run: {ok_run} OK')
