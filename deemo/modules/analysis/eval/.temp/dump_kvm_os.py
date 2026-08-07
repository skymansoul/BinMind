import sys, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

cc = 'x86_64-w64-mingw32-gcc'
src = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf\cve_2016_10150_kvm\cve_2016_10150_kvm_uaf.c'
binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2016_10150_kvm_Os.exe'
r = subprocess.run([cc, '-Os', '-no-pie', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-w', '-o', binary, src], capture_output=True, text=True)
if r.returncode != 0:
    print(f"Compile failed: {r.stderr[:200]}")
    sys.exit(1)

out = subprocess.run(['objdump','-d','-M','intel', binary], capture_output=True, text=True).stdout

# Show all functions and their instructions
lines = out.split('\n')
in_func = False
func_name = ""
for line in lines:
    stripped = line.strip()
    if '<' in stripped and '>:' in stripped and '\t' not in stripped:
        in_func = True
        func_name = stripped
        print(f"\n{'='*60}")
        print(f"FUNC: {func_name}")
        continue
    if in_func:
        if stripped and '<' in stripped and '>:' in stripped and '\t' not in stripped:
            in_func = True
            func_name = stripped
            print(f"\n{'='*60}")
            print(f"FUNC: {func_name}")
            continue
        if stripped:
            print(f"  {stripped}")
