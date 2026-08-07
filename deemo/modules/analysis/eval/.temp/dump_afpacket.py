import sys, subprocess
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

# Compile O0
cc = 'x86_64-w64-mingw32-gcc'
src = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\benchmark\samples_uaf\cve_2020_14386_afpacket\cve_2020_14386_afpacket_uaf.c'
binary = r'C:\Users\Administrator\Desktop\BinMind\deemo\modules\analysis\eval\build_tmp_uaf\cve_2020_14386_afpacket_O0.exe'
subprocess.run([cc, '-O0', '-no-pie', '-fno-stack-protector', '-fno-asynchronous-unwind-tables', '-w', '-o', binary, src], capture_output=True)

out = subprocess.run(['objdump','-d','-M','intel', binary], capture_output=True, text=True).stdout

# Find the loop_free function
lines = out.split('\n')
in_func = False
func_name = ""
for i, line in enumerate(lines):
    if '<v_2020_14386_afpacket_loop_free>:' in line:
        in_func = True
        func_name = line.strip()
        continue
    if in_func:
        if line.strip() and '<' in line and '>:' in line and '\t' not in line:
            break
        print(line.rstrip())
