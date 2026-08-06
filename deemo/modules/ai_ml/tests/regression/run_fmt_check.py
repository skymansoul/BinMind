"""格式化字符串专项检测——对已编译样本运行format_string_check"""
import subprocess, json, sys, re, time
from pathlib import Path

BASE = Path(__file__).parent.parent.parent
BUILD = BASE / "tests" / "regression" / "build"

def objdump_disasm(path):
    r = subprocess.run(["objdump", "-d", str(path)], capture_output=True, text=True, timeout=30)
    raw = r.stdout
    funcs = {}
    cur, instrs = None, []
    for line in raw.split('\n'):
        m = re.search(r'([0-9a-f]+)\s+<(\w+)>:', line)
        if m:
            if cur and instrs: funcs[cur] = instrs
            cur, instrs = m.group(2), []
            continue
        mi = re.match(r'\s*([0-9a-f]+):\s+[0-9a-f ]+\s+(.+)', line.strip())
        if mi and cur: instrs.append(mi.group(2).strip())
    if cur and instrs: funcs[cur] = instrs
    return funcs

FMT_FUNCS = {'printf','fprintf','sprintf','snprintf','vprintf','dprintf','syslog',
             '__mingw_printf','__mingw_fprintf','__mingw_snprintf'}
# Windows x64: rcx=arg1. Linux x64: rdi=arg1. Both covered.
FMT_ARG1_REGS = ['rcx','ecx','rdi','edi']
FMT_CONST_PATTERNS = ['lea rcx,[rip','lea rdi,[rip','mov ecx,0x','mov edi,0x',
                      'mov rcx,0x','mov rdi,0x']

def check_fmt(instructions):
    results = []
    for i, instr in enumerate(instructions):
        for ff in FMT_FUNCS:
            if ff in instr.lower() and 'call' in instr.lower():
                fmt_const = False
                fmt_param = False
                # AT&T语法: 检查arg1寄存器在call前的来源
                fmt_source = "unknown"
                for j in range(i-1, max(-1, i-3), -1):
                    prev = instructions[j].lower() if j < len(instructions) else ''
                    # 使用正则处理可变空白: mov\s+...\s*,\s*%reg
                    for r in FMT_ARG1_REGS:
                        # 立即数→arg1 (安全)
                        if re.search(rf'mov\s+\$0x.*,\s*%{r}\b', prev):
                            fmt_source = "constant"; break
                        # .rodata地址 (安全)
                        if re.search(rf'lea\s+.*rip.*,\s*%{r}\b', prev):
                            fmt_source = "constant"; break
                        # 寄存器→arg1 (来自栈/参数/返回值 — 潜在漏洞)
                        if re.search(rf'mov\s+%.*,\s*%{r}\b', prev):
                            fmt_source = "variable"; break
                        # 内存加载→arg1 (来自栈 — 潜在漏洞)
                        if re.search(rf'mov\s+.*\(.*\),\s*%{r}\b', prev):
                            fmt_source = "variable"; break
                    if fmt_source != "unknown":
                        break
                vuln = (fmt_source == "variable")
                results.append({'instr_idx': i, 'func': ff, 'fmt_const': fmt_const, 'vulnerable': vuln})
    return results

results = {}
for exe in sorted(BUILD.glob("*_fmt*_O0.exe")):
    funcs = objdump_disasm(exe)
    sample_results = {}
    for fname, instrs in funcs.items():
        sample_results[fname] = check_fmt(instrs)
    results[exe.stem] = sample_results

total_funcs = sum(len(v) for v in results.values())
vuln_funcs = sum(1 for v in results.values() for f, checks in v.items() if any(c['vulnerable'] for c in checks))
print(f"Format string scan: {len(results)} binaries, {total_funcs} functions, {vuln_funcs} with vulnerable printf")
print(f"Detection rate: {vuln_funcs}/{len(results)} = {vuln_funcs/max(1,len(results)):.0%}")
with open(BUILD / "fmt_results.json", "w") as f:
    json.dump(results, f, indent=2)
