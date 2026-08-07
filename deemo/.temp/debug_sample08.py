"""调试sample08: 检查反汇编输出中的函数名和call指令."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.vuln.detection.src.format.fmt_detector import (
    disassemble_elf, extract_rodata_strings, detect_fmt_vuln_enhanced)

elf = Path(__file__).resolve().parent.parent / 'modules' / 'vuln' / 'detection' / 'src' / 'format' / 'fmt_samples' / 'sample08_wrapper_fmt_vuln' / 'main'
if not elf.exists():
    elf = elf.with_suffix('.exe')

funcs = disassemble_elf(elf)
print(f"Functions found: {len(funcs)}")
for func_name, insns, addrs in funcs:
    print(f"\n=== {func_name} ({len(insns)} insns) ===")
    for i, (instr, addr) in enumerate(zip(insns, addrs)):
        if 'call' in instr.lower() or 'log' in instr.lower() or 'vprintf' in instr.lower():
            print(f"  [{i}] {addr:#x}: {instr}")

    rodata = extract_rodata_strings(elf)
    scan = detect_fmt_vuln_enhanced(insns, addrs, rodata)
    print(f"  detected={scan['detected']}, findings={scan['n_findings']}")
    for f in scan['findings']:
        print(f"    -> {f.get('desc', '')}, conf={f.get('confidence', 0)}")
