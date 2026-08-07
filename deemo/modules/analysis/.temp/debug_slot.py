import sys, json, re
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import extract_stack_slot

tests = [
    "QWORD PTR [rsp+0x28]",
    "QWORD PTR [rbp-0x8]",
    "[rsp+0x28]",
    "[rbp-0x10]",
    "QWORD PTR [rsp]",
    "rax",
    "QWORD PTR [rax+0x8]",
]
for t in tests:
    print(f"  {t!r:40s} -> {extract_stack_slot(t)}")

# 直接测试正则
cleaned = "qwordptr[rsp+0x28]"
m = re.search(r'\[(rb[ps][-+]\s*0x[0-9a-f]+)\]', cleaned)
print(f"\nDirect regex test on '{cleaned}': {m}")
cleaned2 = "[rsp+0x28]"
m2 = re.search(r'\[(rb[ps][-+]\s*0x[0-9a-f]+)\]', cleaned2)
print(f"Direct regex test on '{cleaned2}': {m2}")

