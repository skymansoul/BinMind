import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.disasm_util import resolve_rip_relative

# The operand from vmac Os: 'QWORD PTR [rip+0x78e0] # 140009080 <g_obj_v_2018_17182_vmac>'
src_raw = 'QWORD PTR [rip+0x78e0] # 140009080 <g_obj_v_2018_17182_vmac>'
ins = {'mnemonic': 'mov', 'operands': ['rax', src_raw]}
addr = 0x140001799

result = resolve_rip_relative(ins, src_raw, addr)
print(f"resolve_rip_relative result: {result}")
print(f"Expected: {0x140001799 + 7 + 0x78e0:#x}")  # 0x140009080

# Try cleaning the comment first
import re
cleaned = re.sub(r'\s*#.*$', '', src_raw)
print(f"Cleaned: {cleaned!r}")
result2 = resolve_rip_relative({'mnemonic':'mov','operands':['rax',cleaned]}, cleaned, addr)
print(f"resolve_rip_relative(cleaned): {result2}")
