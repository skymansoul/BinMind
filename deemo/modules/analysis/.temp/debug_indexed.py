import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')
from modules.analysis.static.uaf_operand_utils import is_indexed_access

tests = [
    "QWORD PTR [rbp-0x10]",
    "QWORD PTR [rax+0x8]",
    "QWORD PTR [rbp-0x8]",
    "DWORD PTR [rax]",
    "BYTE PTR [rax]",
    "QWORD PTR [rsp+0x28]",
]
for t in tests:
    print(f"  is_indexed_access({t!r}) = {is_indexed_access(t)}")
