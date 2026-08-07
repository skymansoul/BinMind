import sys
sys.path.insert(0, r"C:\Users\Administrator\Desktop\BinMind\deemo")
from modules.analysis.static.heap_overflow_detect import HeapOverflowDetector
from modules.analysis.static.heap_alloc_model import AllocatorFamily

addr = 0x401000
insns = [
    {"address": addr, "mnemonic": "mov", "operands": ["edi", "0x40"]},
    {"address": addr+5, "mnemonic": "call", "operands": ["0x402000 <malloc>"]},
    {"address": addr+10, "mnemonic": "mov", "operands": ["rdi", "rax"]},
    {"address": addr+13, "mnemonic": "lea", "operands": ["rsi", "[rip+0x4000]"]},
    {"address": addr+20, "mnemonic": "mov", "operands": ["edx", "0x80"]},
    {"address": addr+25, "mnemonic": "call", "operands": ["0x403000 <memcpy>"]},
]

det = HeapOverflowDetector(AllocatorFamily.GLIBC)
det.pre_analyze(insns)
for ins in insns:
    det.analyze_instruction(ins)
    mnem = ins.get("mnemonic","")
    ops = ins.get("operands",[])
    ptr_map = dict(det._alloc_tracker._ptr_to_alloc)
    consts = dict(det._known_constants)
    raw = det._raw_findings
    print("%s %s | ptr=%s | const=%s | raw=%d" % (mnem, ops, ptr_map, consts, len(raw)))
    if raw:
        for r in raw:
            print("  result:", {k:v for k,v in r.items() if k != "_write_sym_expr"})

print("raw_findings:", len(det._raw_findings))
findings = det.finalize(insns)
print("final findings:", len(findings))
