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
findings = det.finalize(insns)
s = det.stats
print("raw_findings:", s["raw_findings"])
print("filtered_findings:", s["filtered_findings"])
print("sawce:", s.get("sawce_correlator", {}))
for f in findings:
    print("  finding: alloc_size=%s write_size=%s sev=%s" % (
        f.get("alloc_size"), f.get("write_size"), f.get("severity")))
    print("  fp_stage=%s fp_reason=%s" % (
        f.get("fp_stage",""), f.get("fp_reason","")))
