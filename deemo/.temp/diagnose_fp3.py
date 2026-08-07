"""Run exactly what the suite does for cve_26."""
import sys
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind')
sys.path.insert(0, r'C:\Users\Administrator\Desktop\BinMind\deemo')

from pathlib import Path
from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier

SAMPLE_DIR = Path(r'C:\Users\Administrator\Desktop\BinMind\deemo\tests\cve_samples\heap_overflow')

def read_sample_source(name):
    d = SAMPLE_DIR / name
    c_files = list(d.glob("*.c"))
    return c_files[0].read_text(encoding='utf-8', errors='replace') if c_files else None

def run_source_verifier(source):
    v = HeapOverflowSrcVerifier()
    results = v.verify(source)
    return [{
        "verdict": r.verdict.value,
        "alloc_line": r.alloc_line,
        "write_line": r.write_line,
        "var_name": r.var_name,
        "alloc_size": r.alloc_size,
        "write_size": r.write_size,
        "confidence": r.confidence,
        "reason": r.reason,
    } for r in results]

for name in ['cve_26_realloc_grow_safe', 'cve_28_guarded_loop_safe']:
    source = read_sample_source(name)
    findings = run_source_verifier(source)
    vuln_count = sum(1 for f in findings if f["verdict"] == "VULN")
    print(f"\n=== {name} ===")
    print(f"  vuln_count = {vuln_count}")
    for f in findings:
        print(f"  L{f['alloc_line']}-L{f['write_line']} var={f['var_name']} "
              f"verdict={f['verdict']} conf={f['confidence']:.2f}")
        print(f"    {f['reason'][:100]}")
