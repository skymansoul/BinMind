"""对比cve_39 FP和cve_2022_1015 TP的CSA overflow差异."""
import os, sys
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from tests.source_scanner_part1 import extract_heap_ops_c
from tests.source_classifier import classify_finding

# cve_39
src39 = open(os.path.join(BASE, 'tests/cve_samples/heap_overflow/cve_39_loop_guard_cross_path/loop_guard_cross_path.c'),
             encoding='utf-8', errors='replace').read()
ops39 = extract_heap_ops_c(src39)
print('=== cve_39 (SAFE, FP) ===')
for o in ops39:
    cls = classify_finding(o)
    print('  is_ovf=%s cls=%s ptr=%s alloc_req=%d alloc_eff=%d write=%d offset=%d func=%s line=%d' % (
        o.get('is_overflow'), cls, o.get('ptr_var',''),
        o.get('alloc_requested',0), o.get('alloc_effective',0),
        o.get('write_size',0), o.get('offset',0),
        o.get('write_func',''), o.get('write_line',0)))
    if o.get('is_overflow'):
        print('    write_line_text:', o.get('write_line_text','')[:120])
        print('    alloc_line_text:', o.get('alloc_line_text','')[:120])

# cve_2022_1015
src1015 = open(os.path.join(BASE, 'samples/cve_heap_overflow/cve_2022_1015_netfilter/nf_expr_overflow.c'),
               encoding='utf-8', errors='replace').read()
ops1015 = extract_heap_ops_c(src1015)
print('\n=== cve_2022_1015 (VULN, TP) ===')
for o in ops1015:
    cls = classify_finding(o)
    print('  is_ovf=%s cls=%s ptr=%s alloc_req=%d alloc_eff=%d write=%d offset=%d func=%s line=%d' % (
        o.get('is_overflow'), cls, o.get('ptr_var',''),
        o.get('alloc_requested',0), o.get('alloc_effective',0),
        o.get('write_size',0), o.get('offset',0),
        o.get('write_func',''), o.get('write_line',0)))
    if o.get('is_overflow'):
        print('    write_line_text:', o.get('write_line_text','')[:120])
        print('    alloc_line_text:', o.get('alloc_line_text','')[:120])
