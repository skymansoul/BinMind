"""分析cve_2022_1015_netfilter FN根因."""
import os, sys
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import _run_hosv_source, _run_csa_source

src = open(os.path.join(BASE, 'samples/cve_heap_overflow/cve_2022_1015_netfilter/nf_expr_overflow.c'),
           encoding='utf-8', errors='replace').read()
h = _run_hosv_source(src, 'cve_2022_1015')
c = _run_csa_source(src, 'cve_2022_1015')
print('HOSV: detected=%s vuln=%d unc=%d safe=%d no_vuln=%s all_safe=%s' % (
    h['detected'], h.get('n_vuln',0), h.get('n_uncertain',0),
    h.get('n_safe',0), h.get('no_vuln'), h.get('all_safe')))
print('CSA:  detected=%s overflow=%d unc=%d total=%d' % (
    c['detected'], c.get('n_overflow',0), c.get('n_uncertain',0), c.get('n_total',0)))

# 查看HOSV详情
from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
v = HeapOverflowSrcVerifier()
results = v.verify(src)
print('\nHOSV findings:')
for r in results:
    print('  verdict=%s conf=%.2f alloc=%d write=%d reason=%s' % (
        r.verdict.name, r.confidence, r.alloc_size, r.write_size, r.reason[:120]))

# 查看CSA ops
from tests.source_scanner_part1 import extract_heap_ops_c
ops = extract_heap_ops_c(src)
print('\nCSA ops:')
for o in ops:
    is_ovf = o.get('is_overflow')
    print('  is_overflow=%s ptr=%s alloc=%d eff=%d write=%d func=%s line=%d' % (
        is_ovf, o.get('ptr_var',''), o.get('alloc_requested',0),
        o.get('alloc_effective',0), o.get('write_size',0),
        o.get('write_func',''), o.get('write_line',0)))
