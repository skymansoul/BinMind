"""分析剩余1 FP + 1 FN根因."""
import os, sys, glob
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)

from eval.cve_full_comparison_tools import _run_hosv_source, _run_csa_source

# cve_39: FP
src39 = open(os.path.join(BASE, 'tests/cve_samples/heap_overflow/cve_39_loop_guard_cross_path/loop_guard_cross_path.c'), encoding='utf-8', errors='replace').read()
h39 = _run_hosv_source(src39, 'cve_39')
c39 = _run_csa_source(src39, 'cve_39')
print('cve_39 FP analysis:')
print('  HOSV: detected=%s vuln=%d unc=%d safe=%d all_safe=%s' % (
    h39['detected'], h39.get('n_vuln',0), h39.get('n_uncertain',0),
    h39.get('n_safe',0), h39.get('all_safe')))
print('  CSA:  detected=%s overflow=%d unc=%d total=%d' % (
    c39['detected'], c39.get('n_overflow',0), c39.get('n_uncertain',0), c39.get('n_total',0)))
if c39.get('error'):
    print('  CSA error:', c39['error'])

# cve_52: FN
cfiles52 = glob.glob(os.path.join(BASE, 'tests/cve_samples/heap_overflow/cve_52_*/*.c'))
if cfiles52:
    src52 = open(cfiles52[0], encoding='utf-8', errors='replace').read()
    h52 = _run_hosv_source(src52, 'cve_52')
    c52 = _run_csa_source(src52, 'cve_52')
    print('\ncve_52 FN analysis (%s):' % cfiles52[0])
    print('  HOSV: detected=%s vuln=%d unc=%d safe=%d all_safe=%s' % (
        h52['detected'], h52.get('n_vuln',0), h52.get('n_uncertain',0),
        h52.get('n_safe',0), h52.get('all_safe')))
    print('  CSA:  detected=%s overflow=%d unc=%d total=%d' % (
        c52['detected'], c52.get('n_overflow',0), c52.get('n_uncertain',0), c52.get('n_total',0)))
    if c52.get('error'):
        print('  CSA error:', c52['error'])

    # 查看CSA提取的ops详情
    from tests.source_scanner_part1 import extract_heap_ops_c
    ops = extract_heap_ops_c(src52)
    print('\n  CSA ops detail:')
    for o in ops:
        print('    %s' % {k: v for k, v in o.items() if k != 'lines'})

# 检查IR fallback对cve_52
from eval.cve_full_comparison_tools import c_to_ir
from core.heap_overflow_pipeline import detect_heap_overflows_full
if cfiles52:
    ir = c_to_ir(src52)
    print('\n  IR lines for cve_52:', ir)
    candidates, stats = detect_heap_overflows_full(ir, src52)
    print('  IR candidates:', len(candidates))
