"""调试二进制级样本的FCPV检测."""
import sys
sys.path.insert(0, '.')

from core.fcpv_constraint_collector import FcpvConstraintCollector
from core.fcpv_pipeline import fcpv_filter
import os

bin_dir = 'modules/vuln/detection/src/format/fmt_samples'
for d in sorted(os.listdir(bin_dir)):
    p = os.path.join(bin_dir, d, 'main.c')
    if not os.path.isfile(p):
        continue
    src = open(p, encoding='utf-8', errors='replace').read()
    c = FcpvConstraintCollector()
    cands = c.collect(src)
    r = fcpv_filter(src)
    print(f'\n=== {d} ===')
    print(f'Tainted: {c.tainted_set}')
    print(f'Sources: {c._taint_sources[:3]}')
    has_vuln = r['has_vuln']
    for v in r['vuln']:
        print(f'  VULN: {v.sink.sink_func}({v.sink.fmt_arg}) L{v.sink.line} {v.reason[:80]}')
    if not has_vuln:
        for u in r['uncertain']:
            print(f'  UNC: {u.sink.sink_func}({u.sink.fmt_arg}) L{u.sink.line} {u.reason[:80]}')
        for s in r['safe']:
            print(f'  SAFE: {s.sink.sink_func}({s.sink.fmt_arg}) L{s.sink.line} {s.reason[:60]}')
