"""检查真实CVE中CSA is_overflow=True的ops的eff_size分布."""
import os, sys, glob
BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)
from tests.source_scanner_part1 import extract_heap_ops_c

root = os.path.join(BASE, 'samples', 'cve_heap_overflow')
for d in sorted(os.listdir(root)):
    src_dir = os.path.join(root, d)
    if not os.path.isdir(src_dir):
        continue
    cfiles = glob.glob(os.path.join(src_dir, '*.c'))
    if not cfiles:
        continue
    src = open(cfiles[0], encoding='utf-8', errors='replace').read()
    ops = extract_heap_ops_c(src)
    ovf_ops = [o for o in ops if o.get('is_overflow')]
    if ovf_ops:
        for o in ovf_ops:
            eff = o.get('alloc_effective', 0)
            ws = o.get('write_size', 0)
            print('%s: eff=%d ws=%d func=%s line=%d %s' % (
                d, eff, ws, o.get('write_func',''), o.get('write_line',0),
                'EFF_ZERO!' if eff <= 0 else ''))
