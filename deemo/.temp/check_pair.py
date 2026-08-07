"""检查nf1015和uaf配对结果"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from tests.source_scanner import extract_heap_ops_c

for name, path in [
    ('nf1015', 'samples/cve_heap_overflow/cve_2022_1015_netfilter/nf_expr_overflow.c'),
    ('uaf44733', 'samples/cve_heap_overflow/cve_2021_44733_uaf/uaf_overflow.c'),
]:
    source = open(path, encoding='utf-8', errors='replace').read()
    ops = extract_heap_ops_c(source)
    print(f'\n=== {name}: {len(ops)} ops ===')
    for o in ops:
        print(f'  type={o.get("type")} ptr={o.get("ptr_var","")} '
              f'wfunc={o.get("write_func","")} ws={o.get("write_size",0)} '
              f'is_ovf={o.get("is_overflow")} '
              f'eff={o.get("alloc_effective",0)} req={o.get("alloc_requested",0)} '
              f'wline={o.get("write_line","")} aline={o.get("alloc_line","")}')
