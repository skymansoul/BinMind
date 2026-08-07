"""诊断extract_heap_ops_c"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.source_scanner import extract_heap_ops_c

for name, path in [
    ('canbcm', 'samples/cve_heap_overflow/cve_2021_3609_canbcm/canbcm_overflow.c'),
    ('nf1015', 'samples/cve_heap_overflow/cve_2022_1015_netfilter/nf_expr_overflow.c'),
    ('uaf44733', 'samples/cve_heap_overflow/cve_2021_44733_uaf/uaf_overflow.c'),
]:
    source = open(path, encoding='utf-8', errors='replace').read()
    ops = extract_heap_ops_c(source)
    print(f'\n=== {name}: {len(ops)} ops ===')
    for op in ops:
        print(f'  type={op.get("type")} ptr={op.get("ptr_var","")} '
              f'func={op.get("write_func",op.get("func",""))} '
              f'ws={op.get("write_size",0)} '
              f'is_ovf={op.get("is_overflow")} '
              f'eff={op.get("alloc_effective",0)}')
