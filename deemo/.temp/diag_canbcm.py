"""诊断canbcm样本匹配问题"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.source_matcher import match_alloc, WRITE_RE, _ALLOC_RE

source = open('samples/cve_heap_overflow/cve_2021_3609_canbcm/canbcm_overflow.c', encoding='utf-8', errors='replace').read()
lines = source.splitlines()
for i, raw_line in enumerate(lines):
    line = raw_line.strip()
    if not line or line.startswith(('/', '*', '#')):
        continue
    alloc = match_alloc(line)
    if alloc:
        print(f'ALLOC line {i+1}: ptr={alloc["ptr_var"]} func={alloc["func"]} size={alloc["size_expr"]}')
    wm = WRITE_RE.search(line)
    if wm:
        print(f'WRITE line {i+1}: func={wm.group(1)} args={wm.group(2)[:80]}')
    # 也测试原始正则
    am = _ALLOC_RE.search(line)
    if am and not alloc:
        print(f'RAW_ALLOC line {i+1}: groups={am.groups()}')
