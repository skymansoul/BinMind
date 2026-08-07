"""深度诊断_pair_ops"""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from tests.source_scanner import extract_heap_ops_c
from tests.source_matcher import match_alloc, WRITE_RE, extract_base_ptr, extract_macros

# canbcm
source = open('samples/cve_heap_overflow/cve_2021_3609_canbcm/canbcm_overflow.c', encoding='utf-8', errors='replace').read()
macros = extract_macros(source)
lines = source.splitlines()

# 手动模拟 source_scanner 的逐行扫描
alloc_list = []
findings = []
for i, raw_line in enumerate(lines):
    line = raw_line.strip()
    if not line or line.startswith(('/', '*', '#')):
        continue
    line_no = i + 1
    alloc = match_alloc(line)
    if alloc:
        ptr_var = alloc['ptr_var']
        if alloc.get('alloc_type') == 'return_alloc':
            continue
        base = extract_base_ptr(ptr_var) if ptr_var else ptr_var
        alloc_list.append({
            'ptr_var': ptr_var, 'base_ptr': base,
            'func': alloc['func'], 'size_expr': alloc['size_expr'],
            'line_no': line_no, 'line': line,
        })
        continue
    wm = WRITE_RE.search(line)
    if wm:
        func = wm.group(1).lower()
        args_str = wm.group(2)
        from tests.source_scanner_helpers import _parse_args as pa
        args = pa(args_str)
        # 构造finding
        if func in ('memcpy','memmove','memset','strcpy','strncpy','strcat','strncat','sprintf','snprintf') and len(args) >= 1:
            ptr_expr = args[0].strip()
            base_ptr = extract_base_ptr(ptr_expr)
            ws = 0
            if func in ('memcpy','memmove','memset','strncpy','strncat','snprintf') and len(args) >= 3:
                from tests.source_classifier import eval_size
                ws = eval_size(args[2].strip(), macros)
            elif func in ('strcpy','strcat','sprintf'):
                ws = 999999
            findings.append({
                'type': 'write', 'func': func,
                'ptr': base_ptr, 'ptr_full': ptr_expr,
                'write_size': ws, 'size_expr': args[2].strip() if len(args)>=3 else '',
                'line_no': line_no, 'line': line,
            })

print(f'alloc_list ({len(alloc_list)}):')
for a in alloc_list:
    print(f'  ptr_var={a["ptr_var"]!r} base_ptr={a["base_ptr"]!r} func={a["func"]} line={a["line_no"]}')
print(f'\nfindings ({len(findings)}):')
for f in findings:
    print(f'  ptr={f["ptr"]!r} func={f["func"]} ws={f["write_size"]} line={f["line_no"]}')

# 现在测试 find_nearest_alloc
from tests.source_matcher import find_nearest_alloc
print(f'\n配对测试:')
for f in findings:
    if f['type'] in ('write', 'array_write'):
        ptr = f['ptr']
        alloc = find_nearest_alloc(alloc_list, ptr, f['line_no'])
        if alloc:
            print(f'  MATCH: write ptr={ptr!r} -> alloc ptr_var={alloc["ptr_var"]!r}')
        else:
            print(f'  NOMATCH: write ptr={ptr!r} line={f["line_no"]}')
