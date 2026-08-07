import sys
sys.path.insert(0, '.')
import re
from analysis.heap_overflow_src_verifier import HeapOverflowSrcVerifier
from analysis.heap_overflow_src_phases import find_allocs, find_writes
from analysis.heap_overflow_src_patterns import _skip_block_comments
from analysis.heap_overflow_src_interproc import resolve_factory_allocs, resolve_cross_func_writes
from analysis.heap_overflow_src_guards import find_loop_bound_const, infer_stride

src = open('tests/cve_samples/heap_overflow/cve_20_cross_func_guard/cross_func_guard.c', encoding='utf-8').read()
lines = src.splitlines()
valid = {ln for ln, _ in _skip_block_comments(lines)}
allocs = find_allocs(lines, valid)
allocs.extend(resolve_factory_allocs(lines, allocs))
print('allocs:', [(a.var, a.size_const, a.size_expr, a.line) for a in allocs])
writes = find_writes(lines, allocs, valid)
writes.extend(resolve_cross_func_writes(lines, allocs, writes))
for w in writes:
    if w.target == 'buf':
        sv = getattr(w, 'src_var', '')
        print(f'  write line={w.line} kind={w.kind} src_var={sv} size={w.write_size}')
        lb = find_loop_bound_const(lines, w.line, w.target)
        print(f'    loop_bound={lb}')
        for a in allocs:
            if a.var == 'buf':
                sz_var = a.size_expr.strip()
                sc = a.size_const
                print(f'    sz_var={sz_var} sc={sc}')
                search_text = '\n'.join(lines[max(0, w.line-5):w.line])
                m = re.search(r'for\s*\([^;]*;\s*\w+\s*<\s*' + re.escape(sz_var) + r'\s*[;]', search_text)
                print(f'    same_var_match={bool(m)}')
                print(f'    search_text={repr(search_text[:200])}')

v = HeapOverflowSrcVerifier()
results = v.verify(src)
for r in results:
    print(f'RESULT: {r.verdict.name} conf={r.confidence} reason={r.reason}')
