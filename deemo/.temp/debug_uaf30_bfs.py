"""Debug uaf_30 BFS state propagation."""
import sys
sys.path.insert(0, '.')
from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_temporal_scanner import TemporalScanner
from analysis.uaf_temporal_path_types import PtrState
from analysis.uaf_interprocedural import InterprocSummarizer
from analysis.lpvra_types import build_simple_cfg
from collections import deque

source = open('tests/cve_samples/uaf/uaf_30/uaf_30_callback_dtor.c', 'r', encoding='utf-8').read()
lines = source.splitlines()

tpv = TemporalPathVerifier()
frees = TemporalScanner.find_frees(lines)
summarizer = InterprocSummarizer()
vfrees, _ = summarizer.propagate(source)
all_frees = list(frees) + vfrees

blocks, adj = build_simple_cfg(lines)

# 构建 vfree_map
vfree_map = {}
for vf_l, vf_c, vf_v in all_frees:
    if vf_l <= len(lines):
        stripped = TemporalScanner._strip_comments(lines[vf_l - 1]).strip()
        if not TemporalScanner._FREE_RE.search(stripped):
            vfree_map.setdefault(vf_l, vf_v)

print('vfree_map:', vfree_map)

# 模拟 _check_pair 对 free@L15, use@L17
fvar, fl, uvar, ul = 'obj', 15, 'obj', 17
free_block = use_block = -1
for b in blocks:
    if b['start'] <= fl - 1 <= b['end']:
        free_block = b['id']
    if b['start'] <= ul - 1 <= b['end']:
        use_block = b['id']
print(f'free_block={free_block}, use_block={use_block}')

b = blocks[free_block]
new_state = {}
for si, stmt in enumerate(b['stmts']):
    s = TemporalScanner._strip_comments(stmt).strip()
    stmt_line = b['start'] + si + 1
    print(f'L{stmt_line}: "{s}"')

    fm = TemporalScanner._FREE_RE.search(s)
    if fm:
        new_state[fm.group(1)] = PtrState.FREED
        print(f'  -> free detected: {fm.group(1)}')

    if stmt_line in vfree_map:
        vf_var = vfree_map[stmt_line]
        new_state[vf_var] = PtrState.FREED
        print(f'  -> virtual free: {vf_var}')

    # Check if use
    if stmt_line == ul:
        print(f'  -> USE at L{stmt_line}: state={new_state}')
        obj_state = new_state.get('obj', PtrState.UNKNOWN)
        print(f'  -> obj state: {obj_state}')
