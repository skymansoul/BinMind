"""Debug uaf_30 virtual free in BFS."""
import sys
sys.path.insert(0, '.')
from analysis.uaf_temporal_path_verifier import TemporalPathVerifier
from analysis.uaf_temporal_scanner import TemporalScanner
from analysis.uaf_interprocedural import InterprocSummarizer
from analysis.lpvra_types import build_simple_cfg

source = open('tests/cve_samples/uaf/uaf_30/uaf_30_callback_dtor.c', 'r', encoding='utf-8').read()
lines = source.splitlines()

summarizer = InterprocSummarizer()
vfrees, _ = summarizer.propagate(source)
print('vfrees:', vfrees)

blocks, adj = build_simple_cfg(lines)
for b in blocks:
    if b['start'] <= 14 <= b['end']:
        print(f'Block containing L15: {b}')
        for si, stmt in enumerate(b['stmts']):
            stmt_line = b['start'] + si + 1
            stripped = TemporalScanner._strip_comments(stmt).strip()
            fm = TemporalScanner._FREE_RE.search(stripped)
            print(f'  L{stmt_line}: stripped="{stripped}" free_match={fm}')
            for vf_l, vf_c, vf_v in vfrees:
                if vf_l == stmt_line:
                    is_real_free = bool(TemporalScanner._FREE_RE.search(stripped))
                    print(f'    -> virtual free: {vf_v} (is_real_free={is_real_free})')
