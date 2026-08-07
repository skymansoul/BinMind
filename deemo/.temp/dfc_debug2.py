"""DFC-PV debug round 2: 分析剩余 FN 和 FP."""
import os, sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from analysis.dfc_pv_extractor import extract_events
from analysis.dfc_pv_resolver import AOITracker, AliasResolver
from analysis.dfc_pv_path import PathAnalyzer
from analysis.dfc_pv_crossfunc import CrossFuncAnalyzer
from analysis.dfc_pv_types import FreeSite

def debug(name):
    samples = os.path.join(os.path.dirname(__file__), '..', 'tests', 'cve_samples')
    path = os.path.join(samples, name, 'vuln.c')
    with open(path, 'r', errors='replace') as f:
        source = f.read()
    lines = source.splitlines()
    allocs, frees, aliases, nulls, reallocs, func_map = extract_events(source)
    print(f'\n===== {name} =====')
    print(f'  Frees: {[(f.line, f.var_expr, f.base_var, f.func) for f in frees]}')
    print(f'  Allocs: {[(a.line, a.var) for a in allocs]}')
    print(f'  Aliases: {[(a.source, a.target, a.line, a.kind) for a in aliases]}')
    print(f'  Nulls: {[(n.line, n.var, n.conditional) for n in nulls]}')
    print(f'  Reallocs: {[(r.line, r.var) for r in reallocs]}')
    aoi = AOITracker(allocs, reallocs, nulls, aliases)
    print(f'  AOI: {[(n.id, n.alloc_line, n.alloc_var, n.aliases) for n in aoi.nodes]}')
    for f in frees:
        nodes = aoi.get_aoi_for_free(f)
        print(f'    Free@L{f.line}({f.var_expr}) base={f.base_var} -> AOIs={[n.id for n in nodes]}')
    resolver = aoi.resolver
    for f in frees:
        chain = resolver.resolve_chain(f.base_var)
        print(f'    Chain({f.base_var}): {chain}')
    cross = CrossFuncAnalyzer(lines, func_map)
    print(f'  FuncMap: {func_map}')
    print(f'  Wrappers: {cross.wrappers}')
    calls = cross.find_wrapper_calls_with_args()
    print(f'  WrapperCalls: {calls}')
    pa = PathAnalyzer(lines)
    for i, f1 in enumerate(frees):
        for f2 in frees[i+1:]:
            same = f1.base_var == f2.base_var or resolver.bidirectional_alias(f1.base_var, f2.base_var)
            realloc = aoi.has_realloc_between(f1.base_var, f1.line, f2.line) or aoi.has_realloc_between(f2.base_var, f1.line, f2.line)
            null = aoi.has_unconditional_null_between(f1.base_var, f1.line, f2.line)
            mutex = pa.is_mutually_exclusive(f1.line, f2.line)
            print(f'  Pair: L{f1.line}({f1.var_expr})-L{f2.line}({f2.var_expr}) same={same} realloc={realloc} null={null} mutex={mutex}')

# FN samples
for name in ['df_adv_16', 'df_adv_19', 'df_adv_23', 'df_adv_25', 'df_adv_30',
             'double_free_06', 'double_free_14']:
    debug(name)

# FP samples
for name in ['df_adv_17', 'df_adv_18', 'df_adv_21']:
    debug(name)
