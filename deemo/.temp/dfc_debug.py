"""DFC-PV debug: 逐样本输出诊断信息."""
import os, sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from analysis.dfc_pv_extractor import extract_events
from analysis.dfc_pv_resolver import AOITracker
from analysis.dfc_pv_path import PathAnalyzer
from analysis.dfc_pv_crossfunc import CrossFuncAnalyzer

def debug_sample(name):
    samples = os.path.join(os.path.dirname(__file__), '..', 'tests', 'cve_samples')
    path = os.path.join(samples, name, 'vuln.c')
    if not os.path.isfile(path):
        print(f'NOT FOUND: {name}')
        return
    with open(path, 'r', errors='replace') as f:
        source = f.read()
    lines = source.splitlines()

    allocs, frees, aliases, nulls, reallocs, func_map = extract_events(source)
    print(f'\n===== {name} =====')
    print(f'Allocs: {[(a.line, a.var) for a in allocs]}')
    print(f'Frees: {[(f.line, f.var_expr, f.base_var) for f in frees]}')
    print(f'Aliases: {[(a.source, a.target, a.line, a.kind) for a in aliases]}')
    print(f'Nulls: {[(n.line, n.var, n.conditional) for n in nulls]}')
    print(f'Reallocs: {[(r.line, r.var) for r in reallocs]}')
    print(f'FuncMap: {func_map}')

    if frees:
        aoi = AOITracker(allocs, reallocs, nulls, aliases)
        print(f'AOI nodes: {[(n.id, n.alloc_line, n.alloc_var, n.aliases) for n in aoi.nodes]}')
        for f in frees:
            nodes = aoi.get_aoi_for_free(f)
            print(f'  Free@L{f.line}({f.var_expr}) -> AOI: {[n.id for n in nodes]}')
        cross_func = CrossFuncAnalyzer(lines, func_map)
        print(f'Wrappers: {cross_func.wrappers}')
        print(f'CallGraph: {cross_func.call_graph}')
        transitive = {}
        for fn in func_map:
            t = cross_func.find_transitive_frees(fn)
            if t:
                transitive[fn] = t
        print(f'TransitiveFrees: {transitive}')

for name in ['df_adv_19', 'df_adv_25', 'df_adv_30', 'double_free_03',
             'double_free_08', 'double_free_12', 'double_free_13', 'double_free_14',
             'df_adv_17', 'df_adv_18', 'df_adv_21']:
    debug_sample(name)
