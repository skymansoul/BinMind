"""DFC-PV 辅助模块 — 模式3/3b 跨函数检测逻辑.
"""

from typing import List, Optional, Set, Tuple

from analysis.dfc_pv_types import DfcVerdict, DfcResult, FreeSite
from analysis.dfc_pv_resolver import AOITracker
from analysis.dfc_pv_path import PathAnalyzer
from analysis.dfc_pv_crossfunc import CrossFuncAnalyzer


def detect_cross_func_pairs(
        frees: List[FreeSite], aoi: AOITracker,
        path_analyzer: PathAnalyzer,
        cross_func: CrossFuncAnalyzer,
        source: str) -> List[DfcResult]:
    """模式3: 包装函数调用与直接 free 的配对 (双向检测).
    场景A: wrapper 调用后直接 free
    场景B: 直接 free 后调用 wrapper
    """
    results: List[DfcResult] = []
    wrapper_calls = cross_func.find_wrapper_calls_with_args()
    for call_line, wname, arg_var in wrapper_calls:
        freed_in_chain = cross_func.find_transitive_frees(wname)
        if not freed_in_chain:
            continue
        for f in frees:
            if f.func == wname:
                continue
            if f.line == call_line and f.func == wname:
                continue
            if arg_var:
                matched = _same_or_alias(arg_var, f.base_var, aoi) or \
                    _same_or_alias(arg_var, f.var_expr, aoi)
                if not matched and cross_func.is_global_var(f.base_var):
                    matched = True
            else:
                matched = cross_func.is_global_var(f.base_var)
            if matched:
                la, lb = sorted([call_line, f.line])
                if not _check_path_safety(
                        f.base_var, la, lb, aoi, path_analyzer, source):
                    results.append(DfcResult(
                        verdict=DfcVerdict.VULN,
                        first_free_line=la, second_free_line=lb,
                        var_name=f.var_expr, confidence=0.85,
                        pattern='cross_func',
                        reason=f"'{wname}' freed at L{call_line}, "
                               f"direct free at L{f.line}"))
    return results


def detect_callback_df(
        frees: List[FreeSite], aoi: AOITracker,
        path_analyzer: PathAnalyzer,
        cross_func: CrossFuncAnalyzer,
        source: str) -> List[DfcResult]:
    """模式3b: wrapper 内部多个 free 指向同一参数 (回调双释放)."""
    results: List[DfcResult] = []
    wrapper_calls = cross_func.find_wrapper_calls_with_args()
    for call_line, wname, arg_var in wrapper_calls:
        if not arg_var:
            continue
        args = [a.strip() for a in arg_var.split(',') if a.strip()]
        wname_params = cross_func.func_map.get(wname, (0, 0, []))[2]
        chain_funcs = list(cross_func.find_transitive_frees(wname))
        for arg in args:
            if arg in cross_func.func_map and \
               arg in cross_func.wrappers and arg not in chain_funcs:
                chain_funcs.append(arg)

        arg_to_inner = {}
        for i, arg in enumerate(args):
            if i < len(wname_params):
                arg_to_inner[arg] = wname_params[i]

        for arg in args:
            free_count, freed_by = _count_chain_frees(
                arg, inner_var=arg_to_inner.get(arg, arg),
                chain_funcs=chain_funcs, wname=wname,
                wname_params=wname_params, args=args,
                frees=frees, aoi=aoi, cross_func=cross_func)
            if free_count >= 2:
                la, lb = sorted([freed_by[0][0], freed_by[1][0]])
                if not _check_path_safety(
                        arg_to_inner.get(arg, arg), la, lb,
                        aoi, path_analyzer, source):
                    results.append(DfcResult(
                        verdict=DfcVerdict.VULN,
                        first_free_line=la, second_free_line=lb,
                        var_name=arg, confidence=0.82,
                        pattern='callback_df',
                        reason=f"'{arg}' double-freed inside "
                               f"wrapper chain '{wname}'"))
    return results


def _count_chain_frees(
        arg: str, inner_var: str, chain_funcs: List[str],
        wname: str, wname_params: List[str], args: List[str],
        frees: List[FreeSite], aoi: AOITracker,
        cross_func: CrossFuncAnalyzer) -> Tuple[int, List[Tuple[int, str]]]:
    """统计 wrapper 链内指向同一参数的 free 次数."""
    free_count = 0
    freed_by: List[Tuple[int, str]] = []
    for fn_in_chain in chain_funcs:
        fn_s, fn_e, _ = cross_func.func_map.get(fn_in_chain, (0, 0, []))
        if fn_in_chain == wname:
            check_var = inner_var
        elif fn_in_chain in args:
            cb_args = cross_func.find_cb_call_args(
                wname, fn_in_chain, wname_params)
            cb_fn_params = cross_func.func_map.get(
                fn_in_chain, (0, 0, []))[2]
            check_var = _resolve_cb_param(
                cb_args, inner_var, cb_fn_params)
        else:
            check_var = cross_func.map_param_through_chain(
                wname, fn_in_chain, inner_var)
        if not check_var:
            continue
        for fl in frees:
            if fn_s <= fl.line <= fn_e:
                if _same_or_alias(check_var, fl.base_var, aoi) or \
                   _same_or_alias(check_var, fl.var_expr, aoi):
                    free_count += 1
                    freed_by.append((fl.line, fn_in_chain))
    return free_count, freed_by


def _resolve_cb_param(cb_args: List[str], inner_var: str,
                      cb_fn_params: List[str]) -> str:
    """从回调调用实参映射到回调函数形参."""
    for ci, cba in enumerate(cb_args):
        if cba == inner_var and ci < len(cb_fn_params):
            return cb_fn_params[ci]
    return cb_fn_params[0] if cb_fn_params else ''


def _same_or_alias(a: str, b: str, aoi: AOITracker) -> bool:
    if a == b:
        return True
    a_clean = a.lstrip('*').strip()
    b_clean = b.lstrip('*').strip()
    if a_clean == b_clean:
        return True
    return aoi.resolver.bidirectional_alias(a, b) or \
        aoi.resolver.bidirectional_alias(a_clean, b_clean)


def _check_path_safety(var: str, la: int, lb: int,
                       aoi: AOITracker,
                       path_analyzer: PathAnalyzer,
                       source: str) -> bool:
    if aoi.is_null_before_free(var, la):
        return True
    if aoi.has_unconditional_null_between(var, la, lb):
        return True
    if aoi.has_realloc_between(var, la, lb):
        return True
    flags = path_analyzer.find_freed_flags(source)
    if path_analyzer.has_freed_flag_between(la, lb, flags):
        return True
    return False
