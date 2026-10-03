"""DFC-PV 主验证器 — 整合 AOI 追踪 + 路径分析 + 跨函数分析的 double-free 判定.

核心判定流程:
  1. 事件提取: free 调用 / 分配 / 别名 / NULL 赋值 / realloc
  2. 包装函数检测: 循环内 free / wrapper 多次调用 / wrapper 调用后直接 free
  3. 配对检测: 对每对 free, 通过 AOI 或别名链判定是否指向同一分配对象
  4. 安全性证明: realloc/NULL/互斥路径/守卫条件 — 任一成立则 SAFE
  5. 裁决: 无法证明安全则为 VULN
"""

import re
from typing import Dict, List, Optional, Set, Tuple

from analysis.dfc_pv_types import (
    DfcVerdict, DfcResult, FreeSite, AllocSite, AliasEdge,
    NullAssign, ReallocSite)
from analysis.dfc_pv_extractor import extract_events
from analysis.dfc_pv_resolver import AOITracker
from analysis.dfc_pv_path import PathAnalyzer
from analysis.dfc_pv_crossfunc import CrossFuncAnalyzer
from analysis.dfc_pv_helpers import (
    detect_cross_func_pairs, detect_callback_df, _same_or_alias,
    _check_path_safety)


class DfcPvVerifier:
    """Double-free Causal-chain Pattern Verifier 主验证器."""

    def verify(self, source: str) -> List[DfcResult]:
        lines = source.splitlines()
        allocs, frees, aliases, nulls, reallocs, func_map = \
            extract_events(source)
        if not frees:
            return []

        aoi = AOITracker(allocs, reallocs, nulls, aliases)
        path_analyzer = PathAnalyzer(lines)
        cross_func = CrossFuncAnalyzer(lines, func_map)

        results: List[DfcResult] = []

        # 模式1: 循环内 free
        for f in frees:
            if path_analyzer.in_loop_body(f.line):
                results.append(DfcResult(
                    verdict=DfcVerdict.VULN, first_free_line=f.line,
                    second_free_line=f.line, var_name=f.var_expr,
                    confidence=0.90, pattern='loop',
                    reason=f"'{f.var_expr}' free@L{f.line} inside loop body"))

        # 模式2: 包装函数多次调用 (同一 wrapper 被调用 >= 2 次)
        for wrapper in cross_func.wrappers:
            call_count = cross_func.count_calls(wrapper)
            if call_count >= 2:
                for f in frees:
                    enc = cross_func.enclosing(f.line)
                    if enc == wrapper:
                        results.append(DfcResult(
                            verdict=DfcVerdict.VULN,
                            first_free_line=f.line,
                            second_free_line=f.line,
                            var_name=f.var_expr, confidence=0.88,
                            pattern='wrapper',
                            reason=f"'{wrapper}' wraps free "
                                   f"called {call_count}x"))

        # 模式3+3b: 跨函数检测 (委托 helper)
        results.extend(detect_cross_func_pairs(
            frees, aoi, path_analyzer, cross_func, source))
        results.extend(detect_callback_df(
            frees, aoi, path_analyzer, cross_func, source))

        # 模式4: 全局变量跨函数 free 对 (无显式 wrapper 调用)
        for i in range(len(frees)):
            for j in range(i + 1, len(frees)):
                a, b = frees[i], frees[j]
                enc_a = cross_func.enclosing(a.line)
                enc_b = cross_func.enclosing(b.line)
                if enc_a and enc_b and enc_a != enc_b:
                    if cross_func.is_global_var(a.base_var) and \
                       cross_func.is_global_var(b.base_var):
                        if self._same_or_alias(
                                a.base_var, b.base_var, aoi):
                            is_safe = _check_path_safety(
                                a.base_var, a.line, b.line, aoi,
                                path_analyzer, source)
                            if not is_safe:
                                chain = aoi.resolver.resolve_chain(
                                    a.base_var)
                                chain_str = ' -> '.join(chain[:5]) \
                                    if len(chain) > 1 else ''
                                results.append(DfcResult(
                                    verdict=DfcVerdict.VULN,
                                    first_free_line=a.line,
                                    second_free_line=b.line,
                                    var_name=b.var_expr,
                                    alias_chain=chain_str,
                                    confidence=0.85,
                                    pattern='cross_func',
                                    reason=f"'{a.var_expr}' free@L"
                                           f"{a.line} (in {enc_a}) and "
                                           f"'{b.var_expr}' free@L"
                                           f"{b.line} (in {enc_b})"))

        # 模式5: 配对 free 检测 (同函数内)
        if len(frees) >= 2:
            for i in range(len(frees)):
                for j in range(i + 1, len(frees)):
                    r = self._check_pair(
                        frees[i], frees[j], lines, aoi, path_analyzer,
                        cross_func, source)
                    if r:
                        results.append(r)

        # 模式6: 悬垂字段 free: free(a) 后 free(a->field)
        for i, a in enumerate(frees):
            for b in frees:
                if b.line <= a.line:
                    continue
                if '->' in b.var_expr:
                    base = b.var_expr.split('->')[0].strip()
                    if base == a.var_expr or \
                       self._same_or_alias(base, a.base_var, aoi):
                        results.append(DfcResult(
                            verdict=DfcVerdict.VULN,
                            first_free_line=a.line,
                            second_free_line=b.line,
                            var_name=b.var_expr, confidence=0.80,
                            pattern='dangling_field',
                            reason=f"'{b.var_expr}' free@L{b.line} after "
                                   f"'{a.var_expr}' freed@L{a.line}"))

        return self._dedup(results)

    def _check_pair(self, a: FreeSite, b: FreeSite,
                     lines: List[str], aoi: AOITracker,
                     path_analyzer: PathAnalyzer,
                     cross_func: CrossFuncAnalyzer,
                     source: str) -> Optional[DfcResult]:
        """检查一对 free 是否构成 double-free."""
        same = self._same_alloc_object(a, b, aoi)
        if not same:
            return None

        if aoi.is_null_before_free(a.base_var, a.line):
            return None

        if aoi.has_realloc_between(a.base_var, a.line, b.line):
            return None
        if aoi.has_realloc_between(b.base_var, a.line, b.line):
            return None

        if aoi.has_unconditional_null_between(a.base_var, a.line, b.line):
            return None

        if path_analyzer.is_mutually_exclusive(a.line, b.line):
            return None

        flags = path_analyzer.find_freed_flags(source)
        if path_analyzer.has_freed_flag_between(a.line, b.line, flags):
            return None

        # 同变量名但指向不同 AOI
        if a.base_var == b.base_var and aoi.nodes:
            aoi_a = set(aoi.get_aoi_for_free(a))
            aoi_b = set(aoi.get_aoi_for_free(b))
            if aoi_a and aoi_b and not (aoi_a & aoi_b):
                return None

        chain = aoi.resolver.resolve_chain(a.base_var)
        chain_str = ' -> '.join(chain[:5]) if len(chain) > 1 else ''

        enc_a = cross_func.enclosing(a.line)
        enc_b = cross_func.enclosing(b.line)
        cross = enc_a != enc_b and enc_a and enc_b
        pattern = 'cross_func' if cross else 'alias_chain' \
            if chain_str else 'direct'
        conf = 0.88 if cross else 0.85 if chain_str else 0.90

        return DfcResult(
            verdict=DfcVerdict.VULN,
            first_free_line=a.line, second_free_line=b.line,
            var_name=b.var_expr, alias_chain=chain_str,
            confidence=conf, pattern=pattern,
            reason=f"'{a.var_expr}' free@L{a.line} and "
                   f"'{b.var_expr}' free@L{b.line}"
                   + (f" (chain: {chain_str})" if chain_str else ""))

    def _same_alloc_object(self, a: FreeSite, b: FreeSite,
                            aoi: AOITracker) -> bool:
        """两 free 点是否指向同一分配对象."""
        if aoi.nodes:
            aoi_a = aoi.get_aoi_for_free(a)
            aoi_b = aoi.get_aoi_for_free(b)
            if aoi_a and aoi_b:
                return bool(set(aoi_a) & set(aoi_b))
        if a.base_var == b.base_var:
            return True
        if aoi.resolver.bidirectional_alias(a.base_var, b.base_var):
            return True
        if a.line == b.line:
            return aoi.resolver.bidirectional_alias(
                a.var_expr, b.var_expr)
        return False

    def _same_or_alias(self, a: str, b: str,
                        aoi: AOITracker) -> bool:
        return _same_or_alias(a, b, aoi) if False else \
            (a == b or
             a.lstrip('*').strip() == b.lstrip('*').strip() or
             aoi.resolver.bidirectional_alias(a, b) or
             aoi.resolver.bidirectional_alias(
                 a.lstrip('*').strip(), b.lstrip('*').strip()))

    def _dedup(self, results: List[DfcResult]) -> List[DfcResult]:
        seen = set()
        unique = []
        for r in results:
            key = (r.first_free_line, r.second_free_line, r.var_name)
            if key not in seen:
                seen.add(key)
                unique.append(r)
        return unique
