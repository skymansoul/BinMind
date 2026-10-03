"""
过程间仿射关系追踪 — 跨函数边界的 alloc-write 符号差分.

核心问题: AffineRelationTracker 仅处理单函数伪代码, 但真实堆溢出常跨函数
  (f() malloc → g() memcpy). 本模块通过函数摘要将仿射关系扩展到过程间.

方法 (Sharir-Pnueli 过程间分析框架的轻量实例化):
  1. 为每个函数计算摘要: {param → alloc/write 仿射表达式}
  2. 调用点将实参替换形参, 实例化摘要
  3. 跨函数建立 alloc-write 仿射差分 → 判定溢出/安全

保守约束: 仅追踪一级间接; realloc/指针算术/嵌套结构体 → UNCERTAIN.
  间接调用 (函数指针) → 跳过, 不产生摘要.

参考: Sharir & Pnueli, Reps-Horwitz-Sagiv, CSA.
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional, Set, Tuple

from analysis.affine_expr import AffineExpr, parse_expression
from analysis.interprocedural_affine_types import (
    FuncAllocSummary, FuncWriteSummary, FunctionSummary, CrossFuncRelation,
)


class InterproceduralAffineTracker:
    """过程间仿射关系追踪器 — 跨函数边界的 alloc-write 符号差分.

    用法:
        tracker = InterproceduralAffineTracker()
        tracker.extract_summary(func_name, pseudocode, params)
        relations = tracker.track_cross_function(caller_pseudocode)
    """

    _FUNC_DEF_PAT = re.compile(
        r'(?:static\s+)?(?:inline\s+)?'
        r'(?:void|int|char|long|short|size_t|unsigned\s+(?:int|long|char))\s*'
        r'\*?\s*(\w+)\s*\(([^)]*)\)', re.IGNORECASE)
    _MALLOC_PAT = re.compile(
        r'(\w+)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(\s*([^)]+)\s*\)',
        re.IGNORECASE)
    _MEMCPY_PAT = re.compile(
        r'(memcpy|memmove|strncpy)\s*\(\s*([^,]+?)\s*,\s*[^,]*,\s*([^)]+)\s*\)',
        re.IGNORECASE)
    _RETURN_PAT = re.compile(r'return\s+(\w+)\s*;')
    _CALL_PAT = re.compile(r'(\w+)\s*=\s*(\w+)\s*\(([^)]*)\)')
    _TYPE_KW = frozenset([
        'int', 'char', 'long', 'short', 'void', 'unsigned', 'signed',
        'const', 'volatile', 'static', 'size_t', 'struct', 'enum', 'union'])

    def __init__(self):
        self._summaries: Dict[str, FunctionSummary] = {}
        self._var_expr: Dict[str, AffineExpr] = {}

    def extract_summary(self, func_name: str, pseudocode: str,
                        params: Optional[List[str]] = None) -> FunctionSummary:
        """从函数伪代码提取摘要 — alloc/write 操作的仿射签名."""
        if params is None:
            params = self._infer_params(pseudocode)
        summary = FunctionSummary(func_name=func_name, params=params)
        self._var_expr = {p: AffineExpr(terms={p: 1}) for p in params}

        lines = pseudocode.splitlines()
        return_var = ""
        for i, line in enumerate(lines):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            self._track_assignment(line)
            alloc = self._extract_alloc(line, i)
            if alloc:
                summary.allocs.append(alloc)
                continue
            write = self._extract_write(line, i)
            if write:
                summary.writes.append(write)
            rm = self._RETURN_PAT.search(line)
            if rm:
                return_var = rm.group(1)
        summary.return_var = return_var
        for a in summary.allocs:
            if a.alloc_var == return_var:
                a.is_returned = True
        self._summaries[func_name] = summary
        return summary

    def track_cross_function(self, caller_pseudocode: str) -> List[CrossFuncRelation]:
        """在调用者伪代码中扫描调用点, 实例化摘要, 建立跨函数关系."""
        relations: List[CrossFuncRelation] = []
        lines = caller_pseudocode.splitlines()
        local_exprs: Dict[str, AffineExpr] = {}
        for line in lines:
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            self._track_assignment_local(line, local_exprs)

        for line in lines:
            line = line.strip()
            if not line:
                continue
            cm = self._CALL_PAT.search(line)
            if not cm:
                continue
            ret_var, callee, raw_args = cm.group(1), cm.group(2), cm.group(3).strip()
            if callee not in self._summaries:
                continue
            summary = self._summaries[callee]
            arg_exprs = self._parse_args(raw_args, summary.params, local_exprs)

            for alloc in summary.allocs:
                inst_alloc = self._instantiate(alloc.size_expr, arg_exprs)
                if ret_var:
                    local_exprs[ret_var] = inst_alloc
                for write in summary.writes:
                    if write.target_var not in arg_exprs:
                        continue
                    inst_write = self._instantiate(write.write_expr, arg_exprs)
                    if write.offset_val:
                        inst_write = AffineExpr(
                            inst_write.base + write.offset_val,
                            dict(inst_write.terms))
                    diff = inst_write - inst_alloc
                    shared = inst_alloc.shared_vars(inst_write)
                    if shared:
                        verdict, cond = self._analyze_diff(diff, shared)
                    elif inst_alloc.is_constant and inst_write.is_constant:
                        if inst_write.base <= inst_alloc.base:
                            verdict = "SAFE"
                        else:
                            verdict = "OVERFLOW"
                        cond = f"{inst_write.base} vs {inst_alloc.base}"
                    else:
                        verdict, cond = "UNKNOWN", "no shared symbolic vars"
                    relations.append(CrossFuncRelation(
                        caller_func="", callee_alloc=alloc,
                        callee_write=write,
                        instantiated_alloc=inst_alloc,
                        instantiated_write=inst_write,
                        diff=diff, shared_vars=shared, verdict=verdict))
        return relations

    # 内部辅助

    def _extract_alloc(self, line: str, i: int) -> Optional[FuncAllocSummary]:
        mm = self._MALLOC_PAT.search(line)
        if not mm:
            return None
        alloc_var, alloc_func = mm.group(1), mm.group(2).lower()
        size_expr = parse_expression(mm.group(3).strip(), self._var_expr)
        self._var_expr[alloc_var] = AffineExpr(
            base=size_expr.base, terms=dict(size_expr.terms))
        return FuncAllocSummary(alloc_var=alloc_var, size_expr=size_expr,
                                alloc_func=alloc_func, line_no=i)

    def _extract_write(self, line: str, i: int) -> Optional[FuncWriteSummary]:
        mw = self._MEMCPY_PAT.search(line)
        if mw:
            dest_str = mw.group(2).strip()
            raw_size = mw.group(3).strip()
            write_expr = parse_expression(raw_size, self._var_expr)
            target_var = dest_str
            offset_val = 0
            off_match = re.match(r'(\w+)\s*\+\s*(\d+)', dest_str)
            if off_match:
                target_var = off_match.group(1)
                try:
                    offset_val = int(off_match.group(2))
                except ValueError:
                    pass
            return FuncWriteSummary(target_var=target_var, write_expr=write_expr,
                                    write_type=mw.group(1).lower(),
                                    offset_val=offset_val, line_no=i)
        if 'strcpy(' in line or 'strcat(' in line:
            sc = re.search(r'(strcpy|strcat)\s*\(\s*(\w+)', line)
            if sc:
                return FuncWriteSummary(target_var=sc.group(2),
                                        write_expr=AffineExpr(),
                                        write_type=sc.group(1).lower(), line_no=i)
        return None

    def _track_assignment(self, line: str) -> None:
        m = re.search(r'(\w+)\s*=\s*(.+?)\s*;', line)
        if not m:
            return
        lhs, rhs = m.group(1), m.group(2).strip().rstrip(';').strip()
        if lhs in ('if', 'else', 'for', 'while', 'return', 'sizeof'):
            return
        expr = parse_expression(rhs, self._var_expr)
        if expr is not None:
            self._var_expr[lhs] = expr

    @staticmethod
    def _track_assignment_local(line: str,
                                local_exprs: Dict[str, AffineExpr]) -> None:
        m = re.search(r'(\w+)\s*=\s*(.+?)\s*;', line)
        if not m:
            return
        lhs, rhs = m.group(1), m.group(2).strip().rstrip(';').strip()
        if lhs in ('if', 'else', 'for', 'while', 'return', 'sizeof'):
            return
        expr = parse_expression(rhs, local_exprs)
        if expr is not None:
            local_exprs[lhs] = expr

    @staticmethod
    def _analyze_diff(diff: AffineExpr, shared_vars: Set[str]) -> Tuple[str, str]:
        min_diff = diff.base
        max_diff = diff.base
        for _var, coef in diff.terms.items():
            if coef > 0:
                max_diff = float('inf')
            else:
                min_diff = float('-inf')
        non_shared = sum(
            abs(c) for v, c in diff.terms.items() if v not in shared_vars)
        if non_shared > 0:
            return ("CONDITIONAL", "non-shared variables unknown")
        if min_diff > 0:
            return ("OVERFLOW", f"write - alloc = {diff} > 0 ∀ inputs")
        elif max_diff <= 0:
            return ("SAFE", f"write - alloc = {diff} <= 0 ∀ inputs")
        return ("CONDITIONAL", "sign depends on variable values")

    @staticmethod
    def _instantiate(expr: AffineExpr,
                     arg_map: Dict[str, AffineExpr]) -> AffineExpr:
        result = AffineExpr(base=expr.base, terms={})
        for var, coef in expr.terms.items():
            if var in arg_map:
                sub = arg_map[var]
                result.base += coef * sub.base
                for sv, sc in sub.terms.items():
                    result.terms[sv] = result.terms.get(sv, 0) + coef * sc
            else:
                result.terms[var] = result.terms.get(var, 0) + coef
        return result

    @staticmethod
    def _parse_args(raw_args: str, params: List[str],
                    local_exprs: Dict[str, AffineExpr]) -> Dict[str, AffineExpr]:
        arg_map: Dict[str, AffineExpr] = {}
        if not raw_args or not params:
            return arg_map
        arg_list = [a.strip() for a in raw_args.split(',')]
        for j, param in enumerate(params):
            if j >= len(arg_list):
                break
            arg_str = arg_list[j]
            try:
                arg_map[param] = AffineExpr(base=int(arg_str, 0))
            except ValueError:
                if arg_str in local_exprs:
                    arg_map[param] = local_exprs[arg_str]
                elif re.match(r'^[a-zA-Z_]\w*$', arg_str):
                    arg_map[param] = AffineExpr(terms={arg_str: 1})
        return arg_map

    @staticmethod
    def _infer_params(pseudocode: str) -> List[str]:
        m = InterproceduralAffineTracker._FUNC_DEF_PAT.search(pseudocode)
        if not m:
            return []
        params_str = m.group(2).strip()
        if not params_str or params_str == 'void':
            return []
        params = []
        for part in params_str.split(','):
            for w in part.strip().split():
                if w.isidentifier() and w not in InterproceduralAffineTracker._TYPE_KW:
                    params.append(w)
        return params


def track_interprocedural_affine(
        functions: Dict[str, str],
        caller: str,
        caller_body: str) -> List[CrossFuncRelation]:
    """便捷入口: 对一组函数做过程间仿射追踪。

    functions 为 {函数名 → 伪代码} 映射。
    """
    tracker = InterproceduralAffineTracker()
    for fname, fbody in functions.items():
        if fname != caller:
            tracker.extract_summary(fname, fbody)
    return tracker.track_cross_function(caller_body)


__all__ = [
    'FuncAllocSummary', 'FuncWriteSummary', 'FunctionSummary',
    'CrossFuncRelation', 'InterproceduralAffineTracker',
    'track_interprocedural_affine',
]
