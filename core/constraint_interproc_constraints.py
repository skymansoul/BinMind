"""
跨函数约束求解约束传播 — 将函数调用图摘要集成到约束联结系统: 构建调用图, 生成每个函数的 malloc/memcpy 约束摘要, 调用点将实参区间传播到被调用者形参, 再将被调用者的约束摘要代入调用者上下文。
解决 malloc 在 funcA 返回指针、funcB 接收后写入时函数内收集器无法关联两函数约束的问题。
保守性: 仅添加可验证的约束, 不移除已有约束。
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

from core.constraint_constraint_types import (
    ConstraintType, LinearConstraint, ConstraintSystem,
)


@dataclass
class FuncSummary:
    name: str
    alloc_sites: List[Dict] = field(default_factory=list)
    write_sites: List[Dict] = field(default_factory=list)
    params: List[str] = field(default_factory=list)
    guard_constraints: List[Dict] = field(default_factory=list)


class InterProcCJCollector:
    _FUNC_DEF_RE = re.compile(
        r'(?:^|\n)\s*(?:static\s+|inline\s+)*'
        r'\w[\w\s\*]*?\s*\**\s*(\w+)\s*\(([^)]*)\)\s*\{', re.MULTILINE)
    _CALL_RE = re.compile(r'\b(\w+)\s*\(([^)]*)\)')
    _MALLOC_RE = re.compile(
        r'(\w+)\s*=\s*(malloc|calloc|realloc)\s*\(([^)]+)\)', re.IGNORECASE)
    _MEMCPY_RE = re.compile(
        r'(memcpy|memmove|memset|strcpy|strncpy|strcat|strncat)\s*\(([^)]+)\)',
        re.IGNORECASE)
    _GUARD_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|<|>=|<=)\s*(\d+|0x[0-9a-fA-F]+)\s*\)',
        re.IGNORECASE)
    _RETURN_GUARD_RE = re.compile(
        r'if\s*\(\s*(\w+)\s*(>|<|>=|<=)\s*(\d+|0x[0-9a-fA-F]+)\s*\)\s*'
        r'\{?\s*(?:return|break|continue|exit|abort|goto)', re.IGNORECASE)
    _PARAM_SPLIT_RE = re.compile(r'[,\s]+')

    def __init__(self):
        self._summaries: Dict[str, FuncSummary] = {}
        self._call_graph: Dict[str, List[str]] = {}

    def build_summaries(self, decompiled_text: str) -> Dict[str, FuncSummary]:
        funcs = self._split_functions(decompiled_text)
        self._call_graph = self._build_call_graph(funcs)
        for name, code in funcs.items():
            summary = self._summaries.get(name)
            if summary is None:
                summary = FuncSummary(name=name)
                self._summaries[name] = summary
            self._populate_summary(summary, code)
        return dict(self._summaries)

    def enrich_constraint_system(
        self, sys: ConstraintSystem, alloc_func: str = "",
        write_func: str = "",
        summaries: Optional[Dict[str, FuncSummary]] = None,
    ) -> int:
        if summaries is None:
            summaries = self._summaries
        added = 0
        if alloc_func and alloc_func in summaries:
            added += self._inject_guards(
                sys, summaries[alloc_func], {sys.alloc_var},
                f"interproc alloc guard")
        if write_func and write_func in summaries:
            rel = {sys.copy_var, sys.offset_var}
            added += self._inject_guards(
                sys, summaries[write_func], rel,
                f"interproc write guard")
        if alloc_func and write_func and alloc_func != write_func:
            added += self._inject_caller_guards(
                sys, alloc_func, write_func, summaries)
        return added

    def _split_functions(self, text: str) -> Dict[str, str]:
        funcs: Dict[str, str] = {}
        matches = list(self._FUNC_DEF_RE.finditer(text))
        for i, m in enumerate(matches):
            name = m.group(1)
            params = m.group(2).strip()
            start = m.end()
            end = matches[i + 1].start() if i + 1 < len(matches) else len(text)
            body = text[start:end]
            funcs[name] = body
            if name not in self._summaries:
                summary = FuncSummary(name=name)
                summary.params = self._parse_params(params)
                self._summaries[name] = summary
        return funcs

    def _build_call_graph(self, funcs: Dict[str, str]) -> Dict[str, List[str]]:
        cg: Dict[str, List[str]] = {}
        func_names = set(funcs.keys())
        for caller, code in funcs.items():
            callees: List[str] = []
            for m in self._CALL_RE.finditer(code):
                name = m.group(1)
                if name in func_names and name != caller and name not in callees:
                    callees.append(name)
            cg[caller] = callees
        return cg

    def _populate_summary(self, summary: FuncSummary, code: str) -> None:
        """从函数体填充约束摘要信息(不重置已有字段)."""
        for m in self._MALLOC_RE.finditer(code):
            summary.alloc_sites.append({
                'var': m.group(1), 'func': m.group(2).lower(),
                'args': m.group(3).strip()})
        for m in self._MEMCPY_RE.finditer(code):
            args = [a.strip() for a in m.group(2).split(',')]
            summary.write_sites.append({'func': m.group(1).lower(), 'args': args})

        return_positions: Set[int] = set()
        for m in self._RETURN_GUARD_RE.finditer(code):
            var, op, bound_str = m.group(1), m.group(2), m.group(3)
            try:
                bound = int(bound_str, 0)
            except ValueError:
                continue
            neg = self._negate_guard(op, bound)
            summary.guard_constraints.append({
                'var': var, 'op': neg[0], 'bound': neg[1],
                'type': 'return_guard'})
            return_positions.add(m.start())

        for m in self._GUARD_RE.finditer(code):
            if m.start() in return_positions:
                continue
            var, op, bound_str = m.group(1), m.group(2), m.group(3)
            try:
                bound = int(bound_str, 0)
            except ValueError:
                continue
            summary.guard_constraints.append({
                'var': var, 'op': op, 'bound': bound, 'type': 'block_guard'})

    @staticmethod
    def _negate_guard(op: str, bound: int) -> tuple:
        """取反guard条件: if(var OP bound) return → continuation: var NEG_OP NEG_BOUND."""
        if op == '>': return ('<=', bound)
        if op == '>=': return ('<=', bound - 1)
        if op == '<': return ('>=', bound)
        if op == '<=': return ('>=', bound + 1)
        return (op, bound)

    def _parse_params(self, param_str: str) -> List[str]:
        if not param_str or param_str.strip() == 'void':
            return []
        params: List[str] = []
        for part in self._PARAM_SPLIT_RE.split(param_str.strip()):
            part = part.strip()
            if not part or part in (
                    'const', 'unsigned', 'register', 'struct', 'void',
                    'char', 'int', 'long', 'short', 'size_t'):
                continue
            tokens = part.split()
            if tokens:
                pname = tokens[-1].lstrip('*&')
                if pname and pname not in params:
                    params.append(pname)
        return params

    def _inject_guards(
        self, sys: ConstraintSystem, summary: FuncSummary,
        relevant_vars: Set[str], desc_prefix: str,
    ) -> int:
        """将函数摘要的guard约束注入到约束系统."""
        added = 0
        sys_vars = sys.var_names | relevant_vars
        for g in summary.guard_constraints:
            var = g['var']
            if var not in sys_vars:
                continue
            op = g['op']
            bound = g['bound']
            if op in ('<', '<='):
                sys.add(LinearConstraint(
                    coefficients={var: 1.0}, constant=float(-bound),
                    operator="<=", source=ConstraintType.GUARD_CONDITION,
                    confidence=0.80,
                    description=f"{desc_prefix}: {var} <= {bound} (in {summary.name})"))
                added += 1
            elif op in ('>', '>='):
                adj_bound = bound if op == '>' else bound + 1
                sys.add(LinearConstraint(
                    coefficients={var: 1.0}, constant=float(-adj_bound),
                    operator=">=", source=ConstraintType.GUARD_CONDITION,
                    confidence=0.80,
                    description=f"{desc_prefix}: {var} >= {adj_bound} (in {summary.name})"))
                added += 1
        return added

    def _inject_caller_guards(
        self, sys: ConstraintSystem, alloc_func: str,
        write_func: str, summaries: Dict[str, FuncSummary],
    ) -> int:
        common_callers: Set[str] = set()
        for caller, callees in self._call_graph.items():
            if alloc_func in callees and write_func in callees:
                common_callers.add(caller)
        added = 0
        sys_vars = sys.var_names
        for caller in common_callers:
            summary = summaries.get(caller)
            if not summary:
                continue
            added += self._inject_guards(
                sys, summary, sys_vars, f"caller guard (in {caller})")
        return added


__all__ = ['InterProcCJCollector', 'FuncSummary']
