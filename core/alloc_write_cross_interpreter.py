"""
跨上下文分配-写溯源 解释器: 上下文敏感的仿射域前向传播引擎。
在每个函数调用点按 call-site 分桶独立维护仿射状态 (如 foo(n=64) 与 foo(n=128) 分属不同上下文), 独立证明 alloc_size/write_size 关系, 合并时取保守 join。
与 affine_analyzer (无上下文区分) 不同; 复杂度 O(C*N), C 为上下文数 (≤16)。
"""

from __future__ import annotations
import re
from typing import Dict, List, Optional, Set, Tuple

from core.alloc_write_cross_types import CallContext, AffineSnapshot
from core.alloc_write_cross_parser import (
    parse_size_expr as _parse_size_expr,
    expand_vars as _expand_vars,
    multiply_affine as _multiply_affine,
    split_args as _split_args,
)
from core.alloc_write_cross_helpers import process_line


_FUNC_DEF_RE = re.compile(
    r'(?:int|void|char|size_t|unsigned|struct\s+\w+|\w+_t)\s+(\w+)\s*\(([^)]*)\)\s*\{')


class CAAWPInterpreter:
    """上下文敏感仿射域前向传播解释器."""

    def __init__(self, max_contexts: int = 16):
        self._max_contexts = max_contexts
        self._snapshots: Dict[str, List[AffineSnapshot]] = {}
        self._func_params: Dict[str, List[str]] = {}
        self._call_graph: Dict[str, List[Tuple[str, str]]] = {}
        self._func_bodies: Dict[str, str] = {}

    def analyze(self, code: str) -> Dict[str, List[AffineSnapshot]]:
        """分析整段代码, 返回按函数名分组的仿射快照."""
        functions = self._split_functions(code)
        for func_name, func_body, params in functions:
            self._func_params[func_name] = params
            self._func_bodies[func_name] = func_body
            self._analyze_function(func_name, func_body, params)
        return dict(self._snapshots)

    def _split_functions(self, code: str) -> List[Tuple[str, str, List[str]]]:
        """将代码拆分为(函数名, 函数体, 参数列表)."""
        results = []
        lines = code.split('\n')
        i = 0
        while i < len(lines):
            line = lines[i]
            m = _FUNC_DEF_RE.match(line.strip())
            if m:
                func_name = m.group(1)
                params_str = m.group(2)
                params = self._parse_params(params_str)
                body_lines = []
                brace_depth = 1
                i += 1
                while i < len(lines) and brace_depth > 0:
                    body_lines.append(lines[i])
                    brace_depth += lines[i].count('{') - lines[i].count('}')
                    i += 1
                results.append((func_name, '\n'.join(body_lines[:-1] if brace_depth == 0 else body_lines), params))
            else:
                i += 1
        return results

    def _parse_params(self, params_str: str) -> List[str]:
        params = []
        for p in _split_args(params_str):
            p = p.strip()
            if not p or p == 'void':
                continue
            parts = p.split()
            if parts:
                var = parts[-1].lstrip('*')
                params.append(var)
        return params

    def _analyze_function(
        self, func_name: str, body: str, params: List[str],
    ) -> None:
        """分析单个函数, 生成上下文敏感仿射快照."""
        root_ctx = CallContext(call_chain=(func_name,), depth=1)
        snapshot = self._forward_scan(body, root_ctx, params)
        if func_name not in self._snapshots:
            self._snapshots[func_name] = []
        self._snapshots[func_name].append(snapshot)
        self._propagate_to_callees(
            body, root_ctx, func_name, visited={func_name})

    def _propagate_to_callees(
        self, body: str, parent_ctx: CallContext,
        parent_func: str, visited: set,
        parent_arg_exprs: Optional[Dict[str, Tuple[Dict[str, float], float]]] = None,
    ) -> None:
        """递归传播上下文到被调函数, 支持多层调用链."""
        call_sites = self._find_call_sites(body)
        for callee, call_line in call_sites:
            if callee in visited or callee not in self._func_params:
                continue
            callee_params = self._func_params[callee]
            callee_body = self._get_func_body(body, callee)
            if not callee_body:
                continue
            arg_exprs = self._extract_call_args(call_line, callee_params)
            if parent_arg_exprs:
                expanded = {}
                for p, (coefs, const) in arg_exprs.items():
                    new_coefs, new_const = _expand_vars(coefs, const, parent_arg_exprs)
                    expanded[p] = (new_coefs, new_const)
                arg_exprs = expanded
            child_ctx = parent_ctx.extend(f"{callee}@{call_line[:20]}")
            child_snap = self._forward_scan_with_args(
                callee_body, child_ctx, callee_params, arg_exprs)
            if callee not in self._snapshots:
                self._snapshots[callee] = []
            if len(self._snapshots[callee]) < self._max_contexts:
                self._snapshots[callee].append(child_snap)
            self._propagate_to_callees(
                callee_body, child_ctx, callee,
                visited | {callee}, arg_exprs)

    def _forward_scan(
        self, body: str, ctx: CallContext, params: List[str],
    ) -> AffineSnapshot:
        """前向扫描函数体, 构建仿射快照."""
        snapshot = AffineSnapshot(ctx=ctx)
        for p in params:
            snapshot.var_relations[p] = ({p: 1.0}, 0.0)
        lines = [l.strip() for l in body.split('\n') if l.strip()]
        for line in lines:
            process_line(line, snapshot, ctx.key())
        return snapshot

    def _forward_scan_with_args(
        self, body: str, ctx: CallContext, params: List[str],
        arg_exprs: Dict[str, Tuple[Dict[str, float], float]],
    ) -> AffineSnapshot:
        """带参数绑定的前向扫描(上下文敏感)."""
        snapshot = AffineSnapshot(ctx=ctx)
        for p in params:
            if p in arg_exprs:
                snapshot.var_relations[p] = arg_exprs[p]
            else:
                snapshot.var_relations[p] = ({p: 1.0}, 0.0)
        lines = [l.strip() for l in body.split('\n') if l.strip()]
        for line in lines:
            process_line(line, snapshot, ctx.key())
        return snapshot

    def _find_call_sites(self, body: str) -> List[Tuple[str, str]]:
        """查找函数体中的调用点."""
        sites = []
        for line in body.split('\n'):
            line = line.strip()
            if line.startswith('#') or line.startswith('//'):
                continue
            for m in re.finditer(r'(\w+)\s*\(', line):
                name = m.group(1)
                if name not in ('if', 'for', 'while', 'switch', 'sizeof', 'return'):
                    sites.append((name, line))
        return sites

    def _extract_call_args(
        self, call_line: str, callee_params: List[str],
    ) -> Dict[str, Tuple[Dict[str, float], float]]:
        """从调用行提取参数的仿射表达式."""
        m = re.search(r'(\w+)\s*\(([^)]*)\)', call_line)
        if not m:
            return {}
        args_str = m.group(2)
        args = _split_args(args_str)
        result = {}
        for i, p in enumerate(callee_params):
            if i < len(args):
                arg = args[i].strip()
                coefs, const = _parse_size_expr(arg)
                result[p] = (coefs, const)
        return result

    def _get_func_body(self, parent_body: str, func_name: str) -> Optional[str]:
        """返回之前解析存储的函数体."""
        return self._func_bodies.get(func_name)


__all__ = ['CAAWPInterpreter', '_parse_size_expr']  # 类名保持不变
