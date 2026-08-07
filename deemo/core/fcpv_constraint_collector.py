"""
FCPV 约束收集器 — 从 C 源码提取四类约束.

收集策略:
  1. Sink 约束: 扫描 printf 族调用, 提取第 N 参数性质
  2. Taint 约束: 构建变量定义图, BFS 追踪外部输入可达性
  3. Sanitize 约束: 识别 snprintf(dst, sz, "%s", src) 安全化模式
  4. Cross-func 约束: 匹配函数定义 + 调用点, 绑定形参→实参

辅助函数和常量已提取到 fcpv_collector_helpers.py.
"""

import re
from collections import deque
from typing import Dict, List, Set, Tuple

from core.fcpv_constraint_types import (
    ConstraintKind, CrossFuncConstraint, FcpvCandidate, FcpvConstraint,
    SanitizeConstraint, SinkConstraint, SinkType, TaintConstraint,
    TaintState,
)
from core.fcpv_collector_helpers import (
    _FMT_ARG_INDEX, _SINK_RE, _SANITIZE_RE, _FUNC_DEF_RE, _NON_VAR,
    _ARGV_RE, _extract_nth_arg_from_call,
    _is_str_literal, _str_literal, _extract_var,
    find_taint_sources_impl,
)


class FcpvConstraintCollector:
    """从 C 源码收集四类 FCPV 约束."""

    def __init__(self):
        self._lines: List[str] = []
        self._taint_sources: List[Tuple[int, str, str]] = []
        self._var_graph: Dict[str, List[Tuple[int, str]]] = {}
        self._func_defs: Dict[str, Tuple[int, List[str]]] = {}
        self._sanitizers: List[Tuple[int, str, str, str]] = []
        self._tainted_set: Set[str] = set()
        self._taint_paths: Dict[str, List[str]] = {}

    def collect(self, source: str) -> List[FcpvCandidate]:
        """主入口: 收集所有约束, 返回候选列表."""
        self._lines = source.splitlines()
        self._find_taint_sources()
        self._build_var_graph()
        self._run_taint_fixpoint()
        self._find_func_defs()
        self._find_sanitizers()
        self._propagate_through_sanitizers()
        sinks = self._find_sinks()
        candidates = []
        for sink in sinks:
            c = FcpvCandidate(sink=sink)
            fv = sink.fmt_arg
            if fv:
                c.taints = self._collect_taints(fv, sink.line)
                c.sanitizers = self._collect_sanitizers(fv)
                c.cross_funcs = self._collect_cross_funcs(fv, sink.line)
                c.var_chain = self._get_var_chain(fv, sink.line)
            candidates.append(c)
        return candidates

    def _find_taint_sources(self):
        """收集污点源 (委托给 helpers 模块)."""
        self._taint_sources = find_taint_sources_impl(
            self._lines, self._tainted_set)
        for _, _, tv in self._taint_sources:
            if tv not in self._tainted_set:
                self._tainted_set.add(tv)
                self._taint_paths[tv] = [tv]

    def _find_sinks(self) -> List[SinkConstraint]:
        """收集 Sink 约束."""
        sinks = []
        for i, line in enumerate(self._lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')):
                continue
            for m in _SINK_RE.finditer(text):
                fn = m.group(1).lower()
                arg_idx = _FMT_ARG_INDEX.get(fn, 0)
                arg = _extract_nth_arg_from_call(text, fn, arg_idx)
                if not arg:
                    continue
                sc = SinkConstraint(
                    line=i, func=fn, sink_func=fn, fmt_arg=arg,
                    arg_index=arg_idx, var=_extract_var(arg))
                if _is_str_literal(arg):
                    sc.sink_type = SinkType.CONSTANT
                    sc.constant_text = _str_literal(arg)
                else:
                    sc.sink_type = SinkType.VARIABLE
                sinks.append(sc)
        return sinks

    def _build_var_graph(self):
        """构建变量赋值图."""
        for i, line in enumerate(self._lines, start=1):
            text = line.strip()
            if text.startswith(('//', 'if', 'while', 'for', 'return')):
                continue
            am = re.search(r'(\w[\w]*)\s*=\s*([^;]+);', text)
            if am and am.group(1) not in _NON_VAR:
                self._var_graph.setdefault(
                    am.group(1), []).append((i, am.group(2).strip()))

    def _run_taint_fixpoint(self):
        """Worklist 定点污点传播."""
        q: deque = deque()
        for sl, src, tv in self._taint_sources:
            if tv not in self._tainted_set:
                self._tainted_set.add(tv)
                self._taint_paths[tv] = [tv]
                q.append(tv)
        while q:
            var = q.popleft()
            for ov, defs in self._var_graph.items():
                if ov in self._tainted_set:
                    continue
                for al, rhs in defs:
                    if re.search(rf'\b{re.escape(var)}\b', rhs):
                        self._tainted_set.add(ov)
                        self._taint_paths[ov] = self._taint_paths.get(
                            var, [var]) + [ov]
                        q.append(ov)
                        break

    def _find_func_defs(self):
        """收集函数定义."""
        for i, line in enumerate(self._lines, start=1):
            text = line.strip()
            if text.startswith('//'):
                continue
            fm = _FUNC_DEF_RE.search(text)
            if not fm or fm.group(1) in _NON_VAR:
                continue
            ps = fm.group(2)
            params = []
            if ps.strip() and ps.strip() != 'void':
                for p in ps.split(','):
                    pm = re.search(r'(\w[\w]*)\s*$', p.strip())
                    if pm:
                        params.append(pm.group(1))
            self._func_defs[fm.group(1)] = (i, params)

    def _find_sanitizers(self):
        """收集安全化约束."""
        for i, line in enumerate(self._lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')):
                continue
            sm = _SANITIZE_RE.search(text)
            if not sm:
                continue
            func = sm.group(1).lower()
            dst = sm.group(2)
            fmt_arg_idx = 2 if func == 'snprintf' else 1
            fmt_text = _extract_nth_arg_from_call(text, func, fmt_arg_idx)
            if _is_str_literal(fmt_text):
                self._sanitizers.append(
                    (i, func, dst, _str_literal(fmt_text)))
                # %s 透传模式: snprintf(dst, sz, "...%s...", src) → dst 携带用户输入
                fmt_content = _str_literal(fmt_text)
                if re.search(r'%[-+0 #]*\d*(?:\.\d+)?s', fmt_content):
                    src_idx = fmt_arg_idx + 1
                    src_arg = _extract_nth_arg_from_call(text, func, src_idx)
                    src_var = _extract_var(src_arg) if src_arg else ''
                    if src_var and (src_var in self._tainted_set or
                                    src_var.startswith('argv') or
                                    'argv' in src_arg):
                        self._tainted_set.add(dst)
                        self._taint_paths[dst] = self._taint_paths.get(
                            src_var, [src_var]) + [dst]

    def _propagate_through_sanitizers(self):
        """snprintf "%s" 透传引入的新污点变量需通过 var_graph 继续传播."""
        q: deque = deque(self._tainted_set)
        while q:
            var = q.popleft()
            for ov, defs in self._var_graph.items():
                if ov in self._tainted_set:
                    continue
                for al, rhs in defs:
                    if re.search(rf'\b{re.escape(var)}\b', rhs):
                        self._tainted_set.add(ov)
                        self._taint_paths[ov] = self._taint_paths.get(
                            var, [var]) + [ov]
                        q.append(ov)
                        break

    def _collect_taints(self, var: str, sink_line: int) -> List[TaintConstraint]:
        """收集变量的 taint 约束.

        允许 sl <= sink_line (同一行可同时出现 source 和 sink).
        """
        result = []
        if var in self._tainted_set:
            chain = self._taint_paths.get(var, [var])
            for sl, src, tv in self._taint_sources:
                if tv == var and sl <= sink_line:
                    result.append(TaintConstraint(
                        line=sink_line, var=var, source=src,
                        source_line=sl, var_chain=chain))
                    break
            if not result:
                for sl, src, tv in self._taint_sources:
                    if tv in chain and sl <= sink_line:
                        result.append(TaintConstraint(
                            line=sink_line, var=var, source=src,
                            source_line=sl, var_chain=chain))
                        break
        return result

    def _collect_sanitizers(self, var: str) -> List[SanitizeConstraint]:
        """收集变量的 sanitize 约束."""
        result = []
        for sl, func, dst, fmt in self._sanitizers:
            if dst == var:
                result.append(SanitizeConstraint(
                    line=sl, var=var, sanitizer=func,
                    constant_fmt=fmt, sanitizer_line=sl))
        return result

    def _collect_cross_funcs(self, var: str, sink_line: int) -> List[CrossFuncConstraint]:
        """收集跨函数约束.

        搜索全部行, 调用点在 sink 之前或之后都应传播.
        """
        result = []
        func_def_lines = {dl for _, (dl, _) in self._func_defs.items()}
        for fn, (dl, params) in self._func_defs.items():
            pidx = next((i for i, p in enumerate(params) if p == var), -1)
            if pidx < 0:
                continue
            for i, line in enumerate(self._lines, start=1):
                if i == dl or i in func_def_lines:
                    continue
                text = line.strip()
                if text.startswith('//'):
                    continue
                if not re.search(rf'\b{re.escape(fn)}\s*\(', text):
                    continue
                caller_arg = _extract_var(
                    _extract_nth_arg_from_call(text, fn, pidx))
                if not caller_arg or caller_arg in _NON_VAR:
                    continue
                result.append(CrossFuncConstraint(
                    line=i, var=var, callee=fn, param_index=pidx,
                    caller_arg=caller_arg, caller_line=i))
        return result

    def _get_var_chain(self, var: str, sink_line: int) -> List[str]:
        """获取变量到污点源的传播链."""
        if var in self._tainted_set:
            return self._taint_paths.get(var, [var])
        for cf in self._collect_cross_funcs(var, sink_line):
            if cf.caller_arg in self._tainted_set:
                return self._taint_paths.get(
                    cf.caller_arg, [cf.caller_arg]) + [var]
        return [var]

    @property
    def tainted_set(self) -> Set[str]:
        return self._tainted_set


__all__ = ['FcpvConstraintCollector']
