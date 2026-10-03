"""UAF跨过程摘要分析 — 函数边界free传播 + 返回值别名追踪 ≤300行."""

from __future__ import annotations
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

@dataclass
class FuncSummary:
    """函数摘要: 参数free副作用 + 返回值污染状态 + 回调转发."""
    name: str
    params: List[str]
    freed_params: Set[int]     # 被free的形参索引
    nullified_params: Set[int] # 被置NULL的形参索引
    returns_from_global: bool  # 返回值来自全局容器
    global_var: str = ""
    body_start: int = 0
    body_end: int = 0
    callback_calls: Dict[int, List[int]] = field(default_factory=dict)
    stores_to_global: Dict[int, str] = field(default_factory=dict)
    cb_lines: Dict[int, int] = field(default_factory=dict)


class InterprocSummarizer:
    """跨过程摘要分析: parse→build→propagate 三步法."""

    _FUNC_DEF_RE = re.compile(
        r'(?:static\s+)?(?:inline\s+)?(?:struct\s+)?'
        r'\w+(?:\s*\*)*\s*\*?\s*'  # return type
        r'(\w+)\s*\(([^)]*)\)\s*\{', re.IGNORECASE)
    _FREE_RE = re.compile(
        r'free\s*\(\s*(\*?\w+(?:->\w+)*)\s*\)', re.IGNORECASE)
    _RETURN_RE = re.compile(r'return\s+(\w[\w]*(?:->\w+)*)\s*;')
    _CALL_RE = re.compile(
        r'(?:(\w[\w]*)\s*=\s*)?(\w+)\s*\(([^)]*)\)', re.IGNORECASE)
    _FP_ASSIGN_RE = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;')

    def __init__(self) -> None:
        self._summaries: Dict[str, FuncSummary] = {}

    def parse_functions(self, source: str) -> Dict[str, FuncSummary]:
        """解析源文件中所有函数定义."""
        lines = source.splitlines()
        summaries: Dict[str, FuncSummary] = {}
        stack: List[Tuple[str, List[str], int]] = []
        depth = 0
        for i, line in enumerate(lines):
            if not stack:
                m = self._FUNC_DEF_RE.search(line)
                if m:
                    name, ps = m.group(1), m.group(2)
                    if name in ('if', 'while', 'for', 'switch', 'return',
                                'sizeof', 'else', 'do', 'goto', 'case'):
                        continue
                    params = self._parse_params(ps)
                    depth = line.count('{') - line.count('}')
                    if depth <= 0:
                        summaries[name] = FuncSummary(
                            name=name, params=params, freed_params=set(),
                            nullified_params=set(), returns_from_global=False,
                            body_start=i, body_end=i)
                    else:
                        stack.append((name, params, i))
                continue
            if stack:
                depth += line.count('{') - line.count('}')
                if depth <= 0:
                    name, params, start = stack.pop()
                    summaries[name] = FuncSummary(
                        name=name, params=params, freed_params=set(),
                        nullified_params=set(), returns_from_global=False,
                        body_start=start, body_end=i)
        self._summaries = summaries
        return summaries

    @staticmethod
    def _parse_params(params_str: str) -> List[str]:
        """从形参字符串提取变量名列表."""
        KW = {'void', 'int', 'char', 'float', 'double', 'long', 'short',
              'size_t', 'struct', 'unsigned', 'signed', 'const', 'static'}
        result = []
        if not params_str.strip():
            return result
        for part in params_str.split(','):
            part = part.strip()
            if not part:
                continue
            toks = re.findall(r'\*+|\w+', part)
            names = [t for t in toks if t not in KW and t != '*'
                     and not all(c == '*' for c in t)]
            if names:
                result.append(names[-1])
        return result

    def build_summaries(self, source: str) -> Dict[str, FuncSummary]:
        """扫描函数体 检测free(param)和全局返回值."""
        if not self._summaries:
            self.parse_functions(source)
        lines = source.splitlines()
        for name, summary in self._summaries.items():
            body = '\n'.join(lines[summary.body_start:summary.body_end + 1])
            # free(param)
            for m in self._FREE_RE.finditer(body):
                fv = m.group(1)
                for idx, pname in enumerate(summary.params):
                    if fv == pname or fv == '*' + pname or fv.endswith('->' + pname):
                        summary.freed_params.add(idx)
# param=NULL
            for m in re.finditer(
                    r'\*\s*(\w[\w]*)\s*=\s*(?:NULL|0|nullptr|nil)\s*;',
                    body, re.IGNORECASE):
                nv = m.group(1)
                for idx, pname in enumerate(summary.params):
                    if nv == pname:
                        summary.nullified_params.add(idx)
            # global = param
            for idx, pname in enumerate(summary.params):
                gpat = re.compile(
                    rf'(g_\w+|[A-Z_]+\w*)\s*=\s*{re.escape(pname)}\s*;')
                for gm in gpat.finditer(body):
                    summary.stores_to_global[idx] = gm.group(1)
            # 回调转发: param_j(param_i)
            for j, pj in enumerate(summary.params):
                cb_re = re.compile(rf'\b{re.escape(pj)}\s*\(([^)]*)\)')
                for cm in cb_re.finditer(body):
                    cargs = cm.group(1)
                    lo = body[:cm.start()].count('\n')
                    for i, pi in enumerate(summary.params):
                        if i != j and re.search(rf'\b{re.escape(pi)}\b', cargs):
                            summary.callback_calls.setdefault(j, []).append(i)
                            summary.cb_lines[j] = lo
            # return expr — 返回值是否来自全局容器
            for rv in self._RETURN_RE.findall(body):
                base = rv.split('->')[0].lstrip('*')
                if self._is_from_global(body, base):
                    summary.returns_from_global = True
                    summary.global_var = self._find_global_source(body, base)
        return self._summaries

    def _is_from_global(self, body, var):
        """检查变量是否迭代自全局/静态容器."""
        gpat = re.compile(
            rf'{re.escape(var)}\s*=\s*(g_\w+|s_\w+|[A-Z_]+\w*)\s*;')
        next_pat = re.compile(
            rf'{re.escape(var)}\s*=\s*{re.escape(var)}\s*->\s*next\s*;')
        return bool(gpat.search(body) and next_pat.search(body))

    def _find_global_source(self, body, var):
        """找到var迭代的全局变量名."""
        m = re.search(
            rf'{re.escape(var)}\s*=\s*(g_\w+|s_\w+|[A-Z_]+\w*)\s*;', body)
        return m.group(1) if m else ""

    def propagate(self, source):
        """在调用点注入虚拟free和别名. 返回 (virtual_frees, virtual_aliases)."""
        if not self._summaries:
            self.parse_functions(source)
            self.build_summaries(source)
        lines = source.splitlines()
        vfrees, valiases = [], []
        fp_aliases = self._resolve_func_ptr_aliases(lines)
        for i, line in enumerate(lines, start=1):
            for m in self._CALL_RE.finditer(line):
                ret_var, func_name, args_str = m.group(1), m.group(2), m.group(3)
                resolved_name = fp_aliases.get(func_name, func_name)
                summary = self._summaries.get(resolved_name)
                if not summary or resolved_name == 'main':
                    continue
                if line[m.end():].strip().startswith('{'):
                    continue
                args = self._parse_args(args_str)
                as_start = m.start(3)
                # freed_params→实参FREED (nullified除外)
                for pidx in (summary.freed_params - summary.nullified_params):
                    if pidx < len(args):
                        vname = self._extract_var(args[pidx])
                        if vname:
                            col = as_start + args_str.find(args[pidx])
                            vfrees.append((i, max(col, 0), vname))
                # stores_to_global→实参别名到全局容器
                for pidx, gvar in summary.stores_to_global.items():
                    if pidx < len(args):
                        vname = self._extract_var(args[pidx])
                        if vname:
                            valiases.append((i, vname, gvar,
                                f"存入全局: {func_name}({vname})->{gvar}"))
                # returns_from_global→返回值可能已释放
                if ret_var and summary.returns_from_global:
                    valiases.append((i, ret_var, summary.global_var,
                        f"跨函数返回: {func_name}()->{summary.global_var}"))
                # callback转发
                for cb_idx, data_indices in summary.callback_calls.items():
                    if cb_idx >= len(args):
                        continue
                    cb_name = self._extract_var(args[cb_idx])
                    cb_summ = self._summaries.get(cb_name)
                    if not cb_summ:
                        continue
                    cb_lo = summary.cb_lines.get(cb_idx, -1)
                    for data_idx in data_indices:
                        if data_idx >= len(args):
                            continue
                        for fp_idx in cb_summ.freed_params:
                            if fp_idx < len(data_indices):
                                tgt_idx = data_indices[fp_idx]
                                if tgt_idx >= len(args):
                                    continue
                                if cb_lo >= 0 and tgt_idx < len(summary.params):
                                    lname = summary.params[tgt_idx]
                                    bl = lines[summary.body_start + cb_lo]
                                    c2 = re.search(
                                        rf'\b{re.escape(summary.params[cb_idx])}'
                                        rf'\s*\(\s*{re.escape(lname)}\s*\)', bl)
                                    col = c2.start()+c2.group().find(lname) if c2 else 0
                                    vfrees.append((summary.body_start + cb_lo + 1, col, lname))
                                else:
                                    vname = self._extract_var(args[tgt_idx])
                                    if vname:
                                        col = as_start + args_str.find(args[tgt_idx])
                                        vfrees.append((i, max(col, 0), vname))
        return vfrees, valiases

    def _resolve_func_ptr_aliases(self, lines):
        """提取函数指针别名: typedef_fn var = known_func; → var→known_func."""
        return {m.group(1): m.group(2) for line in lines
                for m in [self._FP_ASSIGN_RE.search(line.strip())] if m
                if m.group(2) in self._summaries and m.group(1) != m.group(2)}

    @staticmethod
    def _parse_args(args_str):
        """解析调用参数 (处理嵌套括号)."""
        args, depth, cur = [], 0, []
        for ch in args_str:
            if ch == '(':
                depth += 1; cur.append(ch)
            elif ch == ')':
                depth -= 1; cur.append(ch)
            elif ch == ',' and depth == 0:
                args.append(''.join(cur).strip()); cur = []
            else:
                cur.append(ch)
        if cur:
            args.append(''.join(cur).strip())
        return args

    @staticmethod
    def _extract_var(arg):
        """从实参提取变量名: &x→x, *p→p, x->f→x."""
        m = re.match(r'[&*]*(\w[\w]*)', arg.strip())
        return m.group(1) if m else ""

    @property
    def summaries(self) -> Dict[str, FuncSummary]:
        return self._summaries


__all__ = ['InterprocSummarizer', 'FuncSummary']
