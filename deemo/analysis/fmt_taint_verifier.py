"""
格式串污点传播验证器 (FTV). 5-phase: sink识别→污点源→安全化→变量图→跨函数形参绑定.
"""
from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Optional, Tuple

from analysis.fmt_taint_types import (
    FmtVerdict, FmtSink, FmtCallSite, SanitizerSite, TaintPath, FtvResult)


class FmtTaintVerifier:
    """格式串深度验证 — 污点传播 + 安全化检测 + 跨函数分析."""

    _FMT_ARG: Dict[str, int] = {
        'printf':0,'vprintf':0,'fprintf':1,'vfprintf':1,
        'sprintf':1,'vsprintf':1,'snprintf':2,'vsnprintf':2,
        'dprintf':1,'syslog':1,'err':1,'warn':1,'errx':1,'warnx':1}
    _SINK_RE = re.compile(
        r'\b(printf|fprintf|sprintf|snprintf|dprintf|syslog'
        r'|vprintf|vfprintf|vsprintf|vsnprintf|err|warn|errx|warnx)\s*\(',
        re.IGNORECASE)
    _TAINT_SRC_RE = re.compile(
        r'\b(fgets|gets|scanf|fscanf|sscanf|recv|recvfrom'
        r'|read|getenv|fread)\s*\(', re.IGNORECASE)
    _ARGV_RE = re.compile(r'argv\s*\[\s*\d+\s*\]')
    _SANITIZE_RE = re.compile(
        r'(snprintf|sprintf)\s*\(\s*(\w[\w]*)\s*,[^,]*,\s*"([^"]*)"')
    _FUNC_DEF_RE = re.compile(
        r'(?:void|int|char|long|short|float|double'
        r'|unsigned|signed|static|const|inline)\s+'
        r'(?:\w+\s*\*?\s+)?(\w[\w]*)\s*\(\s*([^)]*)\s*\)\s*\{?')
    _NON_VAR = frozenset({
        'if','else','while','for','do','switch','case','default',
        'goto','return','break','continue','sizeof','typedef',
        'struct','enum','union','static','const','volatile',
        'void','int','char','long','short','float','double',
        'unsigned','signed','size_t','ssize_t','NULL','nullptr',
        'free','malloc','calloc','realloc','strlen','strcmp',
        'strncmp','memcmp','memcpy','memset','strcpy','strncpy',
        'strcat','strncat','printf','fprintf','sprintf','snprintf',
        'dprintf','syslog','fgets','gets','scanf','fscanf',
        'getenv','fread','recv','recvfrom','read','exit',
        'main','include','stdin','stdout','stderr','LOG_ERR'})

    def verify(self, source: str) -> List[FtvResult]:
        lines = source.splitlines()
        sinks = self._find_sinks(lines)
        if not sinks:
            return []
        src = self._find_taint_sources(lines)
        san = self._find_sanitizers(lines)
        vg = self._build_var_graph(lines)
        fd = self._build_func_def_map(lines)
        return [self._analyze_sink(s, lines, src, san, vg, fd) for s in sinks]

    @staticmethod
    def _r(sink: FmtCallSite, verdict, **kw) -> FtvResult:
        return FtvResult(verdict=verdict, sink_line=sink.line,
                         sink_func=sink.sink.value, fmt_arg=sink.fmt_arg, **kw)

    # Sink识别

    @staticmethod
    def _extract_nth_arg(text: str, n: int) -> str:
        p = text.find('(')
        if p < 0: return ''
        s = text[p+1:]; depth = 0; a0 = 0; ai = 0
        for idx, ch in enumerate(s):
            if ch == '(': depth += 1
            elif ch == ')':
                if depth == 0: return s[a0:idx].strip() if ai == n else ''
                depth -= 1
            elif ch == ',' and depth == 0:
                if ai == n: return s[a0:idx].strip()
                ai += 1; a0 = idx + 1
        return ''

    _SINK_MAP = {n.value: getattr(FmtSink, n.name) for n in FmtSink}

    def _find_sinks(self, lines: List[str]) -> List[FmtCallSite]:
        sinks = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            sm = self._SINK_RE.search(text)
            if not sm: continue
            fn = sm.group(1).lower()
            st = self._SINK_MAP.get(fn)
            if st is None: continue
            fa = self._extract_nth_arg(text, self._FMT_ARG.get(fn, 0))
            if not fa: continue
            sinks.append(FmtCallSite(
                line=i, sink=st, fmt_arg=fa,
                fmt_arg_var=_extract_var(fa),
                is_constant=_is_str_lit(fa), constant_text=_str_lit(fa)))
        return sinks

    # 污点源识别

    def _find_taint_sources(self,
                            lines: List[str]) -> List[Tuple[int, str, str]]:
        srcs: List[Tuple[int, str, str]] = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            if self._ARGV_RE.search(text):
                am = re.search(r'(\w[\w]*)\s*=\s*argv\s*\[\s*\d+\s*\]', text)
                srcs.append((i, 'argv', am.group(1) if am else 'argv'))
            tm = self._TAINT_SRC_RE.search(text)
            if tm:
                func = tm.group(1).lower()
                am = re.search(r'(\w[\w]*)\s*=\s*'+re.escape(func), text)
                if am:
                    srcs.append((i, func, am.group(1)))
                else:
                    cm = re.search(rf'{re.escape(func)}\s*\(\s*(\w[\w]*)', text)
                    if cm: srcs.append((i, func, cm.group(1)))
            # 启发式: 含recv/read/fetch的非sink函数, 第2参数为数据目标
            if not self._SINK_RE.search(text):
                w = re.findall(r'\b([a-z_]*recv[a-z_]*|[a-z_]*read[a-z_]*'
                               r'|[a-z_]*fetch[a-z_]*)\b', text, re.IGNORECASE)
                if w:
                    cm = re.search(r'(\w[\w]*)\s*\(\s*[^,)]+\s*,\s*(\w[\w]*)', text)
                    if cm and cm.group(1).lower() not in self._NON_VAR:
                        srcs.append((i, cm.group(1).lower(), cm.group(2)))
        return srcs

    # 安全化检测

    def _find_sanitizers(self, lines: List[str]) -> List[SanitizerSite]:
        sans = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            sm = self._SANITIZE_RE.search(text)
            if sm:
                sans.append(SanitizerSite(
                    line=i, func=sm.group(1), output_var=sm.group(2),
                    fmt_is_constant=True, constant_fmt=sm.group(3)))
        return sans

    # 变量图 + 函数定义映射

    def _build_var_graph(self,
                         lines: List[str]) -> Dict[str, List[Tuple[int, str]]]:
        g: Dict[str, List[Tuple[int, str]]] = {}
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//','if','while','for','return')): continue
            am = re.search(r'(\w[\w]*)\s*=\s*([^;]+);', text)
            if am and am.group(1) not in self._NON_VAR:
                g.setdefault(am.group(1), []).append((i, am.group(2).strip()))
        return g

    def _build_func_def_map(self,
                            lines: List[str]) -> Dict[str, Tuple[int, List[str]]]:
        fmap: Dict[str, Tuple[int, List[str]]] = {}
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith('//'): continue
            fm = self._FUNC_DEF_RE.search(text)
            if not fm or fm.group(1) in self._NON_VAR: continue
            ps = fm.group(2); params = []
            if ps.strip() and ps.strip() != 'void':
                for p in ps.split(','):
                    pm = re.search(r'(\w[\w]*)\s*$', p.strip())
                    if pm: params.append(pm.group(1))
            fmap[fm.group(1)] = (i, params)
        return fmap

    def _find_enclosing(self, line_no: int,
                        fd: Dict[str, Tuple[int, List[str]]]
                        ) -> Optional[Tuple[str, int, List[str]]]:
        best = None
        for fn, (dl, params) in fd.items():
            if dl < line_no and (best is None or dl > best[1]):
                best = (fn, dl, params)
        return best

    # sink分析

    def _analyze_sink(self, sink: FmtCallSite, lines: List[str],
                      srcs: List[Tuple[int, str, str]],
                      sans: List[SanitizerSite],
                      vg: Dict[str, List[Tuple[int, str]]],
                      fd: Dict[str, Tuple[int, List[str]]]) -> FtvResult:
        if sink.is_constant:
            return self._r(sink, FmtVerdict.SAFE,
                           reason=f'fmt constant: "{sink.constant_text[:40]}"')
        fv = sink.fmt_arg_var
        if not fv:
            return self._r(sink, FmtVerdict.UNCERTAIN,
                           reason='cannot extract var from fmt arg')
        # 安全化
        for san in sans:
            if san.output_var == fv:
                return self._r(sink, FmtVerdict.SAFE,
                    sanitized_by=f'{san.func}@{san.line}',
                    reason=f"'{fv}'={san.func} output, "
                           f'fixed fmt "{san.constant_fmt[:40]}"')
        # BFS污点追踪
        paths = self._trace_taint(fv, sink.line, srcs, vg)
        if paths:
            return self._r(sink, FmtVerdict.VULN, taint_paths=paths,
                reason=f"'{fv}' tainted: {len(paths)} path(s) "
                       f'from {paths[0].source}@{paths[0].source_line}')
        # 直接污点匹配
        for sl, src, tv in srcs:
            if tv == fv and sl < sink.line:
                tp = TaintPath(source=src, source_line=sl,
                    sink=sink.sink.value, sink_line=sink.line,
                    var_chain=[tv, fv])
                return self._r(sink, FmtVerdict.VULN, taint_paths=[tp],
                    reason=f"'{fv}' directly tainted by {src}@{sl}")
        # 跨函数形参绑定
        enc = self._find_enclosing(sink.line, fd)
        if enc:
            fn, _, params = enc
            pidx = next((idx for idx, p in enumerate(params) if p == fv), -1)
            if pidx >= 0:
                for i, line in enumerate(lines, start=1):
                    text = line.strip()
                    if text.startswith('//'): continue
                    if not re.search(rf'\b{re.escape(fn)}\s*\(', text): continue
                    av = _extract_var(self._extract_nth_arg(text, pidx))
                    if not av: continue
                    for sl, src, tv in srcs:
                        if tv == av and sl < i:
                            tp = TaintPath(source=src, source_line=sl,
                                sink=sink.sink.value, sink_line=sink.line,
                                var_chain=[tv, av, fv])
                            return self._r(sink, FmtVerdict.VULN,
                                taint_paths=[tp],
                                reason=f"'{fv}'=#{pidx} of '{fn}', "
                                       f"'{av}' tainted by {src}@{sl}")
                    ap = self._trace_taint(av, i, srcs, vg)
                    if ap:
                        return self._r(sink, FmtVerdict.VULN, taint_paths=ap,
                            reason=f"'{fv}'=param of '{fn}', "
                                   f"'{av}' is tainted")
        return self._r(sink, FmtVerdict.UNCERTAIN,
                       reason=f"cannot determine taint for '{fv}'")

    # BFS污点传播

    def _trace_taint(self, target: str, tline: int,
                     srcs: List[Tuple[int, str, str]],
                     vg: Dict[str, List[Tuple[int, str]]]) -> List[TaintPath]:
        paths: List[TaintPath] = []
        q: deque = deque([(target, [target], {target})])
        while q and len(paths) < 10:
            cur, chain, vis = q.popleft()
            for sl, src, tv in srcs:
                if tv == cur and sl < tline:
                    paths.append(TaintPath(
                        source=src, source_line=sl,
                        sink='(target)', sink_line=tline,
                        var_chain=list(reversed(chain)))); break
            if cur not in vg: continue
            for al, rhs in vg[cur]:
                if al >= tline: continue
                for rv in re.findall(r'\b([a-z_]\w*)\b', rhs):
                    if rv not in self._NON_VAR and rv != cur and rv not in vis:
                        q.append((rv, chain + [rv], vis | {rv}))
        return paths


# 模块级辅助

def _extract_var(expr: str) -> str:
    m = re.match(r'(\w[\w]*)', re.sub(r'\([^)]*\)\s*', '', expr.strip()))
    return m.group(1) if m else ''

def _is_str_lit(expr: str) -> bool:
    e = expr.strip()
    return (e.startswith('"') and e.endswith('"')) or \
           (e.startswith("'") and e.endswith("'"))

def _str_lit(expr: str) -> str:
    e = expr.strip()
    return e[1:-1] if len(e) >= 2 and e[0] == e[-1] and e[0] in ('"',"'") else ''
