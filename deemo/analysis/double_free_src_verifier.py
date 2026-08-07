"""
双释放源级验证器 (DFSV). 别名追踪 + 路径分析 + 跨函数检测.
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple, Set
from analysis.double_free_types import (
    DfVerdict, FreeSite, AliasRecord, DfResult)

_FREE_RE = re.compile(r'\bfree\s*\(\s*([^)]+)\s*\)\s*;?')
_ASSIGN_RE = re.compile(r'(\w[\w]*(?:->\w[\w]*)*)\s*=\s*([^;]+);')
_MALLOC_RE = re.compile(r'\b(malloc|calloc|realloc)\s*\(')
_FIELD_ASSIGN_RE = re.compile(r'(\w[\w]*->\w[\w]*)\s*=\s*(\w[\w]*)\s*;')
_MEMCPY_RE = re.compile(r'memcpy\s*\(\s*&(\w[\w]*)\s*,\s*&(\w[\w]*)')
_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed|static|const|inline|size_t)\s+'
    r'(?:\w+\s*\*?\s+)?(\w+)\s*\(\s*([^)]*)\s*\)\s*\{?')
_LOOP_RE = re.compile(r'\b(for|while)\s*\(')
_CALL_RE = re.compile(r'\b\w[\w]*\s*\(')
_NON_VAR = frozenset({
    'if','else','while','for','return','int','char','void','long',
    'short','float','double','size_t','unsigned','signed','static','const',
    'sizeof','NULL','nullptr','malloc','calloc','realloc','free',
    'printf','main','include','struct','typedef','switch',
    'case','default','goto','break','continue','exit'})

class DoubleFreeSrcVerifier:
    """双释放源级验证 — 别名追踪 + 路径分析 + 跨函数检测."""

    def verify(self, source: str) -> List[DfResult]:
        lines = source.splitlines()
        frees = self._find_frees(lines)
        if not frees: return []
        aliases = self._build_aliases(lines)
        fm = self._build_func_map(lines)
        results: List[DfResult] = []
        # 循环内free
        for f in frees:
            if self._in_loop_body(f.line, lines):
                results.append(DfResult(verdict=DfVerdict.VULN, free_line=f.line,
                    var_name=f.var, confidence=0.85,
                    reason=f"'{f.var}' free@L{f.line} inside loop body"))
        # 包装函数多次调用
        wrappers = self._find_free_wrappers(fm, lines)
        for wf in wrappers:
            if self._count_calls(wf, lines) >= 2:
                for f in frees:
                    if self._enclosing(f.line, fm) == wf:
                        results.append(DfResult(verdict=DfVerdict.VULN,
                            free_line=f.line, var_name=f.var, confidence=0.85,
                            reason=f"'{wf}' wraps free('{f.var}') called ≥2x"))
        if len(frees) < 2: return results
        # 配对检测
        for i in range(len(frees)):
            for j in range(i + 1, len(frees)):
                cross = self._enclosing(frees[i].line, fm) != self._enclosing(frees[j].line, fm)
                r = self._check_pair(frees[i], frees[j], lines, aliases, fm, cross)
                if r: results.append(r)
        seen = set(); unique = []
        for r in results:
            key = (r.free_line, r.paired_line, r.var_name)
            if key not in seen: seen.add(key); unique.append(r)
        return unique

    # free点提取

    def _find_frees(self, lines: List[str]) -> List[FreeSite]:
        frees = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            for m in _FREE_RE.finditer(text):
                var = m.group(1).strip(); bv = _base_var(var)
                if bv and bv not in _NON_VAR:
                    frees.append(FreeSite(line=i, var=var, base_var=bv))
        return frees

    # 别名追踪

    def _build_aliases(self, lines: List[str]) -> Dict[str, List[AliasRecord]]:
        aliases: Dict[str, List[AliasRecord]] = {}
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*', 'if', 'while', 'for')): continue
            for mm in _MEMCPY_RE.finditer(text):
                aliases.setdefault(mm.group(1), []).append(
                    AliasRecord(source=mm.group(2), target=mm.group(1), line=i, kind='memcpy'))
            for fm in _FIELD_ASSIGN_RE.finditer(text):
                tgt = fm.group(1)
                if '->' in tgt:
                    aliases.setdefault(tgt, []).append(
                        AliasRecord(source=fm.group(2).strip(), target=tgt, line=i, kind='field'))
            for am in _ASSIGN_RE.finditer(text):
                lhs, rhs = am.group(1).strip(), am.group(2).strip()
                if _MALLOC_RE.search(rhs): continue
                lb, rb = _base_var(lhs), _base_var(rhs)
                if not lb or not rb or lb == rb or lb in _NON_VAR or rb in _NON_VAR: continue
                kind = 'global' if not _is_local_assign(line) else 'assign'
                aliases.setdefault(lb, []).append(
                    AliasRecord(source=rb, target=lb, line=i, kind=kind))
        return aliases

    # 配对判定

    def _check_pair(self, a: FreeSite, b: FreeSite, lines: List[str],
                    aliases: Dict[str, List[AliasRecord]],
                    fm: Dict[str, Tuple[int, int, List[str]]],
                    cross_func: bool = False) -> Optional[DfResult]:
        matched = (a.base_var == b.base_var or
                   self._is_alias(a.base_var, b.base_var, aliases) or
                   self._is_alias(b.base_var, a.base_var, aliases) or
                   self._memcpy_alias(a.base_var, b.base_var, aliases) or
                   cross_func or self._cross_func_match(a, b, lines, fm))
        if matched:
            return self._verify_realloc(a, b, lines,
                                        cross_func or a.base_var == b.base_var)
        if self._dangling_field_free(a, b):
            return DfResult(verdict=DfVerdict.VULN, free_line=b.line,
                var_name=b.var, paired_line=a.line, paired_var=a.var,
                confidence=0.75,
                reason=f"'{b.var}' free@L{b.line} after '{a.var}' freed@L{a.line}")
        return None

    def _verify_realloc(self, a: FreeSite, b: FreeSite, lines: List[str],
                         cross_func: bool = False) -> Optional[DfResult]:
        if cross_func:
            return DfResult(verdict=DfVerdict.VULN, free_line=b.line,
                var_name=b.var, paired_line=a.line, paired_var=a.var,
                confidence=0.80,
                reason=f"'{a.var}' free@L{a.line} and '{b.var}' free@L{b.line} (cross)")
        for i in range(a.line + 1, b.line):
            text = lines[i - 1].strip()
            if text.startswith(('//', '/*')): continue
            if re.search(rf'\b{re.escape(a.base_var)}\s*=\s*(?:malloc|calloc|realloc)\s*\(', text):
                return None
            if re.search(rf'\b{re.escape(a.base_var)}\s*=\s*(?:NULL|nullptr|0)\s*;', text):
                return None
        if self._mutex(a.line, b.line, lines): return None
        return DfResult(verdict=DfVerdict.VULN, free_line=b.line,
            var_name=b.var, paired_line=a.line, paired_var=a.var,
            confidence=0.90,
            reason=f"'{a.var}' free@L{a.line} and '{b.var}' free@L{b.line}")

    # 路径分析

    def _mutex(self, la: int, lb: int, lines: List[str]) -> bool:
        for i in range(min(la, lb), max(la, lb)):
            if re.match(r'\}\s*else\s*\{?', lines[i - 1].strip()):
                return True
        return False

    def _bracedepth(self, line: int, lines: List[str]) -> int:
        d = 0
        for i in range(line):
            t = lines[i]; d += t.count('{') - t.count('}')
        return d

    # 别名解析

    def _is_alias(self, target: str, source: str,
                  aliases: Dict[str, List[AliasRecord]],
                  visited: Optional[Set[str]] = None) -> bool:
        if target == source: return True
        if visited is None: visited = set()
        if target in visited: return False
        visited.add(target)
        for ar in aliases.get(target, []):
            if ar.source == source: return True
            if self._is_alias(ar.source, source, aliases, visited): return True
        return False

    def _memcpy_alias(self, va: str, vb: str,
                       aliases: Dict[str, List[AliasRecord]]) -> bool:
        for ar_list in aliases.values():
            for ar in ar_list:
                if ar.kind != 'memcpy': continue
                for sn in (ar.target, ar.source):
                    other = ar.source if sn == ar.target else ar.target
                    if va.startswith(sn + '.') or va == sn:
                        sfx = _field_suffix(va, sn)
                        if vb == (other + sfx if sfx else other): return True
        return False

    # 跨函数追踪

    def _build_func_map(self, lines: List[str]) -> Dict[str, Tuple[int, int, List[str]]]:
        fmap: Dict[str, Tuple[int, int, List[str]]] = {}
        full = '\n'.join(lines)
        for m in _FUNC_DEF_RE.finditer(full):
            name = m.group(1)
            if name in _NON_VAR: continue
            start = full[:m.start()].count('\n') + 1
            ps = m.group(2); params = []
            if ps.strip() and ps.strip() != 'void':
                for p in ps.split(','):
                    pm = re.search(r'(\w[\w]*)\s*$', p.strip())
                    if pm: params.append(pm.group(1))
            if '{' in lines[start-1] and '}' in lines[start-1]:
                fmap[name] = (start, start, params); continue
            depth = 0; end = start
            for j in range(start, len(lines) + 1):
                depth += lines[j-1].count('{') - lines[j-1].count('}')
                if depth <= 0 and j > start: end = j; break
            fmap[name] = (start, end if end else len(lines), params)
        return fmap

    def _cross_func_match(self, a: FreeSite, b: FreeSite, lines: List[str],
                          fm: Dict[str, Tuple[int, int, List[str]]]) -> bool:
        fa = self._enclosing(a.line, fm); fb = self._enclosing(b.line, fm)
        if fa == fb and fa is not None: return False
        if a.base_var == b.base_var and self._is_global(a.base_var, fm, lines):
            return True
        for _, (start, end, _) in fm.items():
            for i in range(start, min(end + 1, len(lines) + 1)):
                text = lines[i - 1].strip()
                if text.startswith('//'): continue
                for gm in re.finditer(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;', text):
                    gv, lv = gm.group(1), gm.group(2)
                    if gv in _NON_VAR or lv in _NON_VAR: continue
                    if not self._is_global(gv, fm, lines): continue
                    if (lv == a.base_var and gv == b.base_var) or \
                       (lv == b.base_var and gv == a.base_var): return True
        return False

    def _is_global(self, var: str, fm: Dict[str, Tuple[int, int, List[str]]],
                    lines: List[str]) -> bool:
        for _, (_, _, params) in fm.items():
            if var in params: return False
        for _, (s, e, _) in fm.items():
            for i in range(s, min(e + 1, len(lines) + 1)):
                if re.search(rf'\b(?:char|int|void|long|short|float|double)\s*\*?\s*{re.escape(var)}\s*[=;]',
                             lines[i - 1].strip()): return False
        return True

    def _find_free_wrappers(self, fm: Dict[str, Tuple[int, int, List[str]]],
                             lines: List[str]) -> Set[str]:
        wrappers = set()
        for name, (s, e, _) in fm.items():
            hf = False; oc = False
            for i in range(s, min(e + 1, len(lines) + 1)):
                text = lines[i - 1].strip()
                if text.startswith('//'): continue
                if _FREE_RE.search(text): hf = True
                elif _CALL_RE.search(text) and not re.search(r'\b(?:if|while|for|return)\b', text):
                    oc = True
            if hf and not oc: wrappers.add(name)
        return wrappers

    def _count_calls(self, fn: str, lines: List[str]) -> int:
        return sum(len(re.findall(rf'\b{re.escape(fn)}\s*\(', l))
                   for l in lines if not l.strip().startswith('//'))

    # 循环检测

    def _in_loop_body(self, line: int, lines: List[str]) -> bool:
        text = lines[line - 1].strip()
        fm = _LOOP_RE.search(text)
        if fm and _FREE_RE.search(text[fm.end():]): return True
        for i in range(line - 2, -1, -1):
            t = lines[i].strip()
            if t.startswith('//'): continue
            lm = _LOOP_RE.search(t)
            if lm:
                if self._bracedepth(line, lines) > self._bracedepth(i + 1, lines):
                    return True
                break
        return False

    def _dangling_field_free(self, a: FreeSite, b: FreeSite) -> bool:
        if '->' not in b.var or '->' in a.var: return False
        return b.var.split('->')[0].strip() == a.var and a.line < b.line

    def _enclosing(self, line: int,
                    fm: Dict[str, Tuple[int, int, List[str]]]) -> Optional[str]:
        best = None; bs = 0
        for name, (s, e, _) in fm.items():
            if s <= line <= e and s > bs: best = name; bs = s
        return best


# 模块级辅助

def _base_var(expr: str) -> str:
    e = expr.strip()
    if e.startswith('*') and not e.startswith('*/'): e = e[1:].strip()
    if '->' in e: return e.split('->')[-1].strip()
    if '.' in e: return e.split('.')[-1].strip()
    return e

def _field_suffix(var: str, sn: str) -> str:
    if var == sn: return ''
    if var.startswith(sn + '.'): return var[len(sn):]
    if var.startswith(sn + '->'): return var[len(sn):]
    return ''

def _is_local_assign(line: str) -> bool:
    return line.strip().startswith(('char', 'int', 'void', 'long', 'short',
        'float', 'double', 'unsigned', 'static', 'const', 'size_t'))
