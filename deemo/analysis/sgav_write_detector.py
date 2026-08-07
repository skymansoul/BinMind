"""
SGAV 写入检测器 — 识别危险写入操作 + 别名解析 + 函数定位.
"""
from __future__ import annotations
import re
from typing import List, Dict, Set, Optional
from analysis.sgav_types import WriteDesc, BufferDesc

_GETS = re.compile(r'\bgets\s*\(\s*(\w[\w]*)\s*\)')
_STRCPY = re.compile(r'\bstrcpy\s*\(\s*(\w[\w]*)\s*,\s*(\w[\w]*)')
_STRCAT = re.compile(r'\bstrcat\s*\(\s*(\w[\w]*)\s*,')
_STRNCPY = re.compile(r'\bstrncpy\s*\(\s*(\w[\w]*)\s*,\s*[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
_STRNCAT = re.compile(r'\bstrncat\s*\(\s*(\w[\w]*)\s*,\s*[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
_SPRINTF = re.compile(r'\bsprintf\s*\(\s*(\w[\w]*)\s*,')
_SNPRINTF = re.compile(r'\bsnprintf\s*\(\s*(\w[\w]*)\s*,\s*(.+?)\s*,')
_SCANF = re.compile(r'\bscanf\s*\(\s*"([^"]*)"\s*,\s*&?(\w[\w]*)')
_SSCANF = re.compile(r'\bsscanf\s*\(\s*[^,]+,\s*"([^"]*)"\s*,\s*&?(\w[\w]*)')
_READ = re.compile(r'\bread\s*\([^,]+,\s*(\w[\w]*)\s*,\s*(.+?)\)\s*;', re.DOTALL)
_RECV = re.compile(r'\brecv\s*\([^,]+,\s*(\w[\w]*)\s*,\s*(.+?)\)\s*;', re.DOTALL)
_MEMCPY = re.compile(r'\bmemcpy\s*\(\s*(\w[\w]*)\s*,[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
_MEMMOVE = re.compile(r'\bmemmove\s*\(\s*(\w[\w]*)\s*,[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
_MEMSET = re.compile(r'\bmemset\s*\(\s*(\w[\w]*)\s*,[^,]+,\s*(.+?)\)\s*;', re.DOTALL)
_FGETS = re.compile(r'\bfgets\s*\(\s*(\w[\w]*)\s*,\s*(.+?)\s*,', re.DOTALL)
_OOB = re.compile(r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=')
_FUNC_DEF = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed|static|'
    r'const|inline|size_t)\s+(?:\w+\s*\*?\s+)?(\w+)\s*\(')
# loop copy: while (*src) *dst++ = *src++
_LOOP_COPY = re.compile(r'while\s*\(\s*\*?(\w[\w]*)\s*\)')
# sizeof(buf)
_SIZEOF_IN_ARG = re.compile(r'sizeof\s*\(\s*(\w[\w]*)\s*\)')

_KEYWORDS = frozenset({
    'if', 'else', 'while', 'for', 'return', 'int', 'char', 'void', 'long',
    'short', 'float', 'double', 'size_t', 'unsigned', 'signed', 'static',
    'const', 'sizeof', 'NULL', 'nullptr', 'malloc', 'calloc', 'realloc',
    'free', 'alloca', 'printf', 'main', 'include', 'struct', 'typedef',
    'switch', 'case', 'default', 'goto', 'break', 'continue', 'exit',
    'puts', 'strlen', 'memset', 'memcpy', 'strcmp', 'strncmp', 'strcat',
    'strcpy', 'sprintf', 'strncpy', 'snprintf', 'gets', 'scanf', 'read',
    'fgets', 'recv', 'atoi', 'sscanf', 'memmove', 'volatile', 'asm',
    'attribute', 'noinline', 'puts',
})


class WriteDetector:
    """危险写入操作检测 + 别名解析."""

    def detect(self, lines: List[str],
               bufs: List[BufferDesc],
               alias_map: Dict[str, str]) -> List[WriteDesc]:
        buf_names = {b.name: b for b in bufs}
        # 扩展到别名
        all_bufs: Set[str] = set()
        for b in bufs:
            all_bufs.add(b.name)
            all_bufs.update(b.aliases)
        writes: List[WriteDesc] = []
        func_map = self._build_func_map(lines)
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            fname = self._func_at(i, func_map)
            writes.extend(self._scan_line(
                i, text, all_bufs, buf_names, alias_map, fname))
        return writes

    def _scan_line(self, line_num: int, text: str,
                   all_bufs: Set[str],
                   buf_names: Dict[str, BufferDesc],
                   alias_map: Dict[str, str],
                   fname: str) -> List[WriteDesc]:
        results = []
        # gets
        for m in _GETS.finditer(text):
            t = m.group(1)
            if t in all_bufs:
                results.append(WriteDesc(
                    line=line_num, target=t, kind='gets',
                    resolved_buf=alias_map.get(t, t), func_name=fname))
        # strcpy / strcat
        for pat, kind in [(_STRCPY, 'strcpy'), (_STRCAT, 'strcat')]:
            for m in pat.finditer(text):
                t = m.group(1)
                if t in all_bufs:
                    src = m.group(2) if m.lastindex and m.lastindex >= 2 else ''
                    results.append(WriteDesc(
                        line=line_num, target=t, kind=kind,
                        resolved_buf=alias_map.get(t, t),
                        func_name=fname, src_var=src))
        # strncpy / strncat (有界)
        for pat, kind in [(_STRNCPY, 'strncpy'), (_STRNCAT, 'strncat')]:
            for m in pat.finditer(text):
                t = m.group(1)
                if t in all_bufs:
                    ws = self._parse_size(m.group(2), buf_names)
                    results.append(WriteDesc(
                        line=line_num, target=t, kind=kind, write_size=ws,
                        resolved_buf=alias_map.get(t, t), func_name=fname))
        # sprintf
        for m in _SPRINTF.finditer(text):
            t = m.group(1)
            if t in all_bufs:
                results.append(WriteDesc(
                    line=line_num, target=t, kind='sprintf',
                    resolved_buf=alias_map.get(t, t), func_name=fname))
        # snprintf (有界)
        for m in _SNPRINTF.finditer(text):
            t = m.group(1)
            if t in all_bufs:
                ws = self._parse_size(m.group(2), buf_names)
                results.append(WriteDesc(
                    line=line_num, target=t, kind='snprintf', write_size=ws,
                    resolved_buf=alias_map.get(t, t), func_name=fname))
        # scanf / sscanf
        for pat, kind in [(_SCANF, 'scanf'), (_SSCANF, 'sscanf')]:
            for m in pat.finditer(text):
                if '%s' in m.group(1):
                    t = m.group(2)
                    if t in all_bufs:
                        results.append(WriteDesc(
                            line=line_num, target=t, kind=kind,
                            resolved_buf=alias_map.get(t, t),
                            func_name=fname))
        # read / recv
        for pat, kind in [(_READ, 'read'), (_RECV, 'recv')]:
            for m in pat.finditer(text):
                t = m.group(1)
                if t in all_bufs:
                    ws = self._parse_size(m.group(2), buf_names)
                    results.append(WriteDesc(
                        line=line_num, target=t, kind=kind, write_size=ws,
                        resolved_buf=alias_map.get(t, t), func_name=fname))
        # memcpy / memmove / memset
        for pat, kind in [
            (_MEMCPY, 'memcpy'), (_MEMMOVE, 'memmove'), (_MEMSET, 'memset')]:
            for m in pat.finditer(text):
                t = m.group(1)
                if t in all_bufs:
                    ws = self._parse_size(m.group(2), buf_names)
                    results.append(WriteDesc(
                        line=line_num, target=t, kind=kind, write_size=ws,
                        resolved_buf=alias_map.get(t, t), func_name=fname))
        # fgets (有界)
        for m in _FGETS.finditer(text):
            t = m.group(1)
            if t in all_bufs:
                ws = self._parse_size(m.group(2), buf_names)
                results.append(WriteDesc(
                    line=line_num, target=t, kind='fgets', write_size=ws,
                    resolved_buf=alias_map.get(t, t), func_name=fname))
        # OOB: arr[i] = val
        for m in _OOB.finditer(text):
            arr = m.group(1)
            idx = m.group(2)
            if arr in all_bufs and not idx.isdigit() and idx not in _KEYWORDS:
                results.append(WriteDesc(
                    line=line_num, target=arr, kind='oob', src_var=idx,
                    resolved_buf=alias_map.get(arr, arr), func_name=fname))
        return results

    @staticmethod
    def _parse_size(expr: str,
                    buf_names: Dict[str, BufferDesc]) -> int:
        expr = expr.strip()
        # sizeof(buf) ± N
        m = re.match(r'sizeof\s*\(\s*(\w[\w]*)\s*\)\s*([+\-])\s*(\d+)', expr)
        if m:
            bname = m.group(1)
            op = m.group(2)
            offset = int(m.group(3))
            if bname in buf_names and buf_names[bname].size > 0:
                base = buf_names[bname].size
                return base - offset if op == '-' else base + offset
            return -3
        # sizeof(buf)
        m = _SIZEOF_IN_ARG.search(expr)
        if m:
            bname = m.group(1)
            if bname in buf_names and buf_names[bname].size > 0:
                return buf_names[bname].size
            return -3
        # 常量
        try:
            return int(expr, 0)
        except ValueError:
            pass
        # 表达式: var + N, var - N
        m = re.match(r'(\w[\w]*)\s*([+\-])\s*(\d+)', expr)
        if m:
            return -2
        # 纯变量
        if re.match(r'^\w[\w]*$', expr):
            return -2
        return -2

    @staticmethod
    def _build_func_map(lines: List[str]) -> List[tuple]:
        funcs = []
        full = '\n'.join(lines)
        for m in _FUNC_DEF.finditer(full):
            name = m.group(1)
            if name in _KEYWORDS: continue
            start = full[:m.start()].count('\n') + 1
            depth = 0
            end = start
            for j in range(start, len(lines) + 1):
                ln = lines[j - 1]
                depth += ln.count('{') - ln.count('}')
                if depth <= 0 and j > start:
                    end = j
                    break
            funcs.append((name, start, end))
        return funcs

    @staticmethod
    def _func_at(line: int, funcs: List[tuple]) -> str:
        for name, s, e in funcs:
            if s <= line <= e:
                return name
        return ""


__all__ = ['WriteDetector']
