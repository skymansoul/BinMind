"""
栈溢出源级验证器 (SOSV). 缓冲区识别→写入检测→溢出判定→递归栈耗尽.
4-phase: buffer detect→write detect→overflow check→recursion exhaustion.
"""
from __future__ import annotations
import re
from typing import Dict, List, Optional, Tuple, Set
from analysis.stack_overflow_types import (
    SoVerdict, StackBuffer, StackWrite, SoResult)

_BUF_RE = re.compile(r'(?:char|int|unsigned\s+int|short|long|float|double)\s+(\w+)\s*\[\s*(\d+|\w[\w]*)\s*\]')
_VLA_BUF_RE = re.compile(r'(?:char|int|unsigned\s+int|short|long|float|double)\s+(\w+)\s*\[\s*(\w[\w]*)\s*\]')
_ALLOCA_RE = re.compile(r'(?:\w[\w]*\s*\*?\s+)?(\w[\w]*)\s*=\s*(?:\(\s*\w[\w]*\s*\*?\s*\)\s*)?alloca\s*\(\s*([^)]+)\s*\)')
_GETS_RE = re.compile(r'\bgets\s*\(\s*(\w[\w]*)\s*\)')
_STRCPY_RE = re.compile(r'\bstrcpy\s*\(\s*(\w[\w]*)\s*,')
_STRCAT_RE = re.compile(r'\bstrcat\s*\(\s*(\w[\w]*)\s*,')
_SPRINTF_RE = re.compile(r'\bsprintf\s*\(\s*(\w[\w]*)\s*,')
_SCANF_RE = re.compile(r'\bscanf\s*\(\s*"([^"]*)"\s*,\s*&?(\w[\w]*)')
_READ_RE = re.compile(r'\bread\s*\([^,]+,\s*(\w[\w]*)\s*,\s*([^)]+)\s*\)')
_MEMCPY_RE = re.compile(r'\bmemcpy\s*\(\s*(\w[\w]*)\s*,[^,]+,\s*([^)]+)\s*\)')
_MEMSET_RE = re.compile(r'\bmemset\s*\(\s*(\w[\w]*)\s*,[^,]+,\s*([^)]+)\s*\)')
_OOB_RE = re.compile(r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*\]\s*=')
_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed|static|const|inline|size_t)\s+'
    r'(?:\w+\s*\*?\s+)?(\w+)\s*\(\s*([^)]*)\s*\)\s*\{?')
_SELF_CALL_RE = re.compile(r'\b(\w+)\s*\(')
_NON_VAR = frozenset({
    'if','else','while','for','return','int','char','void','long','short',
    'float','double','size_t','unsigned','signed','static','const','sizeof',
    'NULL','nullptr','malloc','calloc','realloc','free','alloca','printf',
    'main','include','struct','typedef','switch','case','default','goto',
    'break','continue','exit','puts','strlen','memset','memcpy','strcmp',
    'strncmp','strcat','strcpy','sprintf','strncpy','snprintf','gets','scanf',
    'read','fgets','recv','atoi'})
_RECURSE_FRAME_THRESHOLD = 512   # 递归帧中locals >512B → 栈耗尽风险
_EXCESSIVE_FRAME_THRESHOLD = 32768  # 单帧 >32KB → 过大栈分配


class StackOverflowSrcVerifier:
    """栈溢出源级验证 — 缓冲区分析 + 写入检测 + 递归耗尽."""

    def verify(self, source: str) -> List[SoResult]:
        lines = source.splitlines()
        bufs = self._find_buffers(lines)
        if not bufs: return []
        writes = self._find_writes(lines, bufs)
        fm = self._build_func_map(lines)
        results: List[SoResult] = []
        # 写入溢出检测
        for w in writes:
            r = self._check_write(w, bufs, lines)
            if r: results.append(r)
        # strcat累积检测
        strcat_targets: Dict[str, List[int]] = {}
        for w in writes:
            if w.kind == 'strcat':
                strcat_targets.setdefault(w.target, []).append(w.line)
        for tgt, wlines in strcat_targets.items():
            if len(wlines) >= 3:
                for b in bufs:
                    if b.name == tgt and b.size >= 0 and b.size < 256:
                        results.append(SoResult(verdict=SoVerdict.VULN,
                            buffer_line=b.line, buf_name=b.name, buf_size=b.size,
                            write_line=wlines[-1],
                            reason=f"'{tgt}[{b.size}]': {len(wlines)} strcat calls → cumulative overflow"))
        # 递归栈耗尽
        for name, (s, e, _) in fm.items():
            frame = self._frame_size(name, s, e, lines)
            if frame >= _RECURSE_FRAME_THRESHOLD and self._is_recursive(name, s, e, lines):
                results.append(SoResult(verdict=SoVerdict.VULN,
                    buffer_line=s, buf_name=name, buf_size=frame,
                    reason=f"'{name}': recursive with {frame}B frame → stack exhaustion"))
        # 过大栈帧
        for b in bufs:
            if b.size >= _EXCESSIVE_FRAME_THRESHOLD and b.kind == 'fixed':
                results.append(SoResult(verdict=SoVerdict.VULN,
                    buffer_line=b.line, buf_name=b.name, buf_size=b.size,
                    confidence=0.75,
                    reason=f"'{b.name}[{b.size}]': excessive stack allocation"))
        seen = set(); unique = []
        for r in results:
            key = (r.buffer_line, r.write_line, r.buf_name)
            if key not in seen: seen.add(key); unique.append(r)
        return unique

    # Phase 1: 缓冲区识别

    def _find_buffers(self, lines: List[str]) -> List[StackBuffer]:
        bufs = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            # VLA: char buf[n]
            vm = _VLA_BUF_RE.search(text)
            if vm and not vm.group(2).isdigit() and vm.group(2) not in _NON_VAR:
                bufs.append(StackBuffer(line=i, name=vm.group(1),
                    size=-1, kind='vla')); continue
            # fixed: char buf[64] / int arr[10]
            bm = _BUF_RE.search(text)
            if bm and bm.group(2).isdigit():
                bufs.append(StackBuffer(line=i, name=bm.group(1),
                    size=int(bm.group(2)), kind='fixed'))
            # alloca
            am = _ALLOCA_RE.search(text)
            if am:
                bufs.append(StackBuffer(line=i, name=am.group(1),
                    size=-2, kind='alloca'))
        return bufs

    # Phase 2: 写入检测

    def _find_writes(self, lines: List[str],
                     bufs: List[StackBuffer]) -> List[StackWrite]:
        buf_names = {b.name for b in bufs}
        writes = []
        for i, line in enumerate(lines, start=1):
            text = line.strip()
            if text.startswith(('//', '/*')): continue
            # gets
            for m in _GETS_RE.finditer(text):
                if m.group(1) in buf_names:
                    writes.append(StackWrite(line=i, target=m.group(1),
                        kind='gets'))
            # strcpy/strcat
            for pat, kind in [(_STRCPY_RE, 'strcpy'), (_STRCAT_RE, 'strcat')]:
                for m in pat.finditer(text):
                    if m.group(1) in buf_names:
                        writes.append(StackWrite(line=i, target=m.group(1), kind=kind))
            # sprintf
            for m in _SPRINTF_RE.finditer(text):
                if m.group(1) in buf_names:
                    writes.append(StackWrite(line=i, target=m.group(1), kind='sprintf'))
            # scanf("%s", buf)
            for m in _SCANF_RE.finditer(text):
                if '%s' in m.group(1) and m.group(2) in buf_names:
                    writes.append(StackWrite(line=i, target=m.group(2), kind='scanf'))
            # read/memcpy/memset
            for pat, kind in [(_READ_RE, 'read'), (_MEMCPY_RE, 'memcpy'), (_MEMSET_RE, 'memset')]:
                for m in pat.finditer(text):
                    if m.group(1) not in buf_names: continue
                    try: ws = int(m.group(2), 0)
                    except ValueError: ws = -2
                    writes.append(StackWrite(line=i, target=m.group(1),
                        kind=kind, write_size=ws))
            # OOB: arr[i] = val
            for m in _OOB_RE.finditer(text):
                arr = m.group(1); idx = m.group(2)
                if arr in buf_names and not idx.isdigit() and idx not in _NON_VAR:
                    writes.append(StackWrite(line=i, target=arr,
                        kind='oob', src_var=idx))
        return writes

    # Phase 3: 溢出判定

    def _check_write(self, w: StackWrite, bufs: List[StackBuffer],
                     lines: List[str]) -> Optional[SoResult]:
        for b in bufs:
            if b.name != w.target: continue
            bsz = b.size
            # VLA: 无界写入 → VULN
            if w.kind == 'strcpy' and b.kind == 'vla':
                return SoResult(verdict=SoVerdict.VULN, buffer_line=b.line,
                    write_line=w.line, buf_name=b.name, buf_size=-1,
                    confidence=0.85, write_size=-1,
                    reason=f"VLA '{b.name}[n]': unbounded strcpy@L{w.line}")
            # 无界写入 → VULN
            if w.kind in ('gets', 'strcpy', 'sprintf', 'scanf'):
                if b.kind == 'fixed' or b.kind == 'vla':
                    return SoResult(verdict=SoVerdict.VULN,
                        buffer_line=b.line, write_line=w.line,
                        buf_name=b.name, buf_size=bsz, write_size=-1,
                        confidence=0.90,
                        reason=f"'{b.name}[{bsz}]': unbounded {w.kind}@L{w.line}")
            # 有界写入: write_size > buffer_size → VULN
            if w.write_size >= 0 and b.size >= 0 and w.write_size > b.size:
                return SoResult(verdict=SoVerdict.VULN,
                    buffer_line=b.line, write_line=w.line,
                    buf_name=b.name, buf_size=b.size,
                    write_size=w.write_size, confidence=0.95,
                    reason=f"'{b.name}[{b.size}]': {w.kind} writes {w.write_size}B@L{w.line}")
            # alloca + memset: N > alloc_size
            if w.kind == 'memset' and b.kind == 'alloca':
                # alloca(s); memset(p,0,s*2) — write_size is expression
                if w.write_size == -2:  # variable size → check if > alloca param
                    return SoResult(verdict=SoVerdict.VULN,
                        buffer_line=b.line, write_line=w.line,
                        buf_name=b.name, buf_size=-2,
                        confidence=0.80,
                        reason=f"alloca '{b.name}': memset with oversized write@L{w.line}")
            # OOB: arr[i]其中i无界检查
            if w.kind == 'oob':
                return SoResult(verdict=SoVerdict.VULN,
                    buffer_line=b.line, write_line=w.line,
                    buf_name=b.name, buf_size=b.size,
                    confidence=0.80,
                    reason=f"'{b.name}[{b.size}]': OOB write arr[{w.src_var}]@L{w.line}")
        return None

    # Phase 4: 递归检测

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

    def _is_recursive(self, name: str, start: int, end: int,
                      lines: List[str]) -> bool:
        if start == end:
            # 单行函数: 搜索{之后的部分
            text = lines[start - 1]
            brace = text.find('{')
            if brace >= 0: text = text[brace + 1:]
            return any(m.group(1) == name for m in _SELF_CALL_RE.finditer(text))
        # 多行函数: 跳过定义行
        for i in range(start + 1, min(end + 1, len(lines) + 1)):
            text = lines[i - 1].strip()
            if text.startswith(('//', '/*')): continue
            if any(m.group(1) == name for m in _SELF_CALL_RE.finditer(text)):
                return True
        return False

    def _frame_size(self, name: str, start: int, end: int,
                    lines: List[str]) -> int:
        """计算函数栈帧中局部数组的总大小."""
        total = 0
        for i in range(start, min(end + 1, len(lines) + 1)):
            text = lines[i - 1].strip()
            if text.startswith(('//', '/*')): continue
            bm = _BUF_RE.search(text)
            if bm and bm.group(2).isdigit():
                total += int(bm.group(2))
            elif _ALLOCA_RE.search(text):
                # alloca不计入帧大小(动态), 但递归中alloca也是风险
                pass
        # 递归深度×帧大小粗略估计
        return total


# 模块级辅助

def _base_var(expr: str) -> str:
    e = expr.strip()
    if e.startswith('*') and not e.startswith('*/'): e = e[1:].strip()
    if '->' in e: return e.split('->')[-1].strip()
    if '.' in e: return e.split('.')[-1].strip()
    return e
