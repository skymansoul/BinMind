"""
堆循环写入累积分析器 — 仿射边界验证 (Affine Bound Verification) 维度7候选.
追踪循环内堆缓冲区的累积写入量, 与分配大小对比.
填补检测盲区: 逐条malloc/memcpy配对无法检出循环内逐字节累积溢出.
方法: 识别循环→提取归纳变量界→累积单次写入量×迭代次数→比较分配大小.
保守性: 仅当循环界已知且累积写入≤分配大小时才判定SAFE. UNCERTAIN→保留.
"""

from __future__ import annotations
import re
from dataclasses import dataclass
from enum import Enum
from typing import Dict, List, Tuple


class LoopWriteVerdict(Enum):
    SAFE = "SAFE"
    OVERFLOW = "OVERFLOW"
    UNCERTAIN = "UNCERTAIN"


@dataclass
class LoopWriteFinding:
    alloc_var: str = ""
    alloc_line: int = 0
    alloc_size: int = 0
    alloc_expr: str = ""
    loop_line: int = 0
    loop_bound: int = -1
    loop_var: str = ""
    writes_per_iter: int = 0
    total_write_estimate: int = 0
    verdict: LoopWriteVerdict = LoopWriteVerdict.UNCERTAIN
    reason: str = ""


class HeapLoopAccumulator:
    """循环感知堆写入累积分析 — 检测循环内malloc/memcpy配对盲区."""

    _MALLOC_RE = re.compile(
        r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(\s*([^)]+)',
        re.IGNORECASE)
    _FOR_RE = re.compile(
        r'for\s*\(\s*\w+\s+(\w+)\s*=\s*(\d+)\s*;'
        r'\s*\1\s*([<<=]+)\s*(\w[\w]*)\s*;'
        r'\s*\1\s*(\+\+|\-\-|\+\s*=\s*(\d+)|\-\s*=\s*(\d+))',
        re.IGNORECASE)
    _ARRAY_WRITE_RE = re.compile(
        r'(\w[\w]*)\s*\[\s*(\w[\w]*)\s*(?:\]\s*=|\]\s*\+=)')
    _MCPY_RE = re.compile(
        r'(?:memcpy|memmove|strcpy|strncpy|memset)\s*\(\s*(\w[\w]*)',
        re.IGNORECASE)
    _PTR_ASSIGN_RE = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;')
    _CONST_DEF_RE = re.compile(r'#define\s+(\w+)\s+(\d+)')

    def analyze(self, source: str) -> List[LoopWriteFinding]:
        """分析C源码中的循环堆写入累积溢出. 返回所有发现."""
        lines = source.splitlines()
        findings: List[LoopWriteFinding] = []

        macros = self._extract_macros(lines)
        allocs = self._find_allocs(lines, macros)
        aliases = self._find_aliases(lines)
        loops = self._find_loops(lines)

        for alloc_var, alloc_line, _func, alloc_size, alloc_expr in allocs:
            for loop_line, loop_var, loop_bound, body_end in loops:
                if loop_line <= alloc_line:
                    continue
                if body_end > 0 and body_end <= alloc_line:
                    continue
                writes = self._count_loop_writes(
                    lines, loop_line, body_end, alloc_var, aliases)
                if writes == 0:
                    continue

                finding = LoopWriteFinding(
                    alloc_var=alloc_var, alloc_line=alloc_line,
                    alloc_size=alloc_size, alloc_expr=alloc_expr,
                    loop_line=loop_line, loop_bound=loop_bound,
                    loop_var=loop_var, writes_per_iter=writes)

                if alloc_size == 0:
                    finding.total_write_estimate = writes
                    if loop_bound > 0:
                        finding.total_write_estimate *= loop_bound
                    finding.reason = f"unresolved alloc size, {finding.total_write_estimate}b est"
                    finding.verdict = LoopWriteVerdict.UNCERTAIN
                elif loop_bound > 0:
                    finding.total_write_estimate = writes * loop_bound
                    if finding.total_write_estimate <= alloc_size:
                        finding.verdict = LoopWriteVerdict.SAFE
                        finding.reason = (
                            f"loop cum {writes}*{loop_bound}"
                            f"={finding.total_write_estimate} <= {alloc_size}")
                    else:
                        finding.verdict = LoopWriteVerdict.OVERFLOW
                        finding.reason = (
                            f"loop cum {writes}*{loop_bound}"
                            f"={finding.total_write_estimate} > {alloc_size}")
                else:
                    finding.total_write_estimate = writes
                    finding.reason = f"unknown bound, {writes}b/iter"
                findings.append(finding)
        return findings

    def _extract_macros(self, lines: List[str]) -> Dict[str, int]:
        macros: Dict[str, int] = {}
        for line in lines:
            m = self._CONST_DEF_RE.match(line.strip())
            if m:
                try:
                    macros[m.group(1)] = int(m.group(2))
                except ValueError:
                    pass
        return macros

    def _find_allocs(self, lines: List[str],
                     macros: Dict[str, int]) -> List[Tuple[str, int, str, int, str]]:
        allocs = []
        for i, line in enumerate(lines, start=1):
            m = self._MALLOC_RE.search(line)
            if m:
                var = m.group(1)
                func = m.group(2)
                args_str = m.group(3).strip().rstrip(')')
                size_expr = args_str
                size = self._resolve_size(args_str, macros)
                if not size and func in ('calloc', 'realloc') and ',' in args_str:
                    nmemb_str, _, size_str = args_str.partition(',')
                    nmemb = self._resolve_size(nmemb_str.strip(), macros)
                    sz = self._resolve_size(size_str.strip(), macros)
                    if nmemb > 0 and sz > 0:
                        size = nmemb * sz
                        size_expr = f'{nmemb}*{sz}'
                allocs.append((var, i, func, size, size_expr))
        return allocs

    def _find_aliases(self, lines: List[str]) -> Dict[str, str]:
        aliases: Dict[str, str] = {}
        for line in lines:
            m = self._PTR_ASSIGN_RE.search(line.strip())
            if m:
                dst, src = m.group(1), m.group(2)
                if dst != src and not dst.startswith(
                        ('if', 'while', 'for')):
                    aliases[dst] = src
        return aliases

    def _find_loops(self,
                    lines: List[str]) -> List[Tuple[int, str, int, int]]:
        """返回 (行号, 归纳变量, 迭代次数界, 循环体结束行). bound=-1=未知."""
        loops = []
        for i, line in enumerate(lines, start=1):
            s = line.strip()
            fm = self._FOR_RE.search(s)
            if fm:
                ivar = fm.group(1)
                init_val = int(fm.group(2))
                op = fm.group(3)
                bound_str = fm.group(4)
                try:
                    bound = int(bound_str)
                except ValueError:
                    bound = -1
                if op in ('<', '<=') and bound > 0:
                    trips = bound - init_val if op == '<' else bound - init_val + 1
                else:
                    trips = -1
                body_end = self._find_body_end(lines, i)
                loops.append((i, ivar, trips, body_end))
        return loops

    def _find_body_end(self, lines: List[str], start: int) -> int:
        """括号计数找循环体结束行."""
        depth = 0
        started = False
        for i in range(start - 1, len(lines)):
            s = lines[i].strip()
            if '{' in s:
                depth += s.count('{')
                started = True
            if '}' in s:
                depth -= s.count('}')
                if started and depth == 0:
                    return i + 1
        return len(lines)

    def _count_loop_writes(self, lines: List[str], loop_start: int,
                           body_end: int, buf_var: str,
                           aliases: Dict[str, str]) -> int:
        """统计循环体内对buf_var的单次迭代写入字节数."""
        resolved = {buf_var}
        for dst, src in aliases.items():
            if src in resolved:
                resolved.add(dst)

        total = 0
        in_body = False
        single_line = (body_end == loop_start)
        for i, line in enumerate(lines, start=1):
            s = line.strip()
            if i == loop_start:
                in_body = True
                if not single_line:
                    continue
            if body_end > 0 and i > body_end:
                break
            if not in_body:
                continue

            am = self._ARRAY_WRITE_RE.search(s)
            if am:
                if am.group(1) in resolved:
                    total += 1
                continue

            mm = self._MCPY_RE.search(s)
            if mm:
                tgt = mm.group(1)
                if tgt in resolved or tgt == buf_var:
                    total += max(1, self._extract_memcpy_size(s))
        return total

    def _extract_memcpy_size(self, line: str) -> int:
        """从memcpy/memset调用提取常量大小参数."""
        parts = line.split(',')
        if len(parts) >= 3:
            sz_str = parts[2].strip().rstrip(');').strip()
            try:
                return int(sz_str)
            except ValueError:
                pass
        return 1

    @staticmethod
    def _resolve_size(expr: str, macros: Dict[str, int]) -> int:
        """解析malloc大小表达式为整数常量. 返回0=无法解析."""
        expr = expr.strip()
        if expr.isdigit():
            return int(expr)
        if expr.startswith('0x'):
            try:
                return int(expr, 16)
            except ValueError:
                pass
        if expr in macros:
            return macros[expr]
        sm = re.match(r'sizeof\s*\(\s*(\w+)\s*\)?', expr)
        if sm:
            type_sizes = {'char': 1, 'short': 2, 'int': 4, 'long': 8,
                          'float': 4, 'double': 8, 'void': 1}
            return type_sizes.get(
                sm.group(1).replace('*', '').strip(), 4)
        mult = re.match(r'(\d+)\s*\*\s*sizeof', expr)
        if mult:
            return int(mult.group(1)) * 4
        return 0


__all__ = ['HeapLoopAccumulator', 'LoopWriteFinding', 'LoopWriteVerdict']
