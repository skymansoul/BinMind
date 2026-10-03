"""
C源码语义分析器 — 三阶段: 提取alloc/write → 值域传播 → 溢出判定.
v2: 多行合并 + 结构体成员→父变量解析 (c_source_preprocessor).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from analysis.c_source_preprocessor import (
    preprocess_source, resolve_write_target,
)


@dataclass
class AllocPoint:
    line: int; var: str; func: str; size_expr: str
    size_const: int = 0; size_vars: Set[str] = field(default_factory=set)


@dataclass
class WritePoint:
    line: int; target_var: str; op: str; size_expr: str
    size_const: int = 0; count_expr: str = ""; count_const: int = 0


@dataclass
class SemVerdict:
    alloc: AllocPoint; write: WritePoint
    verdict: str; reason: str
    overflow_bytes: int = 0; confidence: float = 0.0


class CSemanticAnalyzer:
    """C源码语义分析器 — 值域传播 + 溢出判定."""

    _ALLOC_RE = re.compile(
        r'(?:\w+\s+[\*\s]*)?(\w+)\s*=\s*'
        r'(?:\([^)]*\*?\s*\)\s*)?(malloc|calloc|realloc)\s*\(',
        re.IGNORECASE)
    _MEMCPY_RE = re.compile(
        r'(memcpy|memset|memmove|strncpy)\s*\(\s*(\w+(?:->\w+)?)\s*,'
        r'\s*[^,]+?\s*,\s*([^)]+)\)', re.IGNORECASE)
    _STRCPY_RE = re.compile(
        r'(strcpy|sprintf)\s*\(\s*(\w+(?:->\w+)?)\s*,', re.IGNORECASE)
    _CONST_ASSIGN_RE = re.compile(
        r'(?:int|unsigned|size_t|long|short|char)\s+(\w+)\s*=\s*(\d+)\s*;')
    _PURE_ASSIGN_RE = re.compile(r'(\w+)\s*=\s*(\d+)\s*;')
    _LOOP_FOR_RE = re.compile(
        r'for\s*\(\s*(?:int|unsigned|size_t)?\s*(\w+)\s*=\s*(\d+)\s*;'
        r'\s*\w+\s*(<|<=|>|>=)\s*(\w+)\s*;\s*\w+\s*(\+\+|\-\-)\s*\)')
    _ARRAY_WRITE_RE = re.compile(r'(\w+)\s*\[\s*(\w+)\s*\]\s*=')
    _PTR_WRITE_RE = re.compile(
        r'(?:memcpy|memset|memmove|strncpy)\s*\(\s*(\w+)\s*\+\s*(\w+\s*\*\s*\d+)')
    _ARITH_ASSIGN_RE = re.compile(
        r'(\w+)\s*=\s*(\w+)\s*([+\-*])\s*(\w+|\d+)')

    def analyze(self, source: str) -> List[SemVerdict]:
        """三阶段分析: 预处理→提取alloc/write→值域传播判定."""
        lines, field_map = preprocess_source(source)
        consts = self._collect_constants(lines)
        allocs = self._find_allocs(lines, consts)
        writes = self._find_writes(lines, consts)

        verdicts: List[SemVerdict] = []
        for ap in allocs:
            for wp in writes:
                # 直接匹配或通过结构体成员→父变量匹配
                target = wp.target_var
                if target != ap.var:
                    resolved = resolve_write_target(target, field_map)
                    if resolved != ap.var:
                        continue
                v = self._judge(ap, wp, consts)
                verdicts.append(v)
        return verdicts

    def _collect_constants(self, lines: List[str]) -> Dict[str, int]:
        """收集常量赋值: var=CONST."""
        consts: Dict[str, int] = {}
        for line in lines:
            m = self._CONST_ASSIGN_RE.search(line)
            if m:
                consts[m.group(1)] = int(m.group(2))
                continue
            m = self._PURE_ASSIGN_RE.search(line)
            if m:
                consts[m.group(1)] = int(m.group(2))
        return consts

    def _find_allocs(self, lines: List[str],
                     consts: Dict[str, int]) -> List[AllocPoint]:
        """提取所有分配点."""
        allocs = []
        for i, line in enumerate(lines, start=1):
            m = self._ALLOC_RE.search(line)
            if not m:
                continue
            var, func = m.group(1), m.group(2).lower()
            # 提取参数
            paren_start = m.end() - 1
            args = self._split_args(line, paren_start)
            if not args:
                continue

            if func == 'realloc':
                size_raw = args[1] if len(args) > 1 else args[0]
            elif func == 'calloc':
                n_raw = args[0] if args else '0'
                s_raw = args[1] if len(args) > 1 else '0'
                size_raw = f"({n_raw})*({s_raw})"
            else:
                size_raw = args[0] if args else '0'

            size_const, size_vars = self._resolve_size(size_raw, consts)
            allocs.append(AllocPoint(i, var, func, size_raw, size_const, size_vars))
        return allocs

    def _find_writes(self, lines: List[str],
                     consts: Dict[str, int]) -> List[WritePoint]:
        """提取所有写入点."""
        writes = []
        for i, line in enumerate(lines, start=1):
            # memcpy/memset 等
            m = self._MEMCPY_RE.search(line)
            if m:
                op, dst, size_raw = m.group(1).lower(), m.group(2), m.group(3).strip()
                size_const, _ = self._resolve_size(size_raw, consts)
                writes.append(WritePoint(i, dst, op, size_raw, size_const))
                continue

            # strcpy (无界)
            m = self._STRCPY_RE.search(line)
            if m:
                op, dst = m.group(1).lower(), m.group(2)
                writes.append(WritePoint(i, dst, op, "unbounded", -1))
                continue

            # 数组写: buf[idx] = val (配合for循环)
            m = self._ARRAY_WRITE_RE.search(line)
            if m:
                dst, idx_var = m.group(1), m.group(2)
                # 尝试找对应的循环边界
                loop_count = self._find_loop_bound(lines, i, idx_var)
                elem_size = self._infer_element_size(lines, dst)
                writes.append(WritePoint(
                    i, dst, 'store', f"{loop_count}*{elem_size}",
                    loop_count * elem_size if loop_count > 0 else 0,
                    count_expr=str(loop_count), count_const=loop_count))
                continue

            # 指针偏移写: memcpy(buf + offset, ...)
            m = self._PTR_WRITE_RE.search(line)
            if m:
                dst = m.group(1)
                writes.append(WritePoint(i, dst, 'ptr_write', 'unknown', 0))
                continue

        return writes

    def _judge(self, ap: AllocPoint, wp: WritePoint,
               consts: Dict[str, int]) -> SemVerdict:
        """判定单个alloc-write对."""
        alloc_n = ap.size_const
        write_n = wp.size_const

        # 两常量 — 直接比较
        if alloc_n > 0 and write_n > 0:
            if write_n > alloc_n:
                return SemVerdict(ap, wp, "OVERFLOW",
                    f"write({write_n}) > alloc({alloc_n})",
                    write_n - alloc_n, 0.90)
            else:
                return SemVerdict(ap, wp, "SAFE",
                    f"write({write_n}) <= alloc({alloc_n})",
                    0, 0.85)

        # alloc常量, write动态 — 尝试解析write表达式
        if alloc_n > 0 and ap.size_vars:
            # 分配大小依赖变量 — 用consts替换后重算
            resolved = self._resolve_with_consts(ap.size_expr, consts)
            if resolved > 0:
                alloc_n = resolved

        if alloc_n > 0 and write_n <= 0:
            # write是变量或表达式 — 尝试常量传播
            resolved_w = self._resolve_with_consts(wp.size_expr, consts)
            if resolved_w > 0:
                write_n = resolved_w

        # 重新判定
        if alloc_n > 0 and write_n > 0:
            if write_n > alloc_n:
                return SemVerdict(ap, wp, "OVERFLOW",
                    f"resolved: write({write_n}) > alloc({alloc_n})",
                    write_n - alloc_n, 0.85)
            else:
                return SemVerdict(ap, wp, "SAFE",
                    f"resolved: write({write_n}) <= alloc({alloc_n})",
                    0, 0.80)

        # 循环写 — 检查循环次数*元素大小 vs 分配大小
        if wp.count_const > 0 and wp.op == 'store':
            elem_sz = self._infer_element_type_size(ap.var, consts)
            total_write = wp.count_const * elem_sz
            if alloc_n > 0 and total_write > alloc_n:
                return SemVerdict(ap, wp, "OVERFLOW",
                    f"loop {wp.count_const}*{elem_sz}={total_write} > alloc({alloc_n})",
                    total_write - alloc_n, 0.85)
            elif alloc_n > 0 and total_write <= alloc_n:
                return SemVerdict(ap, wp, "SAFE",
                    f"loop {wp.count_const}*{elem_sz}={total_write} <= alloc({alloc_n})",
                    0, 0.80)

        # calloc整数溢出检测
        if ap.func == 'calloc':
            args = re.findall(r'\(([^)]+)\)\*\(([^)]+)\)', ap.size_expr)
            if args:
                n_val = self._resolve_with_consts(args[0][0], consts)
                s_val = self._resolve_with_consts(args[0][1], consts)
                if n_val > 0 and s_val > 0:
                    product = n_val * s_val
                    if product > (1 << 31):  # 可能32位回绕
                        actual = product & 0xFFFFFFFF
                        return SemVerdict(ap, wp, "OVERFLOW",
                            f"calloc({n_val},{s_val})={product} wraps to {actual}",
                            -1, 0.80)

        return SemVerdict(ap, wp, "UNCERTAIN",
            f"insufficient const info: alloc={ap.size_expr}, write={wp.size_expr}",
            confidence=0.30)

    # 辅助

    @staticmethod
    def _split_args(line: str, paren_pos: int) -> List[str]:
        """括号深度计数分割参数."""
        depth, i, args, cur = 1, paren_pos + 1, [], []
        while i < len(line) and depth > 0:
            ch = line[i]
            if ch == '(': depth += 1; cur.append(ch)
            elif ch == ')':
                depth -= 1
                if depth == 0: args.append(''.join(cur).strip()); cur = []
                else: cur.append(ch)
            elif ch == ',' and depth == 1: args.append(''.join(cur).strip()); cur = []
            else: cur.append(ch)
            i += 1
        if cur: args.append(''.join(cur).strip())
        return args

    @staticmethod
    def _resolve_size(expr: str, consts: Dict[str, int]) -> Tuple[int, Set[str]]:
        """解析size表达式: 常量求值或变量收集."""
        expr = expr.strip()
        try: return int(expr, 0), set()
        except (ValueError, TypeError): pass
        expr = re.sub(r'sizeof\s*\([^)]+\)', '4', expr)
        vars_found = set(re.findall(r'\b([a-zA-Z_]\w*)\b', expr))
        resolved = expr
        for v in vars_found:
            if v in consts: resolved = resolved.replace(v, str(consts[v]))
        try:
            val = eval(resolved, {"__builtins__": {}}, {})
            if isinstance(val, (int, float)): return int(val), vars_found
        except Exception: pass
        return 0, vars_found

    @staticmethod
    def _resolve_with_consts(expr: str, consts: Dict[str, int]) -> int:
        resolved = expr
        for v, c in consts.items(): resolved = re.sub(r'\b'+v+r'\b', str(c), resolved)
        resolved = re.sub(r'sizeof\s*\([^)]+\)', '4', resolved)
        try: return int(eval(resolved, {"__builtins__": {}}, {}))
        except Exception: return 0

    @staticmethod
    def _find_loop_bound(lines: List[str], write_line: int, idx_var: str) -> int:
        for i in range(write_line - 1, max(0, write_line - 20), -1):
            m = re.search(
                r'for\s*\(\s*(?:int|unsigned|size_t)?\s*' + re.escape(idx_var) +
                r'\s*=\s*\d+\s*;\s*\w+\s*(<|<=)\s*(\w+)\s*;', lines[i])
            if m:
                try: return int(m.group(2))
                except ValueError: pass
        return 0

    @staticmethod
    def _infer_element_size(lines: List[str], buf_var: str) -> int:
        tmap = {'char':1,'int':4,'short':2,'long':8,'float':4,'double':8,'void':1}
        for line in lines:
            m = re.search(r'(char|int|short|long|float|double|void)\s*\*+\s*' +
                          re.escape(buf_var), line)
            if m: return tmap.get(m.group(1), 4)
        return 1

    @staticmethod
    def _infer_element_type_size(var: str, consts: Dict[str, int]) -> int:
        return 1  # 默认char