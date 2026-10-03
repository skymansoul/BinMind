"""
C源码前向变量传播 — 轻量 intra-procedural def-use 链追踪, 将动态size/offset解析为常量或区间.
收集 #define + 赋值 → 正向传播至 malloc/memcpy 调用点. 线性扫描, O(n).

▎DefPoint + 正则模式 → analysis.c_source_var_patterns
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

from analysis.c_source_var_patterns import (
    DefPoint,
    _RE_DEFINE, _RE_CONST_DECL, _RE_ASSIGN_CONST, _RE_ASSIGN_VAR,
    _RE_ASSIGN_ADD, _RE_ASSIGN_SUB, _RE_ASSIGN_MUL,
    _RE_ALLOC_CALL, _RE_MEMCPY_CALL, _try_int,
)


class CSourceVarResolver:
    """C 源码变量解析器 — 正向传播, 解析 malloc/memcpy 中的变量大小."""

    def __init__(self, src_lines: List[str]):
        self._lines = src_lines
        self._values: Dict[str, int] = {}      # var → concrete value
        self._defs: Dict[str, List[DefPoint]] = {}  # var → all def points
        self._collect_defines()
        self._collect_assignments()
        self._propagate_forward()

    # 收集阶段

    def _collect_defines(self) -> None:
        for line in self._lines:
            m = _RE_DEFINE.match(line.strip())
            if m:
                name, val = m.group(1), m.group(2)
                _, n = _try_int(val)
                if n >= 0:
                    self._values[name] = n

    def _collect_assignments(self) -> None:
        for pc, line in enumerate(self._lines):
            stripped = line.strip()
            if not stripped or stripped.startswith('//') or stripped.startswith('/*'):
                continue

            # int var = N;
            m = _RE_CONST_DECL.search(stripped)
            if m:
                name, n = m.group(1), m.group(2)
                _, v = _try_int(n)
                if v >= 0:
                    self._add_def(name, pc, v, n, True)
                    continue

            # var = N;
            m2 = _RE_ASSIGN_CONST.search(stripped)
            if m2:
                name, n = m2.group(1), m2.group(2)
                if any(kw in stripped for kw in ('if', 'while', 'for', 'switch')):
                    continue
                _, v = _try_int(n)
                if v >= 0:
                    self._add_def(name, pc, v, n, True)
                    continue

            # var = other_var;
            m3 = _RE_ASSIGN_VAR.search(stripped)
            if m3 and m3.group(1) != m3.group(2):
                self._add_def(m3.group(1), pc, -1, m3.group(2), False)

            # var = other + N; or var = other - N;
            for pat, sign in [(_RE_ASSIGN_ADD, 1), (_RE_ASSIGN_SUB, -1)]:
                m4 = pat.search(stripped)
                if m4:
                    _, n = _try_int(m4.group(3))
                    if n >= 0:
                        self._add_def(m4.group(1), pc, -1,
                                      f'{m4.group(2)}{"+" if sign>0 else "-"}{n}', False)

            # var = other * N;
            m5 = _RE_ASSIGN_MUL.search(stripped)
            if m5:
                _, n = _try_int(m5.group(3))
                if n >= 0:
                    self._add_def(m5.group(1), pc, -1,
                                  f'{m5.group(2)}*{n}', False)

    def _add_def(self, var: str, pc: int, value: int, expr: str, is_const: bool):
        if var not in self._defs:
            self._defs[var] = []
        self._defs[var].append(DefPoint(var, pc, value, expr, is_const))

    # 传播阶段: 正向扫描, 在定义点后更新当前值

    def _propagate_forward(self) -> None:
        """正向传播: 定义点→值, 最多3跳链式解析."""
        for _ in range(3):
            for var, defs in self._defs.items():
                for d in defs:
                    if d.is_const:
                        self._values[var] = d.value
                    elif d.expr.isidentifier() and d.expr in self._values:
                        self._values[var] = self._values[d.expr]
                    elif '+' in d.expr:
                        parts = d.expr.split('+')
                        if len(parts) == 2:
                            src, delta = parts[0], parts[1]
                            _, n = _try_int(delta)
                            if src in self._values and n >= 0:
                                self._values[var] = self._values[src] + n
                    elif '-' in d.expr:
                        parts = d.expr.split('-')
                        if len(parts) == 2:
                            src, delta = parts[0], parts[1]
                            _, n = _try_int(delta)
                            if src in self._values and n >= 0:
                                self._values[var] = self._values[src] - n
                    elif '*' in d.expr:
                        parts = d.expr.split('*')
                        if len(parts) == 2:
                            src, mult = parts[0], parts[1]
                            _, n = _try_int(mult)
                            if src in self._values and n > 0:
                                self._values[var] = self._values[src] * n

    # 查询接口

    def resolve(self, var: str) -> int:
        """获取变量值, 解析失败返回 -1."""
        return self._values.get(var, -1)

    def resolve_at(self, var: str, pc: int) -> int:
        """获取变量在pc行的值 (使用该行之前的最近定义)."""
        if var in self._defs:
            best = None
            for d in self._defs[var]:
                if d.pc < pc:
                    if best is None or d.pc > best.pc:
                        best = d
            if best:
                if best.is_const:
                    return best.value
                if best.expr.isidentifier():
                    return self.resolve(best.expr)
        return self.resolve(var)

    def resolve_alloc_size(self, pc: int) -> Tuple[int, str]:
        """解析 pc 行的 alloc 调用大小. 返回 (size, size_expr)."""
        if pc >= len(self._lines):
            return 0, ""
        line = self._lines[pc]
        m = re.search(r'(?:malloc|calloc|realloc)\s*\(', line)
        if not m:
            return 0, ""

        paren_start = m.end() - 1
        depth, i = 0, paren_start
        while i < len(line):
            ch = line[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    args_str = line[paren_start + 1:i]
                    args = [a.strip() for a in args_str.split(',')]
                    break
            i += 1
        else:
            return 0, ""

        func = m.group(0).split('(')[0].strip()
        if func == 'realloc' and len(args) >= 2:
            size_str = args[1]
        elif func == 'calloc' and len(args) >= 2:
            s0 = self._resolve_size_str(args[0])
            s1 = self._resolve_size_str(args[1])
            if s0 > 0 and s1 > 0:
                return s0 * s1, ""
            return 0, f'{args[0]}*{args[1]}'
        elif args:
            size_str = args[0]
        else:
            return 0, ""

        sz = self._resolve_size_str(size_str)
        if sz > 0:
            return sz, ""
        var_match = re.match(r'(\w+)', size_str)
        if var_match:
            return 0, var_match.group(1)
        return 0, ""

    def _resolve_size_str(self, s: str) -> int:
        s = s.strip()
        if s.isdigit():
            _, n = _try_int(s)
            return n if n > 0 else -1
        sizeof_m = re.match(r'sizeof\s*\((.+)\)', s)
        if sizeof_m:
            t = sizeof_m.group(1).strip().lower()
            t = re.sub(r'\b(?:unsigned|signed|const|struct)\s+', '', t).strip()
            if t in ('char', 'uint8_t', 'int8_t'):
                return 1
            if t in ('short', 'uint16_t', 'int16_t'):
                return 2
            if t in ('int', 'uint32_t', 'int32_t', 'float', 'unsigned int',
                     'unsigned'):
                return 4
            if t in ('double', 'uint64_t', 'int64_t', 'size_t', 'ssize_t',
                     'long', 'unsigned long', 'long long', 'unsigned long long'):
                return 8
            return 4
        if s.isidentifier():
            return self.resolve(s)
        return -1

    def resolve_store_size(self, store_pc: int) -> int:
        """解析 memcpy/memset 第三参数."""
        if store_pc >= len(self._lines):
            return -1
        line = self._lines[store_pc]
        m = re.search(r'(?:memcpy|memset|memmove|strncpy)\s*\(', line, re.IGNORECASE)
        if not m:
            return -1
        paren_start = m.end() - 1
        depth, i = 0, paren_start
        while i < len(line):
            ch = line[i]
            if ch == '(':
                depth += 1
            elif ch == ')':
                depth -= 1
                if depth == 0:
                    args_str = line[paren_start + 1:i]
                    args = [a.strip() for a in args_str.split(',')]
                    break
            i += 1
        else:
            return -1

        if len(args) < 3:
            return -1

        size_arg = args[-1].strip()
        if size_arg.isdigit():
            _, n = _try_int(size_arg)
            return n
        if size_arg.isidentifier():
            return self.resolve(size_arg)
        s = self._resolve_size_str(size_arg)
        if s > 0:
            return s
        return -1

    def resolve_offset_constant(self, base_var: str, store_pc: int) -> int:
        """解析 buf[N] 或 buf+offset 中的偏移量常量."""
        if store_pc >= len(self._lines):
            return -1
        line = self._lines[store_pc]

        m = re.search(
            r'\b' + re.escape(base_var) + r'\s*\[\s*(\d+)\s*\]\s*=',
            line)
        if m:
            _, n = _try_int(m.group(1))
            return n

        m2 = re.search(
            r'\*\s*\(\s*' + re.escape(base_var) + r'\s*\+\s*(\d+)\s*\)\s*=',
            line)
        if m2:
            _, n = _try_int(m2.group(1))
            return n

        return -1

    def get_all_resolved(self) -> Dict[str, int]:
        return dict(self._values)


# [DEPRECATED] — 直接使用 CSourceVarResolver(src_lines) 即可
def build_var_resolver(src_lines: List[str]) -> CSourceVarResolver:
    return CSourceVarResolver(src_lines)
