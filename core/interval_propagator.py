"""
区间传播引擎 — 从 forward_interval_prop.py 提取的前向区间传播器。
读取反编译 IR 行, 为每个程序点构建抽象状态 (变量名 → Interval)。
"""

import re
from typing import Dict, List, Set, Tuple

from core.forward_interval_prop import (
    Interval, AllocSite, WriteSite, IRStatement,
    _C_TYPE_KEYWORDS, _ASSIGN_RE, _MALLOC_RE, _CALLOC_RE, _REALLOC_RE,
    _MEMCPY_RE, _STRCPY_RE, _CMP_RE, _INCR_RE, eval_rhs_interval,
)

class ForwardIntervalPropagator:
    """区间域前向抽象解释器: 读取 IR 并构建每程序点抽象状态, 入口 analyze() → (alloc_sites, write_sites)。"""

    def __init__(self, max_iter: int = 20):
        self._max_iter = max_iter
        self._state: Dict[int, Dict[str, Interval]] = {}
        self._stmts: List[IRStatement] = []
        self._loop_headers: Set[int] = set()
        self._back_edges: Dict[int, int] = {}  # src → dst (loop back)

    @staticmethod
    def _extract_var_from_decl(lhs: str) -> str:
        """从C声明左侧提取变量名 — 跳过类型关键字。

        'int alloc_sz' → 'alloc_sz', 'char *buf' → 'buf', 'buf' → 'buf'
        """
        tokens = re.split(r'[\s\*&]+', lhs.strip())
        for tok in reversed(tokens):
            if not tok:
                continue
            if tok in _C_TYPE_KEYWORDS:
                continue
            if re.match(r'^[a-zA-Z_]\w*$', tok):
                return tok
        for tok in reversed(tokens):
            if tok and re.match(r'^[a-zA-Z_]\w*$', tok):
                return tok
        return ""

    def _parse_ir(self, lines: List[str]) -> List[IRStatement]:
        """解析IR行 — 识别赋值、malloc、memcpy/strcpy 并提取变量名。

        C类型声明感知: int alloc_sz = 64 → var=alloc_sz, rhs=64
                        char *buf = (char *)malloc(alloc_sz) → var=buf
        """
        stmts = []
        for i, line in enumerate(lines):
            stripped = line.strip().rstrip(';')
            s = IRStatement(idx=i, var="", rhs=stripped)

            eq_pos = stripped.find('=')
            if eq_pos > 0:
                lhs = stripped[:eq_pos].strip()
                rhs = stripped[eq_pos + 1:].strip().rstrip(';')
                var = self._extract_var_from_decl(lhs)
                if var:
                    s.var = var
                    s.rhs = rhs
            else:
                s.rhs = stripped

            # 检测 malloc/calloc/realloc
            mm = _MALLOC_RE.search(stripped)
            cm = _CALLOC_RE.search(stripped)
            rm = _REALLOC_RE.search(stripped)

            if mm:
                s.is_malloc = True
                s.alloc_size_var = mm.group(1) or ""
            elif cm:
                s.is_malloc = True
                s.alloc_size_var = f'{cm.group(1)}*{cm.group(2)}'
            elif rm:
                s.is_malloc = True
                s.alloc_size_var = rm.group(1) or ""

            if s.is_malloc and not s.var:
                pre_eq = stripped[:eq_pos] if eq_pos > 0 else ""
                decl_var = self._extract_var_from_decl(pre_eq) if pre_eq else ""
                if decl_var:
                    s.var = decl_var

            # 检测 memcpy/strncpy
            mc = _MEMCPY_RE.search(stripped)
            if mc:
                s.is_write = True
                s.write_dst_var = mc.group(1)
                s.write_size_var = mc.group(2)

            # 检测 strcpy/sprintf (无显式size)
            sc = _STRCPY_RE.search(stripped)
            if sc and not s.is_write:
                s.is_write = True
                s.write_dst_var = sc.group(1)
                s.write_size_var = ""

            stmts.append(s)
        return stmts

    def _detect_loops(self):
        """粗略循环检测: 经 cmp/jmp 模式寻找回边。"""
        self._loop_headers.clear()
        self._back_edges.clear()
        n = len(self._stmts)

        for i in range(1, n):
            line = self._stmts[i].rhs.lower()
            if 'goto' in line:
                for j in range(i - 1, max(0, i - 30), -1):
                    if 'label_' in self._stmts[j].rhs.lower() or \
                       self._stmts[j].rhs.strip().endswith(':'):
                        self._loop_headers.add(j)
                        self._back_edges[i] = j
                        break
            m_incr = _INCR_RE.search(line)
            if m_incr:
                for k in range(i + 1, min(n, i + 5)):
                    if 'goto' in self._stmts[k].rhs.lower() or \
                       'jmp' in self._stmts[k].rhs.lower() or \
                       'jump' in self._stmts[k].rhs.lower():
                        for j in range(i, max(0, i - 20), -1):
                            if 'label_' in self._stmts[j].rhs.lower() or \
                               self._stmts[j].rhs.strip().endswith(':'):
                                self._loop_headers.add(j)
                                self._back_edges[k] = j
                                break

    def analyze(self, ir_lines: List[str]) -> Tuple[List[AllocSite], List[WriteSite]]:
        """主分析入口: 返回带大小区间的分配位点与写入位点列表。"""
        self._stmts = self._parse_ir(ir_lines)
        self._detect_loops()
        n = len(self._stmts)

        if n == 0:
            return [], []

        # 不动点循环: 计算各程序点的抽象状态
        self._state.clear()
        for _ in range(self._max_iter):
            changed = False
            state: Dict[str, Interval] = {}
            for i, stmt in enumerate(self._stmts):
                if i > 0:
                    prev = self._state.get(i - 1, {})
                    cur = dict(prev)
                    if i in self._loop_headers:
                        for src, dst in self._back_edges.items():
                            if dst == i and src in self._state:
                                be_state = self._state[src]
                                for v, iv in be_state.items():
                                    if v in cur:
                                        cur[v] = cur[v].widen(cur[v].union(iv))
                                    else:
                                        cur[v] = iv
                    state = cur
                else:
                    state = {}

                old = self._state.get(i, {})
                merged = {}
                all_vars = set(state.keys()) | set(old.keys())
                for v in all_vars:
                    iv1 = state.get(v, Interval(1, 0))
                    iv2 = old.get(v, Interval(1, 0))
                    merged[v] = iv1.union(iv2)
                if merged != old:
                    changed = True

                if stmt.var and stmt.rhs:
                    iv = eval_rhs_interval(stmt.rhs, state)
                    if not iv.is_bottom:
                        state[stmt.var] = iv
                    cm = _CMP_RE.search(stmt.rhs)
                    if cm:
                        cmp_var = cm.group(1)
                        cmp_op = cm.group(2)
                        cmp_val_str = cm.group(3)
                        try:
                            cmp_val = int(cmp_val_str, 0)
                            if cmp_var in state:
                                existing = state[cmp_var]
                                if cmp_op in ('<', '<='):
                                    hi = cmp_val if cmp_op == '<' else cmp_val
                                    state[cmp_var] = existing.intersect(
                                        Interval(-1, hi))
                                elif cmp_op in ('>', '>='):
                                    lo = cmp_val if cmp_op == '>' else cmp_val
                                    state[cmp_var] = existing.intersect(
                                        Interval(lo, 2**63 - 1))
                        except (ValueError, TypeError):
                            pass

                self._state[i] = dict(state)

            if not changed:
                break

        # 提取分配/写入位点
        alloc_sites: List[AllocSite] = []
        write_sites: List[WriteSite] = []
        seen_allocs: Set[Tuple[int, str]] = set()
        seen_writes: Set[Tuple[int, str]] = set()

        for i, stmt in enumerate(self._stmts):
            state = self._state.get(i, {})

            if stmt.is_malloc and stmt.var:
                key = (i, stmt.var)
                if key not in seen_allocs:
                    seen_allocs.add(key)
                    sz_iv = eval_rhs_interval(stmt.alloc_size_var, state)
                    alloc_sites.append(AllocSite(
                        loc=i, var_name=stmt.var, size_interval=sz_iv))

            if stmt.is_write and stmt.write_dst_var:
                key = (i, stmt.write_dst_var)
                if key not in seen_writes:
                    seen_writes.add(key)
                    sz_iv = eval_rhs_interval(stmt.write_size_var, state)
                    write_sites.append(WriteSite(
                        loc=i, dst_var=stmt.write_dst_var,
                        size_interval=sz_iv))

        return alloc_sites, write_sites

__all__ = ['ForwardIntervalPropagator']
