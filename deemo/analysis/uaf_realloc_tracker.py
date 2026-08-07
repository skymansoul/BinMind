"""
UAF Realloc-Path 追踪器 — realloc() 引发的别名悬空指针 UAF (CWE-416+CWE-415).
方法: Realloc Alias Propagation (RAP) — 追踪realloc前的别名集, 检测realloc后的悬空使用.
参考: CVE-2023-28328, CVE-2022-32250, CVE-2021-38001, glibc __libc_realloc().
"""

from __future__ import annotations

import re
import logging
from typing import Dict, List, Set, Tuple

from analysis.uaf_realloc_types import DanglingAlias, ReallocSite, ReallocVerdict

_log = logging.getLogger(__name__)


class ReallocPathTracker:
    """Realloc 路径追踪器 — 检测 realloc 引发的别名 UAF."""

    _PTR_ASSIGN_RE = re.compile(
        r'(\w+(?:->\w+)?(?:\s*\[\s*\w+\s*\])?)\s*=\s*'
        r'(?!\s*(?:malloc|calloc|realloc|free)\s*\()'
        r'(\w+(?:->\w+(?:->\w+)?)?(?:\s*\[\s*\w+\s*\])?)\s*;',
        re.IGNORECASE)
    _REALLOC_RE = re.compile(
        r'(?:(\w+(?:->\w+)?)\s*=\s*)?realloc\s*\(\s*'
        r'(\w+(?:->\w+)?)\s*,\s*([^)]+)\s*\)',
        re.IGNORECASE)
    _FREE_RE = re.compile(r'free\s*\(\s*(\w+(?:->\w+)?)\s*\)', re.IGNORECASE)
    _USE_RE = re.compile(
        r'(?:\*(\w+)\b|(\w+)\s*->|(\w+)\s*\[)', re.IGNORECASE)
    _ALLOC_RE = re.compile(
        r'(\w+(?:->\w+)?)\s*=\s*(?:malloc|calloc)\s*\(', re.IGNORECASE)

    def __init__(self):
        self._realloc_sites: List[ReallocSite] = []
        self._dangling: List[DanglingAlias] = []
        self._ptr_aliases: Dict[str, Set[str]] = {}
        self._allocated_vars: Set[str] = set()

    @property
    def realloc_sites(self) -> List[ReallocSite]:
        return list(self._realloc_sites)

    @property
    def dangling_aliases(self) -> List[DanglingAlias]:
        return list(self._dangling)

    def has_dangling_aliases(self) -> bool:
        return len(self._dangling) > 0

    def clear(self):
        self._realloc_sites.clear()
        self._dangling.clear()
        self._ptr_aliases.clear()
        self._allocated_vars.clear()

    def analyze(self, pseudocode: str) -> List[DanglingAlias]:
        """分析伪代码中的所有 realloc 别名 UAF (Phase 1-4)."""
        self.clear()
        lines = pseudocode.splitlines()
        realloc_sites_raw: List[Tuple[int, str, str, str]] = []

        # Phase 1+2: 前向扫描, 构建别名集并定位 realloc
        for i, raw_line in enumerate(lines):
            line = raw_line.strip()
            if not line or line.startswith('//') or line.startswith('/*'):
                continue

            m_assign = self._PTR_ASSIGN_RE.search(line)
            if m_assign:
                dst = m_assign.group(1)
                src = m_assign.group(2)
                if dst != src:
                    if dst not in self._ptr_aliases:
                        self._ptr_aliases[dst] = set()
                    self._ptr_aliases[dst].add(src)
                    if src in self._ptr_aliases:
                        self._ptr_aliases[dst] |= self._ptr_aliases[src]

            m_alloc = self._ALLOC_RE.search(line)
            if m_alloc:
                self._allocated_vars.add(m_alloc.group(1))

            m_realloc = self._REALLOC_RE.search(line)
            if m_realloc:
                target = m_realloc.group(1)
                arg = m_realloc.group(2)
                new_size = m_realloc.group(3).strip()
                realloc_sites_raw.append((i, target, arg, new_size))

        # Phase 3: 对每个 realloc 计算别名集, 检测悬空使用
        for line_no, target, arg, new_size in realloc_sites_raw:
            alias_closure = self._compute_alias_closure(arg)
            is_zero = self._is_zero_size(new_size)
            is_self = (target == arg)

            site = ReallocSite(
                line_no=line_no, target_var=target or "", arg_var=arg,
                new_size=new_size, old_aliases=alias_closure,
                is_zero_size=is_zero, is_self_assign=is_self)

            if is_zero:
                site.verdict = ReallocVerdict.REALLOC_ZERO
                for alias in alias_closure:
                    for use_line in self._find_uses_after(lines, alias, line_no):
                        self._dangling.append(DanglingAlias(
                            alias_var=alias, realloc_line=line_no,
                            use_line=use_line, realloc_target=target or "",
                            risk="HIGH"))
                self._realloc_sites.append(site)
                continue

            if is_self and alias_closure:
                site.verdict = ReallocVerdict.DANGLE_ALIAS
                dangling_set = alias_closure - {arg}
                for alias in dangling_set:
                    for use_line in self._find_uses_after(lines, alias, line_no):
                        self._dangling.append(DanglingAlias(
                            alias_var=alias, realloc_line=line_no,
                            use_line=use_line, realloc_target=target,
                            risk="HIGH"))
            elif not is_self and target:
                site.verdict = ReallocVerdict.DANGLE_ALIAS
                all_dangling = alias_closure | {arg}
                for alias in all_dangling:
                    for use_line in self._find_uses_after(lines, alias, line_no):
                        self._dangling.append(DanglingAlias(
                            alias_var=alias, realloc_line=line_no,
                            use_line=use_line, realloc_target=target,
                            risk="HIGH"))

            self._realloc_sites.append(site)

        self._detect_double_free(lines)
        return self._dangling

    def _compute_alias_closure(self, var: str) -> Set[str]:
        """计算 var 的传递别名闭包 (包括 var 自身)."""
        closure = {var}
        queue = [var]
        while queue:
            current = queue.pop(0)
            for dst, srcs in self._ptr_aliases.items():
                if dst not in closure and current in srcs:
                    closure.add(dst)
                    queue.append(dst)
            if current in self._ptr_aliases:
                for src in self._ptr_aliases[current]:
                    if src not in closure:
                        closure.add(src)
                        queue.append(src)
        return closure

    def _find_uses_after(self, lines: List[str], var: str,
                         after_line: int) -> List[int]:
        """在 after_line 之后查找 var 的使用行号."""
        uses = []
        for i in range(after_line + 1, len(lines)):
            line = lines[i].strip()
            if not line or line.startswith('//'):
                continue
            if re.search(rf'\b{re.escape(var)}\s*=', line):
                break
            m = self._USE_RE.search(line)
            if m:
                used = m.group(1) or m.group(2) or m.group(3)
                if used == var:
                    uses.append(i)
        return uses

    def _detect_double_free(self, lines: List[str]):
        """检测 realloc 返回的指针被二次 free."""
        freed_vars: Dict[str, List[int]] = {}
        for i, raw_line in enumerate(lines):
            line = raw_line.strip()
            m = self._FREE_RE.search(line)
            if m:
                var = m.group(1)
                freed_vars.setdefault(var, []).append(i)

        for site in self._realloc_sites:
            target = site.target_var
            if target and target in freed_vars and len(freed_vars[target]) > 1:
                post_realloc_frees = [
                    fl for fl in freed_vars[target] if fl > site.line_no]
                if len(post_realloc_frees) > 1:
                    site.verdict = ReallocVerdict.DOUBLE_FREE

    @staticmethod
    def _is_zero_size(size_expr: str) -> bool:
        stripped = size_expr.strip().rstrip(';').strip()
        return stripped in ('0', '0x0', 'NULL', 'nullptr')

    def generate_report(self) -> str:
        """生成 realloc UAF 分析报告 (委托给独立函数)."""
        from analysis.uaf_realloc_integration import generate_realloc_report
        return generate_realloc_report(self._realloc_sites, self._dangling)


__all__ = ['ReallocPathTracker', 'ReallocVerdict', 'ReallocSite',
           'DanglingAlias']
