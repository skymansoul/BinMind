"""UAF时序扫描器 — 源码级模式匹配: free/use/alias发现 + 别名闭包 + 变量匹配."""

from __future__ import annotations
import re
from typing import Dict, List, Set, Tuple


class TemporalScanner:
    """源码模式扫描: free位置, use位置, 别名关系, 变量匹配."""

    _ALLOC_RE = re.compile(
        r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?(malloc|calloc|realloc)\s*\(',
        re.IGNORECASE)
    _FREE_RE = re.compile(
        r'free\s*\(\s*(\*?\w+(?:->\w+|\[\w+\])*)\s*\)', re.IGNORECASE)
    _ARR_SUB_RE = re.compile(r'^(\w+)\[\w+\]$')
    _NULL_RE = re.compile(
        r'(\*?\w+(?:->\w+)?)\s*=\s*(?:NULL|0|nullptr|nil)\s*;', re.IGNORECASE)
    _ALIAS_RE = re.compile(r'(\w[\w]*)\s*=\s*(\w[\w]*)\s*;')
    _USE_RE = re.compile(
        r'(?:\*\*\s*(\w[\w]*)|\*\s*(\w[\w]*)|(\w[\w]*)\s*->|(\w[\w]*)\s*\[)')
    _REALLOC_OLD_RE = re.compile(
        r'(\w[\w]*)\s*=\s*(?:\([^)]*\)\s*)?realloc\s*\(\s*(\w[\w]*)\s*,',
        re.IGNORECASE)

    _NON_PTR = {'if', 'else', 'while', 'for', 'return', 'int', 'char',
                 'void', 'long', 'short', 'float', 'double', 'size_t',
                 'sizeof', 'struct', 'typedef', 'static', 'const',
                 'unsigned', 'signed', 'NULL', 'free', 'malloc', 'calloc',
                 'realloc', 'printf', 'memset', 'strcpy', 'strcat',
                 'memcpy', 'strlen', 'strcmp', 'exit', 'main', 'include',
                 'break', 'continue', 'switch', 'case', 'default', 'goto'}

    _COMMENT_RE = re.compile(r'//.*$|/\*.*?\*/')

    def __init__(self):
        pass

    # 变量匹配

    @classmethod
    def strip_subscript(cls, var: str) -> str:
        """nodes[1] → nodes, arr[i] → arr."""
        m = cls._ARR_SUB_RE.match(var)
        return m.group(1) if m else var

    @classmethod
    def var_matches(cls, fvar: str, uvar: str, resolved: Set[str]) -> bool:
        """检查free变量和use变量是否匹配, 支持数组下标标准化."""
        if uvar == fvar:
            return True
        if uvar in resolved:
            return True
        fbase = cls.strip_subscript(fvar)
        ubase = cls.strip_subscript(uvar)
        if ubase == fbase:
            return True
        resolved_bases = {cls.strip_subscript(r) for r in resolved}
        if ubase in resolved_bases:
            return True
        if '->' in fvar:
            fbase_name = fvar.split('->')[-1]
            if ubase == fbase_name or uvar == fbase_name:
                return True
        if '->' in uvar:
            ubase_name = uvar.split('->')[-1]
            if fbase == ubase_name or fvar == ubase_name:
                return True
        return False

    # 模式发现

    @staticmethod
    def _strip_comments(line: str) -> str:
        """移除行内C注释, 避免注释中的变量名被误识别."""
        return TemporalScanner._COMMENT_RE.sub('', line)

    @staticmethod
    def _strip_comments(line: str) -> str:
        """移除行内C注释, 避免注释中的变量名被误识别."""
        return TemporalScanner._COMMENT_RE.sub('', line)

    @staticmethod
    def _strip_comments(line: str) -> str:
        """移除行内C注释, 避免注释中的变量名被误识别."""
        return TemporalScanner._COMMENT_RE.sub('', line)

    @classmethod
    def find_frees(cls, lines: List[str]) -> List[Tuple[int, int, str]]:
        """返回 (行号, 列偏移, 变量名); 过滤注释行."""
        results = []
        for i, l in enumerate(lines, start=1):
            stripped = cls._strip_comments(l)
            if not stripped.strip():
                continue
            for m in cls._FREE_RE.finditer(stripped):
                results.append((i, m.start(), m.group(1)))
        return results

    @classmethod
    def find_aliases(cls, lines: List[str]) -> List[Tuple[int, str, str]]:
        """返回 (行号, dst, src); 过滤注释行/数字常量/解引用赋值."""
        aliases = []
        for i, raw_line in enumerate(lines, start=1):
            s = cls._strip_comments(raw_line).strip()
            if not s:
                continue
            # 跳过解引用赋值: *var = expr;
            if s.startswith('*'):
                continue
            if not s.startswith(('if', 'while', 'for')):
                m = cls._ALIAS_RE.search(s)
                if m:
                    dst, src = m.group(1), m.group(2)
                    if dst != src and not dst.startswith(('if', 'while', 'for', 'return')) \
                            and not re.match(r'^\d+$', src) \
                            and src not in cls._NON_PTR:
                        aliases.append((i, dst, src))
        return aliases

    @classmethod
    def find_uses(cls, lines: List[str],
                   freed_vars: List[str]) -> List[Tuple[int, int, str]]:
        """返回 (行号, 列偏移, 变量名); 过滤注释行."""
        uses = []
        freed_set = set(freed_vars)
        for i, raw_line in enumerate(lines, start=1):
            line = cls._strip_comments(raw_line)
            if not line.strip():
                continue
            for m in cls._USE_RE.finditer(line):
                v = m.group(1) or m.group(2) or m.group(3) or m.group(4)
                if m.group(1):  # **pp → *pp
                    v = '*' + v
                if re.search(rf'\b(?:free|kfree|delete)\s*\(\s*\*?'
                             rf'{re.escape(v)}(?:\s*[\[\)])', line):
                    continue
                uses.append((i, m.start(), v))
            for mw in re.finditer(r'\b([a-z_]\w*)\b', line):
                w = mw.group(1)
                if w not in freed_set or w in cls._NON_PTR:
                    continue
                if line[mw.end():].lstrip().startswith('='):
                    continue
                if line[:mw.start()].rstrip().endswith('='):
                    continue
                if re.search(rf'\b(?:free|kfree|delete)\s*\(\s*\*?'
                             rf'{re.escape(w)}(?:\s*[\[\)])', line):
                    continue
                uses.append((i, mw.start(), w))
        return uses

    # 别名闭包

    @staticmethod
    def build_alias_closure(
            aliases: List[Tuple[int, str, str]]) -> Dict[str, Set[str]]:
        """Union-Find构建别名等价类."""
        p: Dict[str, str] = {}
        def f(x):
            if x not in p: p[x] = x
            if p[x] != x: p[x] = f(p[x])
            return p[x]
        for _, d, s in aliases:
            rd, rs = f(d), f(s)
            if rd != rs: p[rd] = rs
        closure: Dict[str, Set[str]] = {}
        for v in set(p.keys()):
            closure.setdefault(f(v), set()).add(v)
        return closure

    @staticmethod
    def resolve_var(var: str, alias_closure: Dict[str, Set[str]]) -> Set[str]:
        """展开变量的别名等价类."""
        result = {var}
        for members in alias_closure.values():
            if var in members:
                result |= members
        return result


__all__ = ['TemporalScanner']
