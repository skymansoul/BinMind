"""DFC-PV 事件提取器 — 从源码构建 AllocSite/FreeSite/AliasEdge/NullAssign/ReallocSite.

逐字符扫描器识别多语句同行、单行函数体、指针解引用赋值、多行注释.
预处理阶段展开 #define 宏以正确追踪宏内 free.
"""
from __future__ import annotations

import re
from typing import Dict, List, Tuple, Set

from analysis.dfc_pv_types import (
    AllocSite, FreeSite, AliasEdge, NullAssign, ReallocSite)
from analysis.dfc_pv_preprocess import (
    expand_macros, strip_comments, split_statements)

_FREE_RE = re.compile(r'\bfree\s*\(\s*([^)]+)\s*\)\s*;?')
_ALLOC_RE = re.compile(r'\b(malloc|calloc|realloc)\s*\(')
_ASSIGN_RE = re.compile(
    r'([\*\w\[\]\.>\-]+?)\s*=\s*([^;]+);')
_MEMCPY_RE = re.compile(r'memcpy\s*\(\s*([^,]+)\s*,\s*([^,]+)\s*,')
_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed|static|const|inline|size_t)\s+'
    r'(?:\w+\s*\*?\s+)?(\w+)\s*\(\s*([^)]*)\s*\)\s*\{?')
_LOOP_RE = re.compile(r'\b(?:for|while)\s*\(')
_NON_VAR = frozenset({
    'if', 'else', 'while', 'for', 'return', 'int', 'char', 'void', 'long',
    'short', 'float', 'double', 'size_t', 'unsigned', 'signed', 'static',
    'const', 'sizeof', 'NULL', 'nullptr', 'malloc', 'calloc', 'realloc',
    'free', 'printf', 'main', 'include', 'struct', 'typedef', 'switch',
    'case', 'default', 'goto', 'break', 'continue', 'exit'})


def extract_events(source: str) -> Tuple[List[AllocSite], List[FreeSite],
                                           List[AliasEdge], List[NullAssign],
                                          List[ReallocSite],
                                          Dict[str, Tuple[int, int, List[str]]]]:
    """从源码提取全部事件."""
    expanded = expand_macros(source)
    cleaned = strip_comments(expanded)
    lines = cleaned.splitlines()

    func_map = _build_func_map(lines)

    allocs: List[AllocSite] = []
    frees: List[FreeSite] = []
    aliases: List[AliasEdge] = []
    nulls: List[NullAssign] = []
    reallocs: List[ReallocSite] = []

    for i, raw_line in enumerate(lines, start=1):
        text = raw_line.strip()
        if not text or text.startswith('#'):
            continue

        stmts = split_statements(text)
        for stmt in stmts:
            stmt = stmt.strip()
            if not stmt:
                continue

            # 分配点
            alloc_m = _ALLOC_RE.search(stmt)
            assign_m = re.search(
                r'([\*\w\[\]\.>\-]+?)\s*=\s*(?!.*\b(?:for|while|if)\b)', stmt)
            if alloc_m and assign_m:
                var = assign_m.group(1).strip()
                bv = _base_var(var)
                if bv and bv not in _NON_VAR:
                    allocs.append(AllocSite(line=i, var=var))
                    reallocs.append(ReallocSite(line=i, var=var))

            # free 调用
            for fm in _FREE_RE.finditer(stmt):
                var_expr = fm.group(1).strip().rstrip(';')
                bv = _base_var(var_expr)
                if bv and bv not in _NON_VAR:
                    func = _enclosing_func(i, func_map)
                    frees.append(FreeSite(
                        line=i, var_expr=var_expr, base_var=bv, func=func))

            # NULL 赋值
            for am in _ASSIGN_RE.finditer(stmt):
                lhs, rhs = am.group(1).strip(), am.group(2).strip()
                if rhs in ('NULL', 'nullptr', '0', '((void *)0)'):
                    bv = _base_var(lhs)
                    if bv and bv not in _NON_VAR:
                        conditional = _is_conditional(i, lines)
                        nulls.append(NullAssign(
                            line=i, var=bv, conditional=conditional))

            # 别名赋值 (跳过 malloc 和 NULL 赋值)
            if _ALLOC_RE.search(stmt):
                continue
            for am in _ASSIGN_RE.finditer(stmt):
                lhs, rhs = am.group(1).strip(), am.group(2).strip()
                if rhs in ('NULL', 'nullptr', '0', '((void *)0)'):
                    continue
                lb, rb = _base_var(lhs), _base_var(rhs)
                if not lb or not rb or lb == rb:
                    continue
                if lb in _NON_VAR or rb in _NON_VAR:
                    continue

                kind = _classify_alias(lhs, rhs, stmt)
                aliases.append(AliasEdge(
                    source=rb, target=lb, line=i, kind=kind))

            # memcpy 别名
            for mm in _MEMCPY_RE.finditer(stmt):
                dst, src = mm.group(1).strip(), mm.group(2).strip()
                dst = dst.lstrip('&').strip()
                src = src.lstrip('&').strip()
                db, sb = _base_var(dst), _base_var(src)
                if db and sb and db not in _NON_VAR and sb not in _NON_VAR:
                    aliases.append(AliasEdge(
                        source=sb, target=db, line=i, kind='memcpy'))

    return allocs, frees, aliases, nulls, reallocs, func_map


def _classify_alias(lhs: str, rhs: str, stmt: str) -> str:
    if '->' in lhs or '->' in rhs:
        return 'field'
    if re.search(r'\w+\s*\[', stmt):
        return 'array'
    if 'memcpy' in stmt:
        return 'memcpy'
    if '+' in rhs or '-' in rhs:
        return 'arith'
    return 'assign'


def _base_var(expr: str) -> str:
    e = expr.strip().lstrip('*').strip()
    while e.startswith('(') and e.endswith(')'):
        e = e[1:-1].strip()
    if '->' in e:
        return e.split('->')[-1].strip()
    if '.' in e and not e.startswith('.'):
        return e.split('.')[-1].strip()
    m = re.match(r'(\w+)', e)
    return m.group(1) if m else ''


def _is_conditional(line: int, lines: List[str]) -> bool:
    depth = 0
    for i in range(min(line - 1, len(lines))):
        t = lines[i]
        depth += t.count('{') - t.count('}')
    for i in range(min(line - 2, len(lines) - 1), -1, -1):
        t = lines[i].strip()
        if re.match(r'(?:if|else|for|while|switch)\b', t):
            return True
        if t.count('{') and depth <= 0:
            break
    return False


def _build_func_map(lines: List[str]) -> Dict[str, Tuple[int, int, List[str]]]:
    fmap: Dict[str, Tuple[int, int, List[str]]] = {}
    full = '\n'.join(lines)
    for m in _FUNC_DEF_RE.finditer(full):
        name = m.group(1)
        # func_map 需要包含全部函数 (含 main), 仅排除 C 关键字/类型名
        _TYPE_KW = frozenset({
            'int', 'char', 'void', 'long', 'short', 'float', 'double',
            'size_t', 'unsigned', 'signed', 'static', 'const', 'struct',
            'if', 'else', 'while', 'for', 'switch', 'case', 'default',
            'return', 'break', 'continue', 'goto', 'sizeof', 'typedef'})
        if name in _TYPE_KW:
            continue
        start = full[:m.start()].count('\n') + 1
        ps = m.group(2)
        params = []
        if ps.strip() and ps.strip() != 'void':
            for p in ps.split(','):
                pm = re.search(r'(\w[\w]*)\s*$', p.strip())
                if pm and pm.group(1) not in _NON_VAR:
                    params.append(pm.group(1))
        # 精确计算函数体范围: 从 start 行开始追踪大括号深度
        start_text = lines[start - 1] if start - 1 < len(lines) else ''
        start_has_brace = '{' in start_text
        depth = 0
        end = start
        found_brace = start_has_brace
        for j in range(start, len(lines) + 1):
            line_text = lines[j - 1] if j - 1 < len(lines) else ''
            depth += line_text.count('{') - line_text.count('}')
            if depth > 0:
                found_brace = True
            if found_brace and depth <= 0 and j >= start:
                end = j
                break
        else:
            end = len(lines)
        fmap[name] = (start, max(end, start), params)
    return fmap


def _enclosing_func(line: int,
                    fm: Dict[str, Tuple[int, int, List[str]]]) -> str:
    best = None
    bs = 0
    for name, (s, e, _) in fm.items():
        if s <= line <= e and s > bs:
            best = name
            bs = s
    return best or ""
