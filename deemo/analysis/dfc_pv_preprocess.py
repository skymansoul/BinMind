"""
DFC-PV 预处理模块 — 宏展开、注释移除、语句拆分.

使主提取器聚焦事件识别.
"""


import re
from typing import Dict, List, Tuple


def expand_macros(source: str) -> str:
    """展开简单 #define 宏."""
    defines: Dict[str, Tuple[List[str], str]] = {}
    lines = source.splitlines()
    result = []
    for line in lines:
        stripped = line.strip()
        m = re.match(r'#define\s+(\w+)\s*\(([^)]*)\)\s*(.+)', stripped)
        if m:
            name, params_str, body = m.groups()
            params = [p.strip() for p in params_str.split(',') if p.strip()]
            defines[name] = (params, body)
            result.append(line)
            continue
        m2 = re.match(r'#define\s+(\w+)\s+(.+)', stripped)
        if m2:
            defines[m2.group(1)] = ([], m2.group(2))
            result.append(line)
            continue
        result.append(line)
    expanded = '\n'.join(result)
    for name, (params, body) in defines.items():
        if not params:
            pattern = re.compile(rf'\b{re.escape(name)}\b')
            expanded = pattern.sub(body, expanded)
        else:
            call_re = re.compile(rf'\b{re.escape(name)}\s*\(([^)]*)\)')
            def replacer(m):
                args = [a.strip() for a in m.group(1).split(',')]
                repl = body
                for i, p in enumerate(params):
                    if i < len(args):
                        repl = repl.replace(p, args[i])
                return repl
            expanded = call_re.sub(replacer, expanded)
    return expanded


def strip_comments(source: str) -> str:
    """移除单行和多行注释."""
    result = []
    in_block_comment = False
    for line in source.splitlines():
        if in_block_comment:
            end = line.find('*/')
            if end >= 0:
                line = line[end + 2:]
                in_block_comment = False
            else:
                result.append('')
                continue
        stripped = []
        i = 0
        while i < len(line):
            if i + 1 < len(line) and line[i:i+2] == '//':
                break
            if i + 1 < len(line) and line[i:i+2] == '/*':
                end = line.find('*/', i + 2)
                if end >= 0:
                    i = end + 2
                    continue
                else:
                    in_block_comment = True
                    break
            stripped.append(line[i])
            i += 1
        result.append(''.join(stripped))
    return '\n'.join(result)


def split_statements(line: str) -> List[str]:
    """将同行多语句拆分为独立语句."""
    stmts = []
    current = []
    depth = 0
    for ch in line:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ';' and depth <= 0:
            s = ''.join(current).strip()
            if s:
                stmts.append(s + ';')
            current = []
        else:
            current.append(ch)
    rem = ''.join(current).strip()
    if rem:
        stmts.append(rem)
    return stmts


__all__ = ['expand_macros', 'strip_comments', 'split_statements']
