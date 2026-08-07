"""
FCPV 约束收集器辅助模块 — 常量、正则模式、工具函数、污点源检测.

"""
from __future__ import annotations

import re
from collections import deque
from typing import Dict, List, Set, Tuple

from core.fcpv_constraint_types import TaintState  # noqa: F401

# printf 族函数 → 格式参数索引 (0=第一参数)
_FMT_ARG_INDEX: Dict[str, int] = {
    'printf': 0, 'vprintf': 0, 'wprintf': 0,
    'fprintf': 1, 'vfprintf': 1, 'dprintf': 1, 'fwprintf': 1,
    'sprintf': 1, 'vsprintf': 1, 'swprintf': 1,
    'snprintf': 2, 'vsnprintf': 2, 'snwprintf': 2,
    'syslog': 1, 'vsyslog': 1,
    'err': 1, 'warn': 1, 'errx': 1, 'warnx': 1,
}

_SINK_RE = re.compile(
    r'\b(printf|fprintf|sprintf|snprintf|dprintf|syslog|vsyslog'
    r'|vprintf|vfprintf|vsprintf|vsnprintf|err|warn|errx|warnx'
    r'|wprintf|fwprintf|swprintf|snwprintf)\s*\(',
    re.IGNORECASE)

# 污点源函数 → 数据写入哪个参数 (0-indexed)
_TAINT_DST_PARAM: Dict[str, int] = {
    'fgets': 0, 'gets': 0, 'recv': 1, 'recvfrom': 1,
    'read': 1, 'fread': 0, 'fscanf': 1, 'sscanf': 1, 'scanf': 1,
}

# 间接数据传输函数 → (dst_param_idx, src_param_idx)
_XFER_FUNCS: Dict[str, Tuple[int, int]] = {
    'mbstowcs': (0, 1), 'wcstombs': (0, 1),
    'strcpy': (0, 1), 'strncpy': (0, 1),
    'strcat': (0, 1), 'strncat': (0, 1),
    'memcpy': (0, 1), 'memmove': (0, 1), 'bcopy': (1, 0),
}

_TAINT_RET_FUNCS = {'getenv': 0, 'malloc': 0, 'calloc': 0, 'realloc': 0}
_ARGV_RE = re.compile(r'argv\s*\[\s*\d+\s*\]')

_SANITIZE_RE = re.compile(
    r'(snprintf|sprintf)\s*\(\s*(\w[\w]*)\s*,', re.IGNORECASE)

_FUNC_DEF_RE = re.compile(
    r'(?:void|int|char|long|short|float|double|unsigned|signed'
    r'|static|const|inline|size_t|ssize_t)\s+'
    r'(?:\w+\s*\*?\s+)?(\w[\w]*)\s*\(\s*([^)]*)\s*\)\s*\{?')

_NON_VAR = frozenset({
    'if', 'else', 'while', 'for', 'do', 'switch', 'case', 'default',
    'goto', 'return', 'break', 'continue', 'sizeof', 'typedef',
    'struct', 'enum', 'union', 'static', 'const', 'volatile',
    'void', 'int', 'char', 'long', 'short', 'float', 'double',
    'unsigned', 'signed', 'size_t', 'ssize_t', 'NULL', 'nullptr',
    'free', 'malloc', 'calloc', 'realloc', 'strlen', 'strcmp',
    'strncmp', 'memcmp', 'memcpy', 'memset', 'strcpy', 'strncpy',
    'strcat', 'strncat', 'printf', 'fprintf', 'sprintf', 'snprintf',
    'dprintf', 'syslog', 'fgets', 'gets', 'scanf', 'fscanf',
    'getenv', 'fread', 'recv', 'recvfrom', 'read', 'exit',
    'main', 'include', 'stdin', 'stdout', 'stderr', 'LOG_ERR',
    'LOG_INFO', 'LOG_WARNING', 'LOG_DEBUG', 'openlog', 'closelog',
})


def _extract_nth_arg(text: str, n: int) -> str:
    """手动平衡括号提取第 n 参数 (0-indexed)."""
    p = text.find('(')
    if p < 0:
        return ''
    s = text[p + 1:]
    depth = 0
    a0 = 0
    ai = 0
    for idx, ch in enumerate(s):
        if ch == '(':
            depth += 1
        elif ch == ')':
            if depth == 0:
                return s[a0:idx].strip() if ai == n else ''
            depth -= 1
        elif ch == ',' and depth == 0:
            if ai == n:
                return s[a0:idx].strip()
            ai += 1
            a0 = idx + 1
    return ''


def _extract_nth_arg_from_call(text: str, func_name: str, n: int) -> str:
    """从指定函数调用的括号内提取第 n 参数.

    先定位 func_name 的位置, 再从其后的 '(' 开始提取.
    避免误匹配外层 if/while 的括号.
    """
    fm = re.search(rf'\b{re.escape(func_name)}\s*\(', text, re.IGNORECASE)
    if not fm:
        return ''
    p = text.index('(', fm.end() - 1)
    s = text[p + 1:]
    depth = 0
    a0 = 0
    ai = 0
    for idx, ch in enumerate(s):
        if ch == '(':
            depth += 1
        elif ch == ')':
            if depth == 0:
                return s[a0:idx].strip() if ai == n else ''
            depth -= 1
        elif ch == ',' and depth == 0:
            if ai == n:
                return s[a0:idx].strip()
            ai += 1
            a0 = idx + 1
    return ''


def _is_str_literal(expr: str) -> bool:
    e = expr.strip()
    return (e.startswith('"') and e.endswith('"')) or \
           (e.startswith("'") and e.endswith("'"))


def _str_literal(expr: str) -> str:
    e = expr.strip()
    if len(e) >= 2 and e[0] == e[-1] and e[0] in ('"', "'"):
        return e[1:-1]
    return ''


def _extract_var(expr: str) -> str:
    """从表达式中提取主变量名."""
    m = re.match(r'(\w[\w]*)', re.sub(r'\([^)]*\)\s*', '', expr.strip()))
    return m.group(1) if m else ''


def find_taint_sources_impl(
    lines: List[str],
    tainted_set: Set[str],
) -> List[Tuple[int, str, str]]:
    """从源码行中提取污点源.

    三种模式:
      1. var = getenv(...) — 返回值赋值
      2. fgets(buf, ...) — 参数写入
      3. argv[N] — 命令行参数
      4. 间接数据传输: strcpy/memcpy/mbstowcs → dst 被 src 污染
    """
    sources: List[Tuple[int, str, str]] = []
    for i, line in enumerate(lines, start=1):
        text = line.strip()
        if text.startswith(('//', '/*')):
            continue
        # argv 模式
        if _ARGV_RE.search(text):
            am = re.search(r'(\w[\w]*)\s*=\s*argv\s*\[\s*\d+\s*\]', text)
            sources.append((i, 'argv', am.group(1) if am else 'argv'))
        for am in re.finditer(r'argv\s*\[\s*(\d+)\s*\]', text):
            sources.append((i, 'argv', f'argv[{am.group(1)}]'))
        # 参数写入型污点源
        for func, dst_idx in _TAINT_DST_PARAM.items():
            fm = re.search(rf'\b{re.escape(func)}\s*\(', text, re.IGNORECASE)
            if not fm:
                continue
            dst = _extract_nth_arg_from_call(text, func, dst_idx)
            if dst:
                var = _extract_var(dst)
                if var and var not in _NON_VAR:
                    sources.append((i, func, var))
            am = re.search(
                rf'(\w[\w]*)\s*=\s*{re.escape(func)}', text, re.IGNORECASE)
            if am and am.group(1) not in _NON_VAR:
                sources.append((i, func, am.group(1)))
        # 返回值型污点源
        for func in _TAINT_RET_FUNCS:
            am = re.search(
                rf'(\w[\w]*)\s*=\s*{re.escape(func)}\s*\(', text,
                re.IGNORECASE)
            if am and am.group(1) not in _NON_VAR:
                sources.append((i, func, am.group(1)))
        # 启发式: 名称含 recv/read/fetch 的函数
        if not _SINK_RE.search(text):
            w = re.findall(
                r'\b([a-z_]*recv[a-z_]*|[a-z_]*read[a-z_]*'
                r'|[a-z_]*fetch[a-z_]*)\b', text, re.IGNORECASE)
            if w:
                wfunc = w[0].lower()
                if wfunc not in _NON_VAR:
                    dst = _extract_nth_arg_from_call(text, wfunc, 1)
                    if dst:
                        var = _extract_var(dst)
                        if var and var not in _NON_VAR:
                            sources.append((i, wfunc, var))
        # 间接数据传输: strcpy/memcpy/mbstowcs
        for func, (dst_idx, src_idx) in _XFER_FUNCS.items():
            fm = re.search(rf'\b{re.escape(func)}\s*\(', text, re.IGNORECASE)
            if not fm:
                continue
            dst_arg = _extract_nth_arg_from_call(text, func, dst_idx)
            src_arg = _extract_nth_arg_from_call(text, func, src_idx)
            if not dst_arg or not src_arg:
                continue
            dst_var = _extract_var(dst_arg)
            src_var = _extract_var(src_arg)
            if dst_var and dst_var not in _NON_VAR:
                if src_var and (src_var in _ARGV_RE.findall(text) or
                                src_var.startswith('argv') or
                                'argv' in src_arg):
                    sources.append((i, func, dst_var))
                elif src_var and src_var in tainted_set:
                    sources.append((i, func, dst_var))
    return sources


__all__ = [
    '_FMT_ARG_INDEX', '_SINK_RE', '_TAINT_DST_PARAM', '_XFER_FUNCS',
    '_TAINT_RET_FUNCS', '_ARGV_RE', '_SANITIZE_RE', '_FUNC_DEF_RE',
    '_NON_VAR', '_extract_nth_arg', '_extract_nth_arg_from_call',
    '_is_str_literal', '_str_literal', '_extract_var',
    'find_taint_sources_impl',
]
