"""
FSTP 管线阶段 — Phase 2-5 污点扫描/传播/清理/分类 + 格式调用发现.


FSTP 语义分类 (5级):
  SEM_CLEAN     (0): 常量字符串, 无格式说明符 → 绝对安全
  SEM_CONST_FMT (1): 常量但有格式说明符 → 有意图的格式化, 安全
  SEM_USER_SAFE (2): 用户输入但被清理 (%% 替换等) → 安全
  SEM_USER_READ (3): 用户输入, 可能含 %s/%x/%p → 信息泄露
  SEM_USER_WRITE(4): 用户输入, 可能含 %n/%hn → 代码执行 (最高风险)
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple


# 用户输入源 — (函数名, 被污染参数位置)
_INPUT_SRCS = {
    'scanf':   [1, 2, 3, 4, 5],
    'fscanf':  [2, 3, 4, 5],
    'sscanf':  [2, 3, 4, 5],
    'fgets':   [0],
    'gets':    [0],
    'getenv':  [-1],
    'recv':    [1],
    'recvfrom':[1],
    'recvmsg': [1],
    'read':    [1],
    'fread':   [0],
    'getline': [0],
    'getdelim':[0],
}

# 直接输入数组 (不需要函数调用)
_INPUT_ARRAYS = {'argv', 'environ', '__argv'}

# 格式说明符 — 按危险等级分类
_WRITE_SPECS = {'%n', '%hn', '%ln', '%lln'}
_READ_SPECS = {'%s', '%x', '%p', '%lx', '%llx',
               '%d', '%u', '%ld', '%lu', '%lld', '%llu',
               '%c', '%f', '%e', '%g', '%o', '%i'}

# 格式函数及其格式参数位置
_FMT_FUNCS = {
    'printf', 'fprintf', 'dprintf', 'sprintf', 'snprintf',
    'syslog', 'vsyslog', 'err', 'warn', 'errx', 'warnx',
    'setproctitle', 'vwarn', 'verr', 'vwarnx', 'verrx',
}

_FMT_ARG_POS = {
    'printf': 0, 'fprintf': 1, 'dprintf': 1,
    'sprintf': 1, 'snprintf': 2,
    'syslog': 1, 'vsyslog': 1,
    'err': 1, 'warn': 1, 'errx': 1, 'warnx': 1,
    'setproctitle': 0,
    'vwarn': 0, 'verr': 0, 'vwarnx': 0, 'verrx': 0,
}


def _split_top_level(text: str) -> List[str]:
    """按顶层逗号分割 (忽略括号内的逗号)."""
    parts = []
    depth = 0
    current = []
    for ch in text:
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(current).strip())
            current = []
        else:
            current.append(ch)
    if current:
        parts.append(''.join(current).strip())
    return parts


# Phase 2: 用户输入源污点

def scan_taint_sources(lines: List[str], tainted_vars: Dict,
                       sem_class_user_write) -> None:
    """识别来自用户输入的变量 (位置感知). 直接修改 tainted_vars."""
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # 检查直接输入数组 (argv[i], environ[i])
        for arr in _INPUT_ARRAYS:
            if re.search(rf'\b{arr}\s*\[', stripped):
                m = re.match(r'(\w+)\s*=\s*' + arr, stripped)
                if m:
                    tainted_vars[m.group(1)] = sem_class_user_write

        # 检查输入源函数
        for func, tainted_positions in _INPUT_SRCS.items():
            if not re.search(rf'\b{func}\s*\(', stripped):
                continue

            m = re.search(
                rf'{func}\s*\(((?:[^()]|\([^)]*\))*)\)', stripped)
            if not m:
                continue
            args = _split_top_level(m.group(1))
            args = [re.sub(r'^&', '', a).strip() for a in args]

            if -1 in tainted_positions:
                lhs = re.search(r'\b(\w+)\s*=\s*' + func, stripped)
                if not lhs:
                    lhs = re.search(
                        r'(?:char\s*\*|void\s*\*|const\s+char\s*\*)\s*'
                        r'(\w+)\s*=\s*' + func, stripped)
                if not lhs:
                    lhs = re.search(
                        r'(\w+)\s*=\s*\(\s*(?:char|void|const)\s*\*\s*\)'
                        r'\s*' + func, stripped)
                if lhs:
                    var = lhs.group(1)
                    tainted_vars[var] = sem_class_user_write
            else:
                for pos in tainted_positions:
                    if pos < len(args):
                        var = args[pos]
                        var = re.sub(r'\([^)]*\)', '', var).strip()
                        if re.match(r'^\w+$', var):
                            tainted_vars[var] = sem_class_user_write
                        lhs = re.match(r'(\w+)\s*=', stripped)
                        if lhs and pos == 0:
                            tainted_vars[lhs.group(1)] = sem_class_user_write


# Phase 3: 污点传播 (含赋值链)

def propagate_taint(lines: List[str], tainted_vars: Dict) -> None:
    """固定点传播污点至多跳. 直接修改 tainted_vars."""
    changed = True
    max_iter = 20
    while changed and max_iter > 0:
        max_iter -= 1
        changed = False
        for line in lines:
            stripped = line.strip()
            # 直接赋值: a = b
            m = re.search(r'\b(\w+)\s*=\s*(\w+)\s*;?\s*$', stripped)
            if m:
                dst, src = m.group(1), m.group(2)
                if src in tainted_vars:
                    old = tainted_vars.get(dst)
                    new = tainted_vars[src]
                    if old != new:
                        tainted_vars[dst] = new
                        changed = True
            # snprintf/sprintf(a, ..., fmt, ...) → a承袭fmt的语义
            m = re.search(r'(?:snprintf|sprintf)\s*\(\s*(\w+)\s*,', stripped)
            if m:
                dst = m.group(1)
                args_str = re.search(
                    r'(?:snprintf|sprintf)\s*\('
                    r'((?:[^()]|\([^)]*\))*)'
                    r'\)', stripped)
                if args_str:
                    raw = args_str.group(1)
                    args = _split_top_level(raw)
                    if len(args) >= 3:
                        fmt_pos = 2
                        fmt_var = re.sub(r'\([^)]*\)', '', args[fmt_pos])
                        fmt_var = fmt_var.strip()
                        if fmt_var in tainted_vars:
                            tainted_vars[dst] = tainted_vars[fmt_var]
                            changed = True


# Phase 4: 清理模式检测

def detect_sanitizers(lines: List[str], tainted_vars: Dict,
                      sanitized_vars: Dict, sem_class_user_safe) -> None:
    """检测清理操作: %%替换, sanitize(), 输入验证. 直接修改 dicts."""
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()

        # 模式1: var = sanitizer(input) → var 被清理
        for pat in [
            (r'(\w+)\s*=\s*g_strdup_printf\s*\(\s*"%s"\s*,', 0.90),
            (r'(\w+)\s*=\s*(?:escape|quote)_format\s*\(', 0.90),
            (r'(\w+)\s*=\s*sanitize\s*\(', 0.80),
            (r'(\w+)\s*=\s*filter\s*\(', 0.70),
            (r'(\w+)\s*=\s*validate\s*\(', 0.75),
        ]:
            m = re.search(pat[0], stripped)
            if m:
                output_var = m.group(1)
                sanitized_vars[output_var] = lineno
                tainted_vars[output_var] = sem_class_user_safe
                break

        # 模式2: strreplace(buf, "%", "%%") → buf 被原地清理
        m = re.search(
            r'strreplace\s*\(\s*(\w+)\s*,\s*"%"\s*,\s*"%%"', stripped)
        if m:
            var = m.group(1)
            sanitized_vars[var] = lineno
            tainted_vars[var] = sem_class_user_safe
            continue

        # 模式3: str_replace(buf, "%", "%%")
        m = re.search(
            r'str_replace\s*\(\s*(\w+)\s*,\s*"%"\s*,\s*"%%"', stripped)
        if m:
            var = m.group(1)
            sanitized_vars[var] = lineno
            tainted_vars[var] = sem_class_user_safe
            continue

        # 模式4: sanitize(var) — 原地清理
        m = re.search(r'\bsanitize\s*\(\s*(\w+)\s*\)', stripped)
        if m:
            var = m.group(1)
            sanitized_vars[var] = lineno
            tainted_vars[var] = sem_class_user_safe
            continue

        # 模式5: validate(var)
        m = re.search(r'\bvalidate\s*\(\s*(\w+)\s*\)', stripped)
        if m:
            var = m.group(1)
            sanitized_vars[var] = lineno
            tainted_vars[var] = sem_class_user_safe


# Phase 5: 语义分类

def classify_semantics(lines: List[str], tainted_vars: Dict,
                       sem_class_user_write, sem_class_user_read) -> None:
    """根据格式说明符类型对污点变量做语义分类. 直接修改 tainted_vars."""
    for var, cls in list(tainted_vars.items()):
        if cls == sem_class_user_write:
            for lineno, line in enumerate(lines, 1):
                stripped = line.strip()
                if var not in stripped:
                    continue
                if re.search(rf'scanf\s*\(\s*{var}\b', stripped):
                    tainted_vars[var] = sem_class_user_write
                    break
                if re.search(rf'fgets\s*\(\s*{var}\b', stripped):
                    tainted_vars[var] = sem_class_user_read
                    break
                if re.search(rf'(?:read|recv)\s*\([^,]+,\s*{var}\b',
                            stripped):
                    tainted_vars[var] = sem_class_user_write
                    break


# 格式调用发现

def discover_fmt_calls(lines: List[str]) -> List[Tuple[int, str, str]]:
    """自动发现格式函数调用. 返回 [(line_no, func_name, fmt_arg), ...]."""
    calls = []
    for lineno, line in enumerate(lines, 1):
        stripped = line.strip()
        for func in _FMT_FUNCS:
            if not re.search(rf'\b{func}\s*\(', stripped):
                continue
            pos = _FMT_ARG_POS.get(func, 0)
            m = re.search(
                rf'{func}\s*\(((?:[^()]|\([^)]*\))*)\)', stripped)
            if not m:
                continue
            args = _split_top_level(m.group(1))
            if pos < len(args):
                fmt_arg = args[pos].strip()
                if fmt_arg.startswith('"'):
                    continue
                calls.append((lineno, func, fmt_arg))
    return calls


__all__ = [
    'scan_taint_sources', 'propagate_taint',
    'detect_sanitizers', 'classify_semantics',
    'discover_fmt_calls', '_split_top_level',
    '_INPUT_SRCS', '_INPUT_ARRAYS', '_FMT_FUNCS', '_FMT_ARG_POS',
]
