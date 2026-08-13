"""
FOVF 通用解析辅助.

正则常量、函数签名/调用点解析、顶层参数切分、用户源判定等
纯工具函数, 供 fovf_argflow 使用.
"""

import re
from typing import Dict, List, Tuple

_INPUT_SOURCES = frozenset((
    'gets', 'fgets', 'scanf', 'fscanf', 'sscanf', 'recv', 'recvfrom',
    'read', 'getenv', 'argv', 'argc', 'getline', 'strdup', 'strndup',
))
_CONST_WRITE_FUNCS = frozenset(('strcpy', 'strncpy', 'sprintf',
                                'snprintf', 'memcpy', 'memmove',
                                'vsnprintf', 'vsprintf', 'strcat',
                                'strncat', 'strlcat'))
# 危险说明符: %n (写), %x (泄露), %s (泄露), 含长度/宽度修饰
_DANGER_SPEC = re.compile(r'%[-+ 0-9.#]*[hl]*[nxs]')
# 关键位置: 各函数的格式参数位置 (0 起)
_FMT_POS = {'printf': 0, 'fprintf': 1, 'sprintf': 1, 'snprintf': 2,
            'dprintf': 1, 'syslog': 1, 'vsprintf': 1, 'vsnprintf': 2,
            'vprintf': 0, 'vfprintf': 1, 'vprintk': 0, 'printk': 0,
            'panic': 0}

def fmt_position(func: str) -> int:
    return _FMT_POS.get(func, 0)


def split_top(args: str) -> List[str]:
    """按顶层逗号切分参数, 忽略括号内逗号."""
    parts, depth, cur = [], 0, []
    for ch in args:
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
        if ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return parts


def paren_inner(line: str, open_idx: int) -> str:
    """取 open_idx 处 '(' 的匹配闭括号内部内容; 无匹配返回空串."""
    depth = 0
    for i in range(open_idx, len(line)):
        ch = line[i]
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0:
                return line[open_idx + 1:i]
    return ''


def find_close_paren(line: str, open_idx: int) -> int | None:
    depth = 0
    for i in range(open_idx, len(line)):
        ch = line[i]
        if ch in '([{':
            depth += 1
        elif ch in ')]}':
            depth -= 1
            if depth == 0:
                return i
    return None


def signature_params(ir: List[str]) -> Dict[str, List[str]]:
    """函数签名形参名 (去掉类型只留名字)."""
    sig_re = re.compile(r'^[A-Za-z_][\w \*]*\b(\w+)\s*\(([^)]*)\)\s*\{')
    out: Dict[str, List[str]] = {}
    for line in ir:
        m = sig_re.match(line.strip())
        if not m:
            continue
        params = []
        for part in m.group(2).split(','):
            part = part.strip()
            nm = re.search(r'\b([a-z_]\w*)\s*$', part)
            if nm:
                params.append(nm.group(1))
        out[m.group(1)] = params
    return out


def call_args(ir: List[str]) -> Dict[str, List[Tuple[str, int]]]:
    """调用点实参: 函数名 -> [(实参表达式, 位置)].

    用括号匹配取实参, 跳过函数定义 (闭括号后为 `{`) 与控制流.
    """
    call_re = re.compile(r'\b([a-z_]\w*)\s*\(')
    skip = ('if', 'while', 'for', 'switch', 'sizeof', 'return',
            'main', 'else')
    out: Dict[str, List[Tuple[str, int]]] = {}
    for line in ir:
        for m in call_re.finditer(line):
            fname = m.group(1)
            if fname in skip:
                continue
            close = find_close_paren(line, m.end() - 1)
            if close is None:
                continue
            after = line[close + 1:].lstrip()
            if after.startswith('{'):
                continue  # 函数定义
            inner = line[m.end():close]
            args = [a.strip() for a in split_top(inner)]
            for i, a in enumerate(args):
                out.setdefault(fname, []).append((a, i))
    return out


def is_main_ptr_param(name: str, line: str) -> bool:
    """name 是否为 main 签名中的指针形参."""
    if not re.search(r'^int\s+main\s*\(', line.strip()):
        return False
    return bool(re.search(r'\*\s*' + re.escape(name) + r'\b', line)
                or re.search(re.escape(name) + r'\s*\[', line))


def is_user_expr(expr: str, ir: List[str]) -> bool:
    """表达式是否直接来自用户输入源."""
    expr = expr.strip()
    if expr.startswith('argv') or expr == 'argc':
        return True
    if re.fullmatch(r'[a-z_]\w*', expr) and ir:
        if any(is_main_ptr_param(expr, l) for l in ir):
            return True
    m = re.fullmatch(r'(\w+)\s*\[[^\]]*\]', expr)
    if m:
        if m.group(1) in ('argv', 'envp', 'environ'):
            return True
        if ir and any(is_main_ptr_param(m.group(1), l) for l in ir):
            return True
    for src in _INPUT_SOURCES:
        if re.fullmatch(rf'{src}\s*\(.*', expr) or \
           re.fullmatch(rf'\w+\s*=\s*{src}\s*\(.*', expr):
            return True
    return False


def user_or_unknown(src: str, ir: List[str]) -> str:
    if is_user_expr(src, ir):
        return 'user'
    if src.startswith('"'):
        return 'const'
    return 'unknown'


def has_var_rhs(line: str) -> bool:
    """行内赋值右值是否为变量 (非字符常量)."""
    m = re.search(r'=\s*(.+)$', line)
    return bool(m) and not m.group(1).strip().startswith("'")


# 合并前的 helpers 以带下划线别名暴露, 维持既有接口
_fmt_position = fmt_position
_split_top = split_top
_paren_inner = paren_inner
_signature_params = signature_params
_call_args = call_args
_is_user_expr = is_user_expr
_user_or_unknown = user_or_unknown

# 兼容别名: 合并前以下划线命名对外暴露
_fmt_position = fmt_position
_split_top = split_top
_paren_inner = paren_inner
_signature_params = signature_params
_call_args = call_args
_is_user_expr = is_user_expr
_user_or_unknown = user_or_unknown
