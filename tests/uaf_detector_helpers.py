"""
时序-别名-可达-路径验证 UAF 检测辅助 — 全局别名映射 / 变量提取 / 别名展开。

"""
import re
from typing import Dict, List


def _build_global_alias_map(source: str) -> Dict[str, List[str]]:
    """构建函数→全局变量的别名映射。

    检测模式: void func(T *param) { g_var = param; }
    支持单行函数: void f(T *p) { g = p; }
    返回: {func_name: [global_var1, global_var2, ...]}
    """
    gam = {}
    lines = source.splitlines()

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()

        # 单行函数: void func(T *param) { g_var = param; ... }
        oneliner_m = re.match(
            r'(?:void|int|static\s+void|static\s+int)\s+'
            r'(\w+)\s*\([^)]*\)\s*\{(.+)\}\s*$', line)
        if oneliner_m:
            func_name = oneliner_m.group(1)
            body = oneliner_m.group(2)
            for stmt in body.split(';'):
                stmt = stmt.strip()
                gm = re.match(r'(\w+)\s*=\s*(\w+)\s*$', stmt)
                if gm:
                    lhs = gm.group(1)
                    if not re.match(r'(?:char|int|void|size_t|long|short'
                                    r'|unsigned|float|double|static|const'
                                    r'|uint\w+_t|int\w+_t)\s', stmt):
                        gam.setdefault(func_name, []).append(lhs)
            continue

        # 多行函数: void func(T *param) {
        fm = re.match(
            r'(?:void|int|static\s+void|static\s+int)\s+'
            r'(\w+)\s*\([^)]*\)\s*\{?\s*$', line)
        if fm and '{' in line:
            func_name = fm.group(1)
            after_brace = line[line.index('{') + 1:].strip()
            if after_brace:
                for stmt in after_brace.split(';'):
                    stmt = stmt.strip()
                    gm = re.match(r'(\w+)\s*=\s*(\w+)\s*$', stmt)
                    if gm:
                        lhs = gm.group(1)
                        if not re.match(r'(?:char|int|void|size_t|long|short'
                                        r'|unsigned|float|double|static|const'
                                        r'|uint\w+_t|int\w+_t)\s', stmt):
                            gam.setdefault(func_name, []).append(lhs)

    return gam


def _extract_base_name(ptr_expr: str) -> str:
    """从 ptr 表达式提取基变量名。
    arr[i] → arr, p->field → p, *p → p, p → p
    """
    m = re.match(r'(\w+)\[', ptr_expr)
    if m: return m.group(1)
    m = re.match(r'(\w+)\s*->', ptr_expr)
    if m: return m.group(1)
    return ptr_expr.strip()


# 解引用/成员访问 / 函数调用参数
_DEREF_USE_RE = re.compile(
    r'(?:^|[=,;{}(!\s])\*\s*(\w+)\b'
    r'|(\w+)\s*->\s*\w+'
    r'|(\w+)\s*\[[^\]]*\]'
)

_FUNC_ARG_USE_RE = re.compile(
    r'(?:printf|fprintf|sprintf|snprintf|puts|strcpy|strcat|strncpy|strncat'
    r'|memcpy|memmove|memset|strlen|strcmp|strdup|send|write|read|recv'
    r'|free|munmap|realloc)\s*\(',
    re.IGNORECASE,
)

_ARG_VAR_RE = re.compile(r'\b(\w+)\b')


def _extract_used_vars(line: str) -> set:
    """从一行 C 代码中提取所有被"使用"的变量名。

    规则:
      - *p, p->, p[ → 解引用使用
      - printf("..", p, q, ...) → 所有参数中的变量
      - strcpy(p, ...) → p 被写入, 不算"使用"
      - free(p), munmap(p) → 不算使用
    """
    used = set()

    # (A) 解引用/成员访问
    for m in _DEREF_USE_RE.finditer(line):
        for g in m.groups():
            if g:
                used.add(g)

    # (B) 函数调用参数
    fm = _FUNC_ARG_USE_RE.search(line)
    if fm:
        call_start = fm.end() - 1
        args_str = _extract_args_string(line, call_start)
        if args_str:
            for vm in _ARG_VAR_RE.finditer(args_str):
                var = vm.group(1)
                if var not in ('NULL', 'sizeof', 'char', 'int', 'void',
                               'size_t', 'unsigned', 'long', 'short',
                               'const', 'static', 'volatile', 'struct',
                               'if', 'for', 'while', 'return', 'else',
                               'switch', 'case', 'default', 'break',
                               'continue', 'goto', 'typedef', 'enum'):
                    used.add(var)

    return used


def _extract_args_string(line: str, paren_pos: int) -> str:
    """从 '(' 位置提取匹配的 ')' 内的参数字符串。"""
    if line[paren_pos] != '(':
        return ''
    depth = 0
    start = paren_pos
    for i, ch in enumerate(line[paren_pos:], paren_pos):
        if ch == '(':
            depth += 1
        elif ch == ')':
            depth -= 1
            if depth == 0:
                return line[start + 1:i]
    return ''


def _resolve_aliases(var: str, alias_map: Dict[str, List[str]]) -> set:
    """递归展开别名: q→p 时, resolve(q) = {p} (含传递闭包)。"""
    result = set()
    if var not in alias_map:
        return result
    for target in alias_map.get(var, []):
        result.add(target)
        result |= _resolve_aliases(target, alias_map)
    return result
