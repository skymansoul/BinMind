"""
IODS 整数溢出检测辅助 — 用户输入追踪 / 算术变量收集 / 跨函数算术返回。

"""
import re
from typing import Set

# 用户输入来源
_USER_INPUT_RE = re.compile(
    r'(\w+)\s*=\s*(?:atoi|atol|atoll|strtol|strtoul|strtoll|strtoull)'
    r'\s*\(\s*(?:argv\[\d+\]|[^)]+)\s*\)',
)
_USER_INPUT_ARGV_RE = re.compile(r'(\w+)\s*=\s*argv\[(\d+)\]')
_USER_INPUT_SCANF_RE = re.compile(r'(?:f?scanf)\s*\(\s*\w*\s*,?\s*"[^"]*"\s*,\s*&(\w+)')
_USER_INPUT_GETENV_RE = re.compile(r'(\w+)\s*=\s*getenv\s*\(')
_USER_INPUT_FGETS_RE = re.compile(r'fgets\s*\(\s*(\w+)\s*,')
_USER_INPUT_RECV_RE = re.compile(r'recv\s*\([^,]+,\s*(\w+)\s*,')
_USER_INPUT_TERNARY_RE = re.compile(
    r'(\w+)\s*=\s*[^?]+\?\s*(?:\(\s*\w+(?:\s+\w+)*\*?\s*\)\s*)?'
    r'(?:atoi|atol|strtol|strtoll|atoll)\s*\(\s*argv\[',
)
_USER_INPUT_CASTED_RE = re.compile(
    r'(\w+)\s*=\s*(?:\(\s*\w+(?:\s+\w+)*\*?\s*\)\s*)?'
    r'(?:atoi|atol|atoll|strtol|strtoll|strtoul|strtoull)\s*\(\s*argv\[',
)

# 算术表达式 (赋值右侧)
_MUL_EXPR_RE = re.compile(r'(\w+)\s*=\s*(.+?)\s*\*\s*(.+?)\s*;')
_ADD_EXPR_RE = re.compile(r'(\w+)\s*=\s*(.+?)\s*\+\s*(.+?)\s*;')
_SHL_EXPR_RE = re.compile(r'(\w+)\s*=\s*(.+?)\s*<<\s*(.+?)\s*;')

# 窄化类型转换
_NARROW_CAST_RE = re.compile(
    r'\(\s*(?:unsigned\s+)?(?:short|char|int8_t|int16_t|uint8_t|uint16_t'
    r'|int\s*32_t|uint\s*32_t|unsigned\s+int)\s*\)\s*(\w+)'
)

# 跨函数算术运算追踪
_CROSS_FUNC_ARITH_RE = re.compile(
    r'(?:size_t|int|long|unsigned(?:\s+(?:int|long))?)\s+'
    r'(\w+)\s*\(([^)]*)\)\s*\{',
)

def _find_user_input_vars(source: str) -> Set[str]:
    """追踪来自用户/外部输入的变量名 (通过赋值)。"""
    uv = set()

    for m in _USER_INPUT_ARGV_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_TERNARY_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_CASTED_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_SCANF_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_GETENV_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_FGETS_RE.finditer(source):
        uv.add(m.group(1))
    for m in _USER_INPUT_RECV_RE.finditer(source):
        uv.add(m.group(1))

    return uv

def _find_alloc_vars(source: str) -> Set[str]:
    """收集分配调用参数中出现的变量名。"""
    av = set()
    _alloc_expr_re = re.compile(
        r'(?:malloc|calloc|realloc|alloca)\s*\(\s*(.+?)\s*\)', re.IGNORECASE,
    )
    for m in _alloc_expr_re.finditer(source):
        args = m.group(1)
        av |= _extract_vars(args)
    return av

def _find_arith_result_vars(source: str) -> Set[str]:
    """收集算术运算 (乘/加/移位) 的结果变量名。"""
    av = set()
    for m in re.finditer(r'(\w+)\s*=\s*.+?\s*[\*\+\-<<]\s*.+?\s*;', source):
        av.add(m.group(1))
    return av

def _arith_uses_user_var(var: str, arith_vars: Set[str],
                         user_vars: Set[str], source: str) -> bool:
    """反向检查 var 的算术表达式是否涉及用户输入变量。"""
    m = re.search(rf'{re.escape(var)}\s*=\s*(.+?)\s*[\*\+\-<<]\s*(.+?)\s*;', source)
    if not m:
        return False
    left_vars = _extract_vars(m.group(1))
    right_vars = _extract_vars(m.group(2))
    return bool((left_vars | right_vars) & user_vars)

def _extract_vars(expr: str) -> Set[str]:
    """从表达式中提取变量名 (排除关键字/常量)。"""
    vars_found = set()
    for m in re.finditer(r'\b([a-zA-Z_]\w*)\b', expr):
        v = m.group(1)
        if v in ('sizeof', 'NULL', 'char', 'int', 'void', 'size_t',
                 'unsigned', 'long', 'short', 'const', 'static', 'volatile',
                 'struct', 'if', 'for', 'while', 'return', 'else', 'switch',
                 'case', 'default', 'break', 'continue', 'goto', 'typedef',
                 'enum', 'ssize_t', 'uint32_t', 'uint64_t', 'int32_t',
                 'int64_t', 'uint16_t', 'int16_t', 'uint8_t', 'int8_t',
                 'malloc', 'calloc', 'realloc', 'alloca',
                 'printf', 'fprintf', 'sprintf', 'snprintf',
                 'memcpy', 'memset', 'memmove', 'strcpy', 'strcat',
                 'free', 'exit', 'main'):
            continue
        if v[0].isupper():
            continue
        vars_found.add(v)
    return vars_found

def _find_cross_func_arith(source: str) -> dict:
    """预扫描: 找到含算术运算返回值的函数, 用于跨函数溢出追踪。

    返回: {func_name: {return_expr, params}}
    识别: size_t compute_size(int count, int elem) { return count * elem_size; }
         size_t calc_size(int depth, int base) { return base * calc_size(...); }
    """
    funcs = {}
    lines = source.splitlines()
    current_func = None
    func_start = -1

    for i, raw_line in enumerate(lines):
        line = raw_line.strip()

        fm = re.match(
            r'(?:size_t|int|long|unsigned(?:\s+(?:int|long))?)'
            r'\s*(\w+)\s*\([^)]*\)\s*\{?', line)
        if fm and ('{' in line or (i + 1 < len(lines) and '{' in lines[i + 1])):
            current_func = fm.group(1)
            func_start = i
            continue

        if current_func and line == '}':
            current_func = None
            func_start = -1
            continue

        if current_func:
            ret_m = re.search(
                r'return\s+(?:\([^)]+\)\s*)?(.+?)\s*;', line)
            if ret_m:
                ret_expr = ret_m.group(1)
                if any(op in ret_expr for op in ('*', '+', '<<')):
                    funcs[current_func] = {
                        'return_expr': ret_expr,
                        'line_no': i + 1,
                    }

    return funcs

def _detect_advanced_patterns(line: str, line_no: int, user_vars: Set[str],
                               arith_vars: Set[str], cross_func_arith: dict,
                               findings: list):
    """检测高级整数溢出模式 (15-17): 函数参数算术 / 大常量乘法 / 跨函数算术。

约束。
    """
# 模式15: 函数参数中的算术表达式 → var1 * var2
    fcm2 = re.search(
        r'(?:memcpy|memmove|memset|strncpy|calloc|malloc)\s*\(([^)]+)\)',
        line, re.IGNORECASE)
    if fcm2:
        args_str = fcm2.group(1)
        for mul_m in re.finditer(r'(\w+)\s*\*\s*(\w+)', args_str):
            left_v = mul_m.group(1)
            right_v = mul_m.group(2)
            mul_vars = _extract_vars(f'{left_v} {right_v}')
            if mul_vars & user_vars:
                findings.append({
                    'type': 'func_arg_mul_overflow',
                    'line_no': line_no, 'line': line,
                    'desc': f'函数参数中 {mul_m.group(0)} 涉及用户输入, 可能溢出',
                })
                break

# 模式16: 大常量乘法 → 即使没有用户输入也可能溢出
    for lcm in re.finditer(r'(\w+)\s*=\s*(.+?)\s*\*\s*(0x[0-9a-fA-F]+|\d+)\s*;', line):
        lhs = lcm.group(1)
        rhs_const = lcm.group(3)
        try:
            if rhs_const.startswith('0x') or rhs_const.startswith('0X'):
                const_val = int(rhs_const, 16)
            else:
                const_val = int(rhs_const)
        except ValueError:
            const_val = 0
        if const_val >= 0x10000000:
            findings.append({
                'type': 'large_const_mul', 'var': lhs,
                'line_no': line_no, 'line': line,
                'desc': f'{lhs} 乘以大常量 {rhs_const}, 可能溢出',
            })

    # ── 模式17: 跨函数算术调用 → func(user_var, ...) 且 func 返回算术结果 ──
    for func_name, info in cross_func_arith.items():
        if re.search(rf'\b{func_name}\s*\(', line):
            call_m = re.search(rf'{func_name}\s*\(([^)]*)\)', line)
            if call_m:
                call_args = call_m.group(1)
                call_vars = _extract_vars(call_args)
                if call_vars & user_vars or any(
                        v in arith_vars for v in call_vars):
                    findings.append({
                        'type': 'cross_func_arith',
                        'line_no': line_no, 'line': line,
                        'desc': f'跨函数算术 {func_name}({call_args}) 含溢出风险表达式 {info.get("return_expr", "")}',
                    })
            if re.search(rf'malloc\s*\(\s*\w+\s*\)', line):
                ret_var = re.search(
                    rf'(\w+)\s*=\s*{func_name}\s*\(', line)
                if ret_var:
                    findings.append({
                        'type': 'cross_func_to_alloc',
                        'line_no': line_no, 'line': line,
                        'desc': f'{func_name}() 返回值 (含算术 {info.get("return_expr", "")}) 直接用于 malloc',
                    })
