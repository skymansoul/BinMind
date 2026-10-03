"""
fmt_detector 辅助函数 — 用户控制格式串变量追踪 + 格式串参数分类。

"""
import re
from typing import Dict, Tuple


# strncpy/sprintf 构造格式串: strncpy(fmt, argv[1], N);
_STRNCPY_ARGV_RE = re.compile(
    r'(?:strncpy|strcpy|snprintf)\s*\(\s*(\w+)\s*,\s*argv\[',
    re.IGNORECASE,
)

# printf(argv[1]) — 用户输入直接作为格式串
_DIRECT_ARGV_RE = re.compile(
    r'(?:printf|fprintf|sprintf|snprintf)\s*\(\s*argv\[',
    re.IGNORECASE,
)

# sprintf(buf, argv[1], ...) — 用户输入作为格式串
_SPRINTF_ARGV_FMT_RE = re.compile(
    r'(?:sprintf|snprintf)\s*\(\s*\w+\s*,\s*argv\[',
    re.IGNORECASE,
)

# snprintf/sprintf 目标缓冲区追踪 — dest可能被污染
_SNPRINTF_TAINT_RE = re.compile(
    r'(?:snprintf|sprintf)\s*\(\s*(\w+)\s*,.*argv\[',
    re.IGNORECASE,
)


def _find_user_controlled_fmt_vars(source: str) -> set:
    """找出被 argv[] 或 getenv() 填充后可能作为格式串的变量名。

    追踪链:
      1. 直接赋值: fmt = argv[1]
      2. strncpy/strcpy/snprintf 目标 → 含用户输入
      3. 函数参数 → 调用点传入 argv[N]
      4. 全局变量赋值 → 从用户输入参数
    """
    direct_vars = set()

    for m in _STRNCPY_ARGV_RE.finditer(source):
        direct_vars.add(m.group(1))
    # 直接赋值: fmt = argv[1];
    for m in re.finditer(r'(\w+)\s*=\s*argv\[', source):
        direct_vars.add(m.group(1))
    # 三元/条件赋值: fmt = cond ? argv[1] : "safe";
    for m in re.finditer(r'(\w+)\s*=\s*[^?]+\?\s*argv\[', source):
        direct_vars.add(m.group(1))

    # snprintf 目标缓冲区含 argv 数据: snprintf(temp, sz, "fmt", argv[1])
    for m in _SNPRINTF_TAINT_RE.finditer(source):
        direct_vars.add(m.group(1))

    # 函数参数 taint: 查找调用 f(arg) 且 arg 可能为 argv[N] 或已污染变量
    func_param_map = {}  # func_name → {param_name}
    for m in re.finditer(
            r'void\s+(\w+)\s*\(\s*[^)]*?(?:const\s+)?char\s*\*?\s*(\w+)\s*[^)]*\)',
            source, re.IGNORECASE):
        func_param_map.setdefault(m.group(1), set()).add(m.group(2))
    for m in re.finditer(
            r'void\s+(\w+)\s*\([^)]*?(?:const\s+)?char\s*\*?\s*(\w+)\s*\)',
            source, re.IGNORECASE):
        func_param_map.setdefault(m.group(1), set()).add(m.group(2))

    # 查找调用: func(argv[1]), func(..., argv[1]), func(tainted_var)
    for m in re.finditer(r'(\w+)\s*\(\s*(?:[^,)]+,\s*)?argv\[', source):
        callee = m.group(1)
        if callee in func_param_map:
            direct_vars |= func_param_map[callee]
    # 调用时传入已污染的变量: func(tainted_var)
    for tainted in list(direct_vars):
        for m in re.finditer(
                rf'(\w+)\s*\(\s*(?:[^,)]+,\s*)?{tainted}\s*[,)]', source):
            callee = m.group(1)
            if callee in func_param_map:
                direct_vars |= func_param_map[callee]

    # 传递闭包: outer(input) → inner(input) → printf(s)
    for func_name, params in func_param_map.items():
        for param_name in params:
            if param_name in direct_vars:
                func_start = source.find(f'void {func_name}')
                if func_start < 0:
                    continue
                func_end = source.find('\n}', func_start)
                if func_end < 0:
                    func_end = len(source)
                func_body = source[func_start:func_end]
                for cm in re.finditer(
                        rf'(\w+)\s*\(\s*{param_name}\s*[,)]', func_body):
                    nested_callee = cm.group(1)
                    if nested_callee in func_param_map:
                        direct_vars |= func_param_map[nested_callee]

    # 全局变量污染: 在函数体内 g_var = param (param是已污染的参数)
    for func_name, params in func_param_map.items():
        for param in params:
            for gm in re.finditer(rf'(\w+)\s*=\s*{param}\s*;', source):
                gv = gm.group(1)
                if not re.search(rf'(?:char|int|const)\s+\*?\s*{gv}\s*[=;]', source):
                    direct_vars.add(gv)

    # 条件赋值 fmt = user (user是函数参数且已标记)
    for fmt_var in list(direct_vars):
        for m in re.finditer(rf'(\w+)\s*=\s*{fmt_var}\s*;', source):
            direct_vars.add(m.group(1))

    return direct_vars


def _classify_fmt_arg(fmt_arg: str, line: str, full_source: str,
                      direct_vars: set, var_constants: dict) -> Tuple[str, bool, bool]:
    """判定格式串参数来源和风险特征。"""
    has_pct_n = False
    has_positional = False

    # 用户输入直接作为格式串: printf(argv[1])
    if 'argv[' in fmt_arg:
        source = 'EXTERNAL_INPUT'
    elif fmt_arg in direct_vars:
        source = 'EXTERNAL_INPUT'
    # 编译时常量
    elif fmt_arg.startswith('"') and fmt_arg.endswith('"'):
        source = 'CONSTANT'
        fmt_content = fmt_arg[1:-1]
        has_pct_n, has_positional = _scan_fmt_specs(fmt_content)
    # 变量 — 检查是否已知常量
    elif fmt_arg in var_constants:
        source = 'CONSTANT'
        has_pct_n, has_positional = _scan_fmt_specs(var_constants[fmt_arg])
    else:
        # STACK_VAR — 检查源码中是否存在 %n 写原语和位置参数
        source = 'STACK_VAR'
        if re.search(r'%n\b', full_source):
            has_pct_n = True
        if re.search(r'%\d+\$', full_source):
            has_positional = True

    # 全局扫描: 整个文件中有 sprintf(buf, argv[1]) 模式
    if source == 'CONSTANT':
        if _DIRECT_ARGV_RE.search(line):
            source = 'EXTERNAL_INPUT'
            has_pct_n = True
        if _SPRINTF_ARGV_FMT_RE.search(line):
            source = 'EXTERNAL_INPUT'
            has_pct_n = True

    # 动态构造的 %n: sprintf(fmt, "%%%d$n", i+1) → 构造 %N$n 写原语
    if not has_pct_n and source in ('STACK_VAR', 'CONSTANT'):
        if re.search(r'"%%(?:%d|%\d\$)?.*\$n"', full_source):
            has_pct_n = True
        if re.search(r'sprintf\s*\([^,]+,\s*"[^"]*%[^"]*\$n"', full_source):
            has_pct_n = True

    return source, has_pct_n, has_positional


# 格式符扫描 (从主模块导入以避免循环依赖)
_FMT_SPEC_RE = re.compile(
    r'%(?:[0+\- #]*)?(?:\d+|\*)?(?:\.(?:\d+|\*))?(?:hh|h|l|ll|j|z|t|L)?'
    r'([diouxXeEfFgGaAcspn%])',
)


def _scan_fmt_specs(fmt_str: str) -> Tuple[bool, bool]:
    """扫描格式串中的说明符。"""
    has_n = False
    has_pos = False
    for m in _FMT_SPEC_RE.finditer(fmt_str):
        spec = m.group(1)
        if spec == 'n':
            has_n = True
        if spec == '%':
            continue
        if re.search(r'%\d+\$', fmt_str):
            has_pos = True
    return has_n, has_pos
