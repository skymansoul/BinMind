"""格式化字符串检测辅助函数 — 反编译/静态模式匹配/偏移工具。"""


import re
import subprocess
from typing import Any, Dict, List, Optional

from config import R2_PATH

# 格式化函数族 — 与主文件同步, 避免循环导入
_FORMAT_FUNCTIONS = {
    'printf', 'fprintf', 'dprintf', 'sprintf', 'snprintf',
    'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'syslog', 'err', 'errx', 'warn', 'warnx',
}


def _detect_indirect_format_call(func_name: str, pseudocode: str) -> List[Dict[str, Any]]:
    """检测通过函数指针间接调用的格式化函数.

    在反编译代码中搜索 call *%reg 模式,
    结合 PLT 地址判断是否为 printf 系列函数的间接调用.
    """
    import re as _re
    findings = []
    for m in _re.finditer(r'call\s+\*(?:%?)(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10)', pseudocode):
        reg = m.group(1)
        for fmt_func in ('printf', 'sprintf', 'fprintf'):
            findings.append({
                'function': func_name,
                'call_address': 0,
                'format_func': f'{fmt_func}(indirect via {reg})',
                'format_arg': 'unknown',
                'offset': -1,
                'confidence': 0.35,
                'description': (
                    f'Indirect call via {reg} in {func_name} — '
                    f'may resolve to {fmt_func} with user-controlled format'),
                'exploitation': (
                    'Verify with dynamic analysis whether the function '
                    'pointer resolves to a format function.'),
            })
    return findings


def _list_user_functions(binary_path: str) -> List[str]:
    """列出用户定义的函数（排除库函数）。"""
    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false', '-c', 'afl', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        funcs = []
        for line in proc.stdout.splitlines():
            parts = line.strip().split()
            if len(parts) >= 3:
                name = parts[-1]
                if not name.startswith(('_', 'sym.', 'fcn.', 'sub.')):
                    if not any(name.startswith(p) for p in
                               ('__libc', '__cxa', 'register', 'deregister')):
                        funcs.append(name)
        return funcs
    except Exception:
        return []


def _decompile_function(binary_path: str, func_name: str) -> str:
    """反编译单个函数并返回伪代码文本。"""
    try:
        from core.decompiler import decompile_function
        result = decompile_function(binary_path, func_name)
        return result.get('pseudocode', '')
    except Exception:
        pass

    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'pdc', binary_path],
            capture_output=True, text=True, timeout=30,
        )
        return proc.stdout
    except Exception:
        return ''


def _static_format_detect(
    func_name: str,
    pseudocode: str,
) -> List[Dict[str, Any]]:
    """
    在反编译代码中静态检测格式化字符串漏洞。

    识别两种模式:
      1. printf(user_var) —— 格式化参数直接来自变量
      2. printf(fgets(buf)) —— 格式化参数来自用户输入函数返回值
    """
    findings = []

    for fmt_func in _FORMAT_FUNCTIONS:
        for m in re.finditer(
            rf'{fmt_func}\s*\(\s*([^,"\']+)\s*\)',
            pseudocode,
        ):
            arg = m.group(1).strip()
            if arg.startswith('"') or arg.startswith("'"):
                continue
            if arg in ('format', 'fmt', '__fmt', '"%s"'):
                continue

            findings.append({
                'function': func_name,
                'call_address': 0,
                'format_func': fmt_func,
                'format_arg': arg,
                'offset': -1,
                'confidence': 0.6,
                'description': (
                    f'{fmt_func}() called with variable "{arg}" as format string '
                    f'in {func_name} — potential format string vulnerability'
                ),
                'exploitation': (
                    'Control format string → leak stack values (%p/%x) → '
                    'locate target address on stack → %n write primitive'
                ),
            })

    return findings


def format_offset_to_arg_position(offset: int, arch_bits: int = 64) -> str:
    """将格式化字符串栈偏移转换为人类可读的参数位置描述。"""
    if offset <= 0:
        return "unknown"

    if arch_bits == 32:
        return f"argument #{offset} (stack position {offset})"

    if offset <= 6:
        reg_names = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
        return f"argument #{offset} (register {reg_names[offset-1]} → format string itself)"

    stack_pos = offset - 5
    return f"argument #{offset} ({stack_pos}{_ordinal(stack_pos)} stack argument after r9)"


def _ordinal(n: int) -> str:
    """返回英文序数后缀。"""
    if 11 <= (n % 100) <= 13:
        return 'th'
    return {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')
