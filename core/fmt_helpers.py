"""
格式化字符串检测辅助函数。
"""


import logging
import re
import subprocess
from typing import Any, Dict, List

from config import R2_PATH

_log = logging.getLogger(__name__)

_FORMAT_FUNCTIONS = {
    'printf', 'fprintf', 'dprintf', 'sprintf', 'snprintf',
    'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'syslog', 'err', 'errx', 'warn', 'warnx',
}

# 各格式化函数的格式串参数位置 (0-based)
_FORMAT_ARG_POS = {
    'printf': 0, 'vprintf': 0,
    'fprintf': 1, 'dprintf': 1, 'vfprintf': 1,
    'sprintf': 1, 'vsprintf': 1,
    'snprintf': 2, 'vsnprintf': 2,
    'syslog': 1, 'err': 1, 'errx': 1, 'warn': 1, 'warnx': 1,
}

# CRT 基础设施调用 (反编译产物, 如 __acrt_iob_func(1)), 非用户可控格式串
_RE_CRT_CALL = re.compile(r'^_\w+\s*\(')
# 立即数/地址形参数 (0x140002000 / 7 / 0x40)
_RE_ADDR_LITERAL = re.compile(r'^0[xX][0-9a-fA-F]+$|^\d+$')


def _extract_call_args(text: str, start: int) -> str:
    """从 text[start] 指向的 '(' 后提取完整括号参数串 (处理嵌套)。"""
    depth, i = 1, start
    while i < len(text) and depth > 0:
        if text[i] == '(':
            depth += 1
        elif text[i] == ')':
            depth -= 1
        i += 1
    return text[start:i - 1] if depth == 0 else text[start:]


def _split_args(arg_str: str) -> List[str]:
    """按逗号切分参数, 处理嵌套括号。"""
    parts: List[str] = []
    depth, cur = 0, []
    for ch in arg_str:
        if ch == '(':
            depth += 1
            cur.append(ch)
        elif ch == ')':
            depth -= 1
            cur.append(ch)
        elif ch == ',' and depth == 0:
            parts.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        parts.append(''.join(cur).strip())
    return parts


def _is_static_format_arg(arg: str) -> bool:
    """判定格式串参数是否静态不可控, 是则跳过 (不构成格式串漏洞).

    覆盖: C 字面量; 地址/立即数; CRT 基础设施调用; 纯符号引用.
    """
    if not arg:
        return True
    if arg.startswith('"') or arg.startswith("'"):
        return True
    if _RE_ADDR_LITERAL.match(arg):
        return True
    if _RE_CRT_CALL.match(arg):
        return True
    return False


def list_user_functions(binary_path: str) -> List[str]:
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
                # PE 文件 r2 把 main 标为 sym.main, 不能误过滤
                if name in ('main', 'sym.main', 'sym._main', 'entry0'):
                    funcs.append(name if not name.startswith('sym.') else name[4:])
                    continue
                if not name.startswith(('_', 'sym.', 'fcn.', 'sub.')):
                    if not any(name.startswith(p) for p in
                               ('__libc', '__cxa', 'register', 'deregister')):
                        funcs.append(name)
        # 过滤后为空时回退到 main, 避免漏检 PE 格式
        if not funcs:
            return ['main']
        return funcs
    except Exception:
        return ['main']


def decompile_function(binary_path: str, func_name: str) -> str:
    """反编译单个函数并返回伪代码文本。"""
    try:
        from core.decompiler import decompile_function as _decomp
        result = _decomp(binary_path, func_name)
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


def static_format_detect(
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
        # 词边界 + 参数位置感知: 旧正则无 \b 会把 __mingw_fprintf( 当作
        # fprintf( 命中; 单参盲捕获会把 __acrt_iob_func(1 当作格式串变量.
        # 现在先定位函数调用, 再按 _FORMAT_ARG_POS 取格式串实参, 并对静态
        # 参数(字面量/地址/CRT调用)直接跳过.
        for m in re.finditer(rf'\b{re.escape(fmt_func)}\s*\(', pseudocode):
            args_str = _extract_call_args(pseudocode, m.end())
            if not args_str:
                continue
            args = _split_args(args_str)
            pos = _FORMAT_ARG_POS.get(fmt_func)
            if pos is None or pos >= len(args):
                continue
            arg = args[pos].strip()
            if _is_static_format_arg(arg):
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
                    'Control format string -> leak stack values (%p/%x) -> '
                    'locate target address on stack -> %n write primitive'
                ),
            })

    return findings


def compute_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """
    通过符号执行或启发式计算格式化字符串的栈偏移。

    优先使用 angr 符号执行，不可用时回退到启发式估计。
    """
    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        target_func = finding['function']
        for f in cfg.functions.values():
            if f.name == target_func:
                for block in f.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            callee_addr = insn.operands[0].imm
                            callee = cfg.functions.get(callee_addr)
                            if callee and callee.name == finding['format_func']:
                                state = proj.factory.blank_state(addr=insn.address)
                                try:
                                    rdi = state.solver.eval(state.regs.rdi)
                                    rsp = state.solver.eval(state.regs.rsp)
                                    offset = (rdi - rsp) // 8
                                    if 1 <= offset <= 50:
                                        return offset
                                except Exception:
                                    pass
                break
    except ImportError:
        pass
    except Exception as e:
        _log.debug("Symbolic format offset computation failed: %s", e)

    return heuristic_format_offset(binary_path, finding)


def heuristic_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """
    启发式估计格式化字符串偏移。

    对于 x86_64，前 6 个参数通过寄存器传递 (rdi, rsi, rdx, rcx, r8, r9)，
    格式化字符串是第 1 个寄存器参数，因此栈上偏移从第 7 个位置开始。

    对于 i386，所有参数通过栈传递，格式化字符串在 esp+4 处，
    栈偏移为 1（从栈顶算第 1 个参数）。
    """
    try:
        from core.binary_info import get_binary_info
        binfo = get_binary_info(binary_path)
        arch = binfo.get('arch', 'x86-64')
        bits = binfo.get('bits', 64)

        if bits == 32 or '86' in arch:
            return 1

        return 6
    except Exception:
        return -1


def detect_indirect_format_call(func_name: str, pseudocode: str) -> List[Dict[str, Any]]:
    """检测通过函数指针间接调用的格式化函数.

    在反编译代码中搜索 call *%reg 模式,
    结合 PLT 地址判断是否为 printf 系列函数的间接调用.
    """
    findings = []
    for m in re.finditer(r'call\s+\*(?:%?)(rax|rbx|rcx|rdx|rsi|rdi|r8|r9|r10)', pseudocode):
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
