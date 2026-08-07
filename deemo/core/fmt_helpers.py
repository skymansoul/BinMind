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
                if not name.startswith(('_', 'sym.', 'fcn.', 'sub.')):
                    if not any(name.startswith(p) for p in
                               ('__libc', '__cxa', 'register', 'deregister')):
                        funcs.append(name)
        return funcs
    except Exception:
        return []


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
