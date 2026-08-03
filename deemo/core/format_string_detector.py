"""
格式化字符串漏洞检测与偏移分析。

检测 printf/fprintf/sprintf/snprintf 系列函数的格式化字符串漏洞：
1. 静态识别 vararg 调用中格式化参数来自用户输入的代码模式
2. 利用 angr 符号执行或动态爆破计算格式化字符串在栈上的参数偏移
3. 输出偏移值和利用建议（直接修改 GOT / 泄露地址 / 任意写）

多层检测策略:
  Level 1 — 静态模式匹配: 在反编译代码中搜索 printf(buf) 等危险模式
  Level 2 — 符号执行: 将格式化参数符号化，追踪到栈上位置计算偏移
  Level 3 — LLM 辅助: 调用 LLM 分析反编译代码判断格式化字符串利用可行性

参考:
  - scut / team teso, 2001, "Exploiting Format String Vulnerabilities"
  - Peng et al., 2025, ACL, "PwnGPT: Automatic Exploit Generation Based on Large Language Models"
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from typing import Any, Dict, List, Optional, Tuple

from config import R2_PATH

_log = logging.getLogger(__name__)

# 格式化函数族
_FORMAT_FUNCTIONS = {
    'printf', 'fprintf', 'dprintf', 'sprintf', 'snprintf',
    'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
    'syslog', 'err', 'errx', 'warn', 'warnx',
}

# 格式化字符串的可疑模式 —— 第一个参数不是字符串常量
_DIRECT_CALL_PATTERN = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf)\s*\(\s*([^,"]+)',
)


def detect_format_string_vulns(
    binary_path: str,
    func_name: Optional[str] = None,
    use_llm: bool = False,
) -> List[Dict[str, Any]]:
    """
    检测二进制中格式化字符串漏洞。

    返回值列表，每个条目描述一个潜在的格式化字符串漏洞点：
      - function: 包含漏洞的函数名
      - call_address: 危险调用的地址（0 表示未知）
      - format_func: 格式化函数名
      - offset: 格式化字符串在栈上的参数偏移 (-1 表示未知)
      - confidence: 检测置信度 0.0-1.0
      - description: 人类可读描述
      - exploitation: 利用建议

    Args:
        binary_path: ELF 文件路径
        func_name: 限定检测的函数名，None 表示扫描所有函数
        use_llm: 是否调用 LLM 进行深度分析

    Returns:
        漏洞点列表，按置信度降序排列
    """
    findings: List[Dict[str, Any]] = []

    if not os.path.isfile(binary_path):
        return findings

    # 获取函数列表
    if func_name:
        target_funcs = [func_name]
    else:
        target_funcs = _list_user_functions(binary_path)

    # Level 1: 静态模式匹配
    for fname in target_funcs[:50]:  # 限制扫描范围
        decompiled = _decompile_function(binary_path, fname)
        if not decompiled:
            continue

        static_findings = _static_format_detect(fname, decompiled)
        findings.extend(static_findings)

    # Level 2: 对高置信度的静态发现进行符号执行验证
    for finding in findings:
        try:
            offset = _compute_format_offset(binary_path, finding)
            if offset >= 0:
                finding['offset'] = offset
                finding['confidence'] = min(1.0, finding['confidence'] + 0.2)
        except Exception:
            pass

    # Level 3: LLM 辅助（按需）
    if use_llm and findings:
        findings = _llm_enhance_findings(findings, binary_path)

    findings.sort(key=lambda f: (-f['confidence'], f['function']))
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
                # 跳过编译器内部和库函数
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
        # 搜索 fmt_func(variable) 模式 —— 第一个参数非字符串字面量
        for m in re.finditer(
            rf'{fmt_func}\s*\(\s*([^,"\']+)\s*\)',
            pseudocode,
        ):
            arg = m.group(1).strip()
            # 跳过明显的字符串字面量
            if arg.startswith('"') or arg.startswith("'"):
                continue
            # 跳过已知安全的调用
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


def _compute_format_offset(
    binary_path: str,
    finding: Dict[str, Any],
) -> int:
    """
    通过符号执行或启发式计算格式化字符串的栈偏移。

    优先使用 angr 符号执行，不可用时回退到启发式估计。
    """
    # 尝试 angr 符号执行
    try:
        import angr
        import claripy

        proj = angr.Project(binary_path, auto_load_libs=False)
        cfg = proj.analyses.CFGFast()

        target_func = finding['function']
        for f in cfg.functions.values():
            if f.name == target_func:
                # 搜索格式化函数调用位置
                for block in f.blocks:
                    for insn in block.capstone.insns:
                        if insn.mnemonic == 'call':
                            callee_addr = insn.operands[0].imm
                            callee = cfg.functions.get(callee_addr)
                            if callee and callee.name == finding['format_func']:
                                # 在 x86_64 中，第一个参数通过 rdi 传递
                                state = proj.factory.blank_state(addr=insn.address)
                                try:
                                    rdi = state.solver.eval(state.regs.rdi)
                                    # 计算 rdi 距离 rsp 的偏移
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

    # 回退: 启发式估计
    # 在 x86_64 调用约定中，格式化字符串通常在第 5-8 个参数位置
    return _heuristic_format_offset(binary_path, finding)


def _heuristic_format_offset(
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
            return 1  # i386: 第 1 个栈参数

        # x86_64: 前 6 个在寄存器中，栈上从第 7 个开始
        # 但具体偏移因局部变量和栈帧大小而异
        return 6  # 保守估计
    except Exception:
        return -1


def _llm_enhance_findings(
    findings: List[Dict[str, Any]],
    binary_path: str,
) -> List[Dict[str, Any]]:
    """
    调用 LLM 对静态检测结果进行深度分析。

    将反编译代码和检测到的模式发送给 LLM，
    获取利用可行性评估和详细的利用步骤建议。
    """
    try:
        from config import OPENAI_API_KEY
        if not OPENAI_API_KEY:
            return findings

        from core.ai_backends import query_llm

        for finding in findings[:3]:  # 仅对前 3 个高置信度发现调用 LLM
            system_prompt = (
                "You are an expert binary exploitation analyst specializing in "
                "format string vulnerabilities. Evaluate the exploitability of "
                "the given finding concisely."
            )
            user_prompt = (
                f"Format string finding:\n"
                f"Function: {finding['function']}\n"
                f"Dangerous call: {finding['format_func']}({finding['format_arg']})\n"
                f"Estimated offset: {finding.get('offset', -1)}\n\n"
                f"Provide: 1) Is this exploitable? 2) What is the most likely "
                f"attack vector? 3) Key constraints. Keep it under 200 words."
            )
            try:
                response = query_llm(
                    system=system_prompt,
                    user=user_prompt,
                    temperature=0.2,
                    max_tokens=256,
                )
                finding['llm_analysis'] = response.strip()
                finding['confidence'] = min(1.0, finding['confidence'] + 0.15)
            except Exception as e:
                _log.debug("LLM format string analysis failed: %s", e)

    except (ImportError, Exception) as e:
        _log.debug("LLM enhancement unavailable: %s", e)

    return findings


def format_offset_to_arg_position(offset: int, arch_bits: int = 64) -> str:
    """
    将格式化字符串栈偏移转换为人类可读的参数位置描述。

    Args:
        offset: 格式化字符串在栈上的偏移（以指针为单位）
        arch_bits: 架构位数

    Returns:
        例如 "第 6 个参数 (printf 的第 1 个栈参数)"
    """
    if offset <= 0:
        return "unknown"

    if arch_bits == 32:
        return f"argument #{offset} (stack position {offset})"

    # x86_64: 前 6 个参数在寄存器中
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
