# created: 2026-06-02
# 格式化字符串漏洞验证-区分"有漏洞的printf"和"安全的printf"
# 仅当格式化字符串参数来自用户输入且非编译期常量时才报告
#
# 决策逻辑:
#   1. 若fmt是.rodata段的编译期常量→排除(绝大多数printf调用)
#   2. 若fmt来自函数参数+额外参数被传入→潜在漏洞
#   3. 若printf只有一个参数(无语义格式化)→排除(即printf(var)但var是字符串)
#   4. 若fmt来自read/recv/栈变量→标记为漏洞

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Set, Tuple
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class FormatVulnLevel(Enum):
    SAFE = 'safe'              # 确定安全
    SUSPICIOUS = 'suspicious'  # 可疑-需要人工审查
    VULNERABLE = 'vulnerable'  # 确定存在漏洞


@dataclass
class FormatStringVerdict:
    call_addr: int
    func_name: str             # printf/sprintf/fprintf/snprintf等
    fmt_origin: str            # 格式化字符串来源描述
    arg_count: int             # 传入的参数数量
    fmt_is_const: bool         # fmt是否是编译期常量
    fmt_is_user_controlled: bool
    vuln_level: FormatVulnLevel
    evidence: List[str] = field(default_factory=list)


class FormatStringChecker:
    """格式化字符串漏洞检测器。

    分析三步:
      1. 检测格式化函数调用(printf/sprintf/fprintf/snprintf/vprintf)
      2. 追踪第一个参数(fmt)的来源
      3. 判断fmt是否用户可控

    与简单函数名匹配的关键区别:
      不会因为代码中出现printf就报警——大多数printf是安全的
      (如printf("hello world")或printf("%s", buf))。
      仅当fmt参数来自外部输入且非编译时常量时才报警。
    """

    # 格式化函数列表
    _FORMAT_FUNCS = {
        'printf', 'fprintf', 'sprintf', 'snprintf',
        'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf',
        'dprintf', 'syslog',
    }
    # .rodata段中常见的字符串引用模式(x86_64)
    _RODATA_PATTERN = re.compile(
        r'(lea|mov)\s+\w+,\s*\[rip\s*[+-]\s*(0x[0-9a-f]+)\]', re.I)

    def check_call(self,
                    instr_idx: int,
                    instructions: List[str],
                    func_name: str,
                    param_regs: Optional[List[str]] = None
                    ) -> FormatStringVerdict:
        """检查单个格式化函数调用是否存在漏洞。"""
        if func_name not in self._FORMAT_FUNCS:
            return FormatStringVerdict(
                call_addr=instr_idx, func_name=func_name,
                fmt_origin='n/a', arg_count=0,
                fmt_is_const=True, fmt_is_user_controlled=False,
                vuln_level=FormatVulnLevel.SAFE)

        if param_regs is None:
            param_regs = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']

        fmt_reg = param_regs[0] if param_regs else 'rdi'
        evidence = []
        fmt_is_const = False
        fmt_origin = 'unknown'
        arg_count = 0

        # 向前扫描call指令之前的指令，追踪fmt的来源
        for j in range(instr_idx - 1, max(-1, instr_idx - 6), -1):
            if j < 0 or j >= len(instructions):
                break
            instr = instructions[j].strip().lower()
            if not instr:
                continue

            # 模式1: lea rdi, [rip+offset] → fmt是.rodata常量(安全)
            if self._RODATA_PATTERN.search(instr):
                fmt_is_const = True
                fmt_origin = '.rodata constant'
                evidence.append(f"instr[{j}]: {instr} → rodata ref")
                break

            # 模式2: mov rdi, imm → fmt是硬编码地址(通常安全)
            m_imm = re.match(r'mov\s+rdi,\s*(0x[0-9a-f]+)', instr)
            if m_imm:
                fmt_is_const = True
                fmt_origin = f'hardcoded addr {m_imm.group(1)}'
                evidence.append(f"instr[{j}]: {instr} → const addr")
                break

            # 模式3: mov rdi, reg → fmt来自寄存器(需进一步追踪)
            m_reg = re.match(r'mov\s+rdi,\s*(\w+)', instr)
            if m_reg:
                fmt_origin = f'register {m_reg.group(1)}'
                # 检查寄存器是否来自函数参数
                if m_reg.group(1) in param_regs:
                    fmt_origin = f'function parameter ({m_reg.group(1)})'
                    evidence.append(f"instr[{j}]: fmt来源=参数 {m_reg.group(1)} → 潜在用户可控")
                break

            # 模式4: mov rdi, [stack] → fmt来自栈(可疑)
            if re.match(r'mov\s+rdi,\s*\[rbp', instr):
                fmt_origin = 'stack variable'
                evidence.append(f"instr[{j}]: fmt来源=栈 → 潜在用户可控")
                break

            # 模式5: call → fmt是另一函数的返回值(需跨函数分析)
            if 'call' in instr and j < instr_idx - 1:
                fmt_origin = 'return value of another function'
                evidence.append(f"instr[{j}]: fmt来源=函数返回值")
                break

        # 参数计数: 在call之前push/mov到参数寄存器的数量
        for j in range(max(0, instr_idx - 8), instr_idx):
            instr = instructions[j].strip().lower() if j < len(instructions) else ''
            if re.match(rf'mov\s+({"|".join(param_regs[1:])}),', instr):
                arg_count += 1

        # 判定逻辑
        if fmt_is_const:
            vuln_level = FormatVulnLevel.SAFE
        elif arg_count == 0 and func_name in ('printf', 'vprintf'):
            # printf只有一个参数(格式化字符串)→可能是printf(str_var)
            # 这种情况下str_var大概率不是格式化字符串→低风险
            vuln_level = FormatVulnLevel.SUSPICIOUS
            evidence.append('单一参数printf，无法确认fmt是否可控')
        elif 'parameter' in fmt_origin:
            vuln_level = FormatVulnLevel.VULNERABLE
            evidence.append('fmt来自函数参数→用户可控')
        elif 'stack' in fmt_origin or 'return' in fmt_origin:
            vuln_level = FormatVulnLevel.SUSPICIOUS
            evidence.append('fmt来源不确定但非编译期常量')
        else:
            vuln_level = FormatVulnLevel.SAFE

        return FormatStringVerdict(
            call_addr=instr_idx, func_name=func_name,
            fmt_origin=fmt_origin, arg_count=arg_count,
            fmt_is_const=fmt_is_const,
            fmt_is_user_controlled=(vuln_level == FormatVulnLevel.VULNERABLE),
            vuln_level=vuln_level, evidence=evidence)
