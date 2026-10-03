# 格式串深层分析器-区分用户可控fmt和常量fmt
# format_string_check.py的核心缺陷:
#   仅检查printf系列调用的第一个参数是否来自函数参数或栈
#   无法区分: printf(gettext("hello")) vs printf(user_input)
#   前者fmt是安全的翻译字符串，后者是危险的用户输入
#
# 改进(三阶段格式串验证):
#   1. fmt来源分类: const(.rodata) / stack / arg / heap / unknown
#   2. 格式符计数vs参数计数一致性: printf("%s%d", a) → 格式符>参数→危险
#   3. 位置参数检测: printf("%1$s%2$n", ...) → %n写内存→最高风险
#
# 理论: CWE-134 + 部分基于"FormatGuard"的二进制级适配

from __future__ import annotations

import re
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass, field
from enum import Enum

from .fmt_provenance import FmtProvenance

logger = logging.getLogger(__name__)


class FmtSource(Enum):
    CONST_RODATA = 'const_rodata'    # .rodata段-几乎确定安全
    STACK = 'stack'                  # 栈变量-可能可控
    ARG = 'arg'                      # 直接函数参数-可能外部传入
    HEAP = 'heap'                    # 堆分配-需进一步分析
    UNKNOWN = 'unknown'


class FmtRisk(Enum):
    SAFE = 'safe'                    # 常量fmt + 参数匹配
    SUSPICIOUS = 'suspicious'       # 非rodata来源但fmt无%n
    DANGEROUS = 'dangerous'         # 可变fmt含%n或参数不匹配
    CRITICAL = 'critical'           # 可变fmt + %n + 参数不匹配


@dataclass
class DeepFmtVerdict:
    call_idx: int
    func_name: str                  # printf/sprintf/fprintf等
    fmt_source: FmtSource
    fmt_content_hint: str = ""      # 若能静态解析fmt的内容片段
    fmt_spec_count: int = 0         # 格式说明符数(%s%d等)
    extra_args: int = 0             # 格式符之外传递的额外参数数
    has_pct_n: bool = False         # 是否包含%n
    risk: FmtRisk = FmtRisk.SAFE
    evidence: List[str] = field(default_factory=list)


class FormatStringDeepAnalyzer:
    """格式串深层分析器。

    与format_string_check.py的区别:
      不仅检查"fmt是否来自参数"，而且分类fmt来源+参数计数一致性+
      %n检测。对每种模式提供量化风险评估。
    """

    _FMT_FUNCS = {'printf', 'fprintf', 'sprintf', 'snprintf',
                  'dprintf', 'vprintf', 'vfprintf', 'vsprintf',
                  'syslog', '__printf_chk', '__fprintf_chk'}
    # 格式说明符——不含%%(转义百分号)
    _FMT_SPEC = re.compile(r'%(?!%)[+\- 0#]*(?:\d+|\*)?(?:\.(?:\d+|\*))?'
                           r'(?:hh|h|l|ll|j|z|t|L)?[diouxXeEfFgGaAcspn]')
    _PCT_N = re.compile(r'%[+\- 0#]*(?:\d+|\*)?(?:\.(?:\d+|\*))?'
                        r'(?:hh|h|l|ll|j|z|t|L)?n\b')
    # 位置参数格式: %1$s, %2$d
    _POSITIONAL = re.compile(r'%\d+\$')

    def analyze_call(self,
                     call_idx: int,
                     instructions: List[str],
                     func_name: str = 'printf',
                     rodata_refs: Optional[Dict[int, str]] = None
                     ) -> DeepFmtVerdict:
        """分析单个格式串函数调用"""
        if rodata_refs is None:
            rodata_refs = {}

        fmt_reg = self._fmt_reg(instructions, call_idx, func_name)
        fmt_source = self._classify_fmt_source(
            instructions, call_idx, fmt_reg, rodata_refs)
        v = DeepFmtVerdict(
            call_idx=call_idx, func_name=func_name, fmt_source=fmt_source)

        # 尝试静态解析fmt内容
        v.fmt_content_hint = self._try_resolve_fmt(
            instructions, call_idx, fmt_reg, rodata_refs)

        # 计数格式说明符
        v.fmt_spec_count = len(
            self._FMT_SPEC.findall(v.fmt_content_hint))
        v.has_pct_n = bool(self._PCT_N.search(v.fmt_content_hint))

        # 参数计数: 除fmt之外的call参数
        v.extra_args = self._count_call_args(instructions, call_idx)
        if func_name.startswith('v'):  # vprintf等-参数通过va_list
            v.extra_args = -1

        # 风险判定
        v.risk = self._assess_risk(v)
        v.evidence = self._build_evidence(v)

        return v

    @staticmethod
    def _fmt_reg(instructions: List[str], call_idx: int,
                 func_name: str) -> str:
        """按函数定位fmt参数寄存器——printf族fmt在首参, sprintf在次参,
        snprintf在第三参; Windows用rcx/rdx/r8, Linux用rdi/rsi/rdx
        """
        # 参数位置: printf=0; fprintf/sprintf/dprintf/syslog=1; snprintf=2
        base = func_name.split('.')[-1].split('@')[0].lower()
        idx = 0
        if base in ('fprintf', 'vfprintf', 'dprintf', 'syslog',
                    'sprintf', 'vsprintf', '__fprintf_chk'):
            idx = 1
        elif base in ('snprintf', 'vsnprintf', '__snprintf_chk',
                      '__vsnprintf_chk', 'snwprintf'):
            idx = 2
        pairs = {0: ('rdi', 'rcx'), 1: ('rsi', 'rdx'), 2: ('rdx', 'r8')}
        lin, win = pairs[idx]
        # ABI检测: 实参装载含rcx系→win; rdi系→linux
        for j in range(call_idx - 1, max(-1, call_idx - 5), -1):
            if j < 0:
                break
            il = instructions[j].strip().lower()
            if not il or il.startswith((';', '.')):
                continue
            if re.search(r'(?:mov|lea)\s+.*?%r(cx|8|9|dx)\b', il):
                return win
            if re.search(r'(?:mov|lea)\s+(?:r|e)(cx|8|9|dx)\b', il):
                return win
            if re.search(r'(?:mov|lea)\s+.*?%r(di|si)\b', il):
                return lin
            if re.search(r'(?:mov|lea)\s+(?:r|e)(di|si)\b', il):
                return lin
        return lin

    def _classify_fmt_source(self,
                              instructions: List[str],
                              call_idx: int,
                              fmt_reg: str,
                              rodata_refs: Dict[int, str]
                              ) -> FmtSource:
        """分类fmt参数的来源"""
        # 阶段0: 来源深化追踪-穿透寄存器链/栈槽, 常量来源直接判CONST_RODATA
        prov = FmtProvenance().resolve(instructions, call_idx, fmt_reg,
                                       rodata_refs)
        if prov[0] == 'const_rodata':
            return FmtSource.CONST_RODATA

        # 阶段1: 找设置fmt_reg的指令
        setup_idx = -1
        setup_instr = ""
        for j in range(call_idx - 1, max(-1, call_idx - 10), -1):
            if j < 0:
                break
            instr = instructions[j].strip().lower()
            # AT&T: mov/lea src, %rdi (目标寄存器在末尾)
            # Intel: mov/lea rdi, src (目标寄存器在开头)
            if re.search(rf'(?:mov|lea)\s+.*,\s*%?{fmt_reg}\s*$', instr):
                setup_idx = j
                setup_instr = instr
                break
            if re.search(rf'(?:mov|lea)\s+%?{fmt_reg}\s*,\s*', instr):
                setup_idx = j
                setup_instr = instr
                break

        if setup_idx < 0:
            return FmtSource.UNKNOWN

        # lea rdi, [rip+offset] → .rodata引用
        if 'rip' in setup_instr or 'eip' in setup_instr:
            return FmtSource.CONST_RODATA

        # mov rdi, 0x... → 绝对地址
        m = re.search(r'0x([0-9a-f]+)', setup_instr)
        if m:
            addr = int(m.group(1), 16)
            if addr in rodata_refs or addr > 0x400000:  # 典型.rodata范围
                return FmtSource.CONST_RODATA
            if addr < 0x100000:  # 堆/栈范围
                return FmtSource.HEAP
            return FmtSource.UNKNOWN

        # mov rdi, [rsp/rbp+N] → 栈变量
        if 'rsp' in setup_instr or 'rbp' in setup_instr:
            return FmtSource.STACK

        # mov src, dst → 源寄存器因语法而异: AT&T src在前, Intel src在后
        m = re.match(r'mov\s+%?(\w+),\s*%?(\w+)', setup_instr)
        if m:
            r1, r2 = m.group(1), m.group(2)
            src = r1 if '%' in setup_instr else r2  # AT&T: src第一, Intel: src第二
            if src in ('rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9'):
                return FmtSource.ARG
            if src in ('rbx', 'r12', 'r13', 'r14', 'r15'):
                return FmtSource.STACK  # callee-saved→来自栈加载

        return FmtSource.UNKNOWN

    def _try_resolve_fmt(self,
                          instructions: List[str],
                          call_idx: int,
                          fmt_reg: str,
                          rodata_refs: Dict[int, str]
                          ) -> str:
        """尝试静态解析fmt字符串内容"""
        for j in range(call_idx - 1, max(-1, call_idx - 8), -1):
            if j < 0:
                break
            instr = instructions[j].strip().lower()
            # RIP相对: AT&T lea 0xNNN(%rip),%rdi 或 Intel lea rdi,[rip+0xNNN]
            m = re.search(r'(0x[0-9a-f]+)\s*\(\s*%?rip\s*\)', instr)
            if not m:
                m = re.search(r'\[rip([+\-]0x[0-9a-f]+)\]', instr)
            if m:
                offset = int(m.group(1), 16)
                for addr, content in rodata_refs.items():
                    if abs(addr - offset) < 0x10000:
                        return content[:80]
            # 绝对地址: AT&T mov $0xNNN,%reg 或 Intel mov reg,0xNNN
            m = re.search(r'mov\s+\$?(0x[0-9a-f]+)\s*,\s*%?\w+', instr)
            if not m:
                m = re.search(r'mov\s+%?\w+,\s*(0x[0-9a-f]+)', instr)
            if m:
                addr = int(m.group(1), 16)
                if addr in rodata_refs:
                    return rodata_refs[addr][:80]
        return ""

    def _count_call_args(self,
                          instructions: List[str],
                          call_idx: int) -> int:
        """计数函数调用中除fmt外的参数"""
        count = 0
        for j in range(max(0, call_idx - 10), call_idx):
            instr = instructions[j].strip().lower()
            # AT&T: mov $imm/%reg, %esi → 在逗号后匹配参数寄存器
            for arg_reg in ('esi', 'edx', 'ecx', 'r8d', 'r9d',
                            'rsi', 'rdx', 'rcx'):
                # 双ABI: AT&T mov ...,%reg (reg末位) 或 Intel mov reg,... (reg首位)
                if re.search(rf'(?:mov|lea)\s+.*,\s*%?{arg_reg}\b', instr) or \
                   re.search(rf'(?:mov|lea)\s+%?{arg_reg}\s*,\s*', instr):
                    count += 1
        return max(0, count - 1)  # 减去fmt本身(rdi)

    def _assess_risk(self, v: DeepFmtVerdict) -> FmtRisk:
        """综合风险评估"""
        # 常量fmt → 检查参数匹配
        if v.fmt_source == FmtSource.CONST_RODATA:
            if v.has_pct_n:
                return FmtRisk.SUSPICIOUS  # 常量%n罕见但合法
            # 格式符>参数→格式串漏洞的变体(编译时常量但运行时用错)
            if v.fmt_spec_count > v.extra_args >= 0:
                return FmtRisk.SUSPICIOUS
            return FmtRisk.SAFE

        # 非常量fmt
        if v.has_pct_n:
            return FmtRisk.CRITICAL

        if v.fmt_spec_count > v.extra_args >= 0:
            return FmtRisk.DANGEROUS

        if v.fmt_source in (FmtSource.STACK, FmtSource.ARG):
            return FmtRisk.DANGEROUS

        return FmtRisk.SUSPICIOUS

    def _build_evidence(self, v: DeepFmtVerdict) -> List[str]:
        """生成证据链"""
        e = []
        e.append(f"fmt来源: {v.fmt_source.value}")

        if v.fmt_content_hint:
            e.append(f"fmt内容片段: \"{v.fmt_content_hint[:60]}\"")
        else:
            e.append("fmt内容: 无法静态解析")

        spec_info = f"格式符={v.fmt_spec_count}"
        if v.extra_args >= 0:
            spec_info += f" 额外参数={v.extra_args}"
        e.append(spec_info)

        if v.has_pct_n:
            e.append("检测到%n-可写入任意内存地址→最高风险")
        if v.fmt_source != FmtSource.CONST_RODATA:
            e.append("fmt非.rodata常量-用户可能控制格式串")
        if v.fmt_spec_count > v.extra_args >= 0:
            e.append(f"格式符({v.fmt_spec_count})>参数({v.extra_args})→可能栈泄露")

        e.append(f"综合风险: {v.risk.value}")
        return e
