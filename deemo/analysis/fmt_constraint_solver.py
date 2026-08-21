"""
格式串约束求解器 — 从反编译伪代码推导 printf 参数来源和栈偏移。

核心算法:
  1. 识别格式串调用的第0参数 (fmt_str) 来源: 常量/栈变量/堆变量/外部输入
  2. 当 fmt_str 为用户可控时, 解析格式说明符计算可利用原语
  3. 基于调用约定 (x86_64: rdi=fmt, rsi=a1, rdx=a2, rcx=a3, r8=a4, r9=a5, stack≥a6)
     估算 %n$ 位置参数的栈偏移

误报削减策略 (FSCS — Format String Constraint System):
  - 编译时常量格式串 → SAFE (不报告)
  - 不含 %n/%s 写/读原语 → LOW (仅信息泄露, 非任意写)
  - 位置参数不足 → UNCERTAIN (保守保留)
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

class FmtArgSource(Enum):
    CONSTANT = "constant"        # 编译时已知的字符串字面量
    STACK_VAR = "stack_var"      # 栈上局部变量
    HEAP_VAR = "heap_var"        # 堆分配的缓冲区
    EXTERNAL_INPUT = "external"  # argv/recv/read/scanf 等外部输入

class FmtRisk(Enum):
    SAFE = 0       # 格式串为常量, 无风险
    LOW = 1        # 仅信息泄露 (%x, %p), 无任意写
    MEDIUM = 2     # 含 %s (任意读), 可能泄露地址
    HIGH = 3       # 含 %n (任意写), 可劫持控制流
    CRITICAL = 4   # 用户完全可控格式串 + %n 可用

_RE_FMT_SPEC = re.compile(
    r'%(\d+\$)?([-+ #0]*)(\d*|\*)(\.\d*|\.\*)?([hljztL]?)([diouxXeEfFgGaAcspn])')
_RE_FMT_CALL = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf|syslog|err|warn)\s*\(')
_RE_FMT_ARG0 = re.compile(
    r'(printf|fprintf|sprintf|snprintf|dprintf)\s*\(\s*([^,)]+)')
_RE_VAR_ASSIGN = re.compile(
    r'(\w[\w.\->]*)\s*=\s*(.+)')
_RE_EXTERNAL_SRC = re.compile(
    r'(argv|getenv|recv|read|scanf|fgets|gets|atoi|strtol)')

@dataclass
class FmtCallSite:
    """格式串调用点记录。"""
    func: str              # printf / sprintf / ...
    lineno: int
    fmt_arg: str           # 格式串参数的文本表达式
    fmt_source: FmtArgSource
    fmt_text: str = ""     # 若为常量, 则记录格式串内容
    risk: FmtRisk = FmtRisk.SAFE
    has_percent_n: bool = False
    has_percent_s: bool = False
    user_controlled: bool = False

def analyze_format_calls(code: str) -> List[FmtCallSite]:
    """分析代码中所有格式串调用点, 判定风险等级。

    返回按风险降序排列的 FmtCallSite 列表。
    """
    calls: List[FmtCallSite] = []
    lines = code.split('\n')

    for i, line in enumerate(lines, 1):
        m = _RE_FMT_ARG0.search(line)
        if not m:
            continue
        func, arg0 = m.group(1), m.group(2).strip()

        # 判定格式串来源
        source, fmt_text = _classify_fmt_source(arg0, code)
        risk = FmtRisk.SAFE
        has_n, has_s = False, False

        if source == FmtArgSource.CONSTANT:
            risk = FmtRisk.SAFE
            has_n, has_s = _scan_specifiers(fmt_text)
        elif source == FmtArgSource.EXTERNAL_INPUT:
            risk = FmtRisk.CRITICAL
            has_n, has_s = True, True  # 保守: 假设用户可注入任意说明符
        elif source in (FmtArgSource.HEAP_VAR, FmtArgSource.STACK_VAR):
            risk = FmtRisk.HIGH if _has_input_taint(arg0, code) else FmtRisk.MEDIUM

        calls.append(FmtCallSite(
            func=func, lineno=i, fmt_arg=arg0,
            fmt_source=source, fmt_text=fmt_text,
            risk=risk, has_percent_n=has_n, has_percent_s=has_s,
            user_controlled=(source == FmtArgSource.EXTERNAL_INPUT),
        ))

    # 函数指针传递 printf 检测
    # 模式: void wrapper(fn, data) { fn(data); } + wrapper((cast)printf, user_input)
    _RE_FN_PTR_CALL = re.compile(
        r'(?:printf|fprintf|sprintf|snprintf|dprintf)\s*\)')
    _RE_WRAPPER_DEF = re.compile(
        r'(?:void|int)\s+(\w+)\s*\(\s*\w+\s+(\w+)\s*,\s*(?:const\s+)?char\s*\*\s*(\w+)\s*\)')
    _RE_FN_PTR_INVOKE = re.compile(r'(\w+)\s*\(\s*(\w+)\s*\)')

    for i, line in enumerate(lines, 1):
        # 检测 wrapper 定义: void call_fmt(fn, data) { ... fn(data) ... }
        wm = _RE_WRAPPER_DEF.search(line)
        if wm:
            wrapper_name = wm.group(1)
            fn_param = wm.group(2)
            data_param = wm.group(3)
            # 在函数体内找 fn(data) 或 fn(data, ...)
            body_start = i - 1  # i 是1-indexed, lines 是0-indexed
            for j in range(body_start, min(len(lines), body_start + 5)):
                body_line = lines[j] if j < len(lines) else ''
                if f'{fn_param}({data_param})' in body_line or \
                   f'{fn_param}({data_param},' in body_line:
                    # 在完整代码中找 wrapper(printf, user_data) 调用
                    wrapper_call_pat = re.compile(
                        rf'{wrapper_name}\s*\(\s*\(?\s*\w+\s*\*?\s*\)?\s*printf\s*,'
                        r'\s*([^)]+)\s*\)')
                    wc = wrapper_call_pat.search(code)
                    if wc:
                        data_arg = wc.group(1).strip()
                        source, fmt_text = _classify_fmt_source(data_arg, code)
                        risk = FmtRisk.CRITICAL if source == FmtArgSource.EXTERNAL_INPUT else FmtRisk.MEDIUM
                        calls.append(FmtCallSite(
                            func='printf(fn_ptr)', lineno=j + 1,
                            fmt_arg=data_arg, fmt_source=source,
                            fmt_text=fmt_text, risk=risk,
                            has_percent_n=True, has_percent_s=True,
                            user_controlled=(source == FmtArgSource.EXTERNAL_INPUT),
                        ))
                    break

    # 按风险降序
    calls.sort(key=lambda c: c.risk.value, reverse=True)
    return calls

def _classify_fmt_source(arg0: str, code: str) -> Tuple[FmtArgSource, str]:
    """判定格式串参数的来源类别。"""
    arg0 = arg0.strip()

    # 字符串字面量: "format %d" 或 'format %d'
    str_match = re.match(r'^"([^"]*)"$', arg0) or re.match(r"^'([^']*)'$", arg0)
    if str_match:
        return FmtArgSource.CONSTANT, str_match.group(1)

    # 变量名 → 在代码中查找赋值来源
    var_match = re.match(r'^(\w[\w.\->]*)$', arg0)
    if var_match:
        var = var_match.group(1)
        return _trace_var_source(var, code)

    return FmtArgSource.EXTERNAL_INPUT, ""

def _trace_var_source(var: str, code: str) -> Tuple[FmtArgSource, str]:
    """回溯变量的定义, 判定其来源。"""
    # 在代码中搜索 var = ... 的赋值
    for line in code.split('\n'):
        # char *fmt = getenv("LOGFMT")
        if re.search(rf'\b{re.escape(var)}\s*=\s*getenv\s*\(', line):
            return FmtArgSource.EXTERNAL_INPUT, ""
        if re.search(rf'\b{re.escape(var)}\s*=\s*argv\[', line):
            return FmtArgSource.EXTERNAL_INPUT, ""
        if re.search(rf'\b{re.escape(var)}\s*=\s*malloc', line):
            return FmtArgSource.HEAP_VAR, ""
        # "%s" 等常量初始化
        str_match = re.search(rf'\b{re.escape(var)}\s*=\s*"([^"]*)"', line)
        if str_match:
            return FmtArgSource.CONSTANT, str_match.group(1)

    return FmtArgSource.STACK_VAR, ""

def _has_input_taint(var: str, code: str) -> bool:
    """检查变量是否可能被外部输入污染。"""
    for line in code.split('\n'):
        if re.search(rf'\b{re.escape(var)}\b', line) and _RE_EXTERNAL_SRC.search(line):
            return True
    return False

def _scan_specifiers(fmt_text: str) -> Tuple[bool, bool]:
    """扫描格式串中的说明符, 返回 (has_percent_n, has_percent_s)。"""
    has_n, has_s = False, False
    for m in _RE_FMT_SPEC.finditer(fmt_text):
        spec = m.group(6)
        if spec == 'n':
            has_n = True
        elif spec == 's':
            has_s = True
    return has_n, has_s

def estimate_stack_offset(call_site: FmtCallSite, arch: str = "x86_64") -> Optional[int]:
    """估算 %n$ 位置参数对应的栈偏移 (相对于 rsp)。

    x86_64 调用约定 (System V AMD64):
      - 第1-6个整数参数: rdi, rsi, rdx, rcx, r8, r9
      - fmt_str 占 rdi → 实际 vararg 从 rsi 开始
      - 第 n 个 vararg 在栈上的偏移 = (n-5)*8 (当 n>5 时)

    返回: 栈偏移 (字节), 或 None (无法确定)
    """
    if call_site.fmt_source == FmtArgSource.CONSTANT and call_site.fmt_text:
        # 从格式串计数 % 说明符数, 计算最深层参数的栈偏移
        specs = _RE_FMT_SPEC.findall(call_site.fmt_text)
        return len(specs) * 8  # 近似: 每个参数8字节
    return None

def score_exploitability(call: FmtCallSite) -> float:
    """计算格式串漏洞的可利用性评分 (0-10, CVSS风格)。"""
    score = 0.0
    if call.fmt_source == FmtArgSource.EXTERNAL_INPUT:
        score += 5.0
    elif call.fmt_source == FmtArgSource.HEAP_VAR:
        score += 2.0
    elif call.fmt_source == FmtArgSource.STACK_VAR:
        score += 1.0

    if call.has_percent_n:
        score += 3.0  # 任意写, 直接利用
    if call.has_percent_s:
        score += 1.0  # 信息泄露辅助

    if call.user_controlled:
        score += 1.0  # 可控输入提高可利用性

    return min(10.0, score)
