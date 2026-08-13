"""
格式化字符串漏洞检测 — 参数偏移推断 + %n可用性分析。

检测逻辑:
  1. 定位printf/sprintf/fprintf/syslog等格式化函数调用
  2. 检查fmt参数是否为变量 (非字符串常量) → 潜在格式串漏洞
  3. 推断fmt参数在栈上的偏移位置 → 评估攻击者能否通过%N$x访问任意参数
  4. 检查%n是否可用 (取决于输出目标和可见性)

与format_string_scorer.py (output模块) 的分工:
  本模块: 检测是否存在格式串漏洞 (detection)
  format_string_scorer: 量化已检出漏洞的利用精度 (scoring)

修改记录:
  创建 2025-03-28
"""

from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class FormatStringFinding:
    location: str
    format_func: str            # printf / sprintf / fprintf / syslog
    format_arg_index: int       # fmt参数在参数列表中的位置 (1-based)
    is_constant: bool           # fmt是否为编译时常量
    pct_n_available: bool       # %n是否可用
    output_visible: bool        # 攻击者能否看到输出
    stack_offset_estimate: int  # 估计的栈偏移
    confidence: str


_FORMAT_FUNCS = {
    'printf': 0, 'fprintf': 1, 'sprintf': 1, 'snprintf': 2,
    'dprintf': 1, 'syslog': 1, 'vsyslog': 1, 'vprintf': 0,
    'vfprintf': 1, 'vsprintf': 1, 'vsnprintf': 2,
    'err': 1, 'errx': 1, 'warn': 1, 'warnx': 1,
}


def _detect_format_arg(
    func_name: str,
    format_string_candidates: List[str],
) -> int:
    """返回fmt参数在参数列表中的位置 (1-based), 0=未找到。"""
    idx = _FORMAT_FUNCS.get(func_name, -1)
    if idx >= 0:
        return idx + 1  # 转为1-based
    return 0


def _is_constant_string(operand: str) -> bool:
    """检测操作数是否为编译时常量字符串 (从.rodata加载)。"""
    return (operand.startswith('"') or operand.startswith("'") or
            '.rodata' in operand or 'LC' in operand or 'OFFSET' in operand.upper())


def _estimate_stack_offset(instructions: List[str], call_idx: int) -> int:
    """
    估算fmt参数在栈上的偏移量 (以参数位置计)。
    简化: 从call指令往前找fmt参数的push/mov位置。
    """
    offset = 1
    push_count = 0
    for j in range(max(0, call_idx - 10), call_idx):
        insn = instructions[j].lower()
        if 'push' in insn: push_count += 1
    # x86-64: 前6个参数在寄存器中, 之后的在栈上
    if push_count > 0:
        offset = max(1, push_count)
    return offset


def detect_format_string(
    instructions: List[str],
    string_constants: Optional[Dict[int, str]] = None,
) -> List[FormatStringFinding]:
    findings: List[FormatStringFinding] = []
    constants = string_constants or {}

    for i, insn in enumerate(instructions):
        insn_lower = insn.lower().strip()
        if not ('call' in insn_lower or 'bl' in insn_lower): continue
        parts = insn_lower.split()
        if len(parts) < 2: continue
        callee = parts[-1].lstrip('*').strip('<>').split('@')[0].split('.')[-1]

        fmt_idx = _detect_format_arg(callee, [])
        if fmt_idx == 0: continue

        # 检查fmt参数是否为变量
        is_const = False
        # 简化: 在指令序列中查找紧邻的lea/mov (加载格式串地址)
        for j in range(max(0, i - 5), i):
            prev = instructions[j].lower()
            if 'lea' in prev and ('rip' in prev or '.l' in prev or 'LC' in prev):
                is_const = True; break
            if 'mov' in prev and ('offset' in prev or '.l' in prev):
                is_const = True; break

        if is_const:
            continue  # 格式串为常量 → 安全

        # 格式串是变量 → 潜在漏洞
        offset = _estimate_stack_offset(instructions, i)

        # %n可用性判断 (简化: 非stderr输出 → 可用)
        pct_n_ok = not any(kw in insn_lower for kw in ('stderr', 'syslog'))

        findings.append(FormatStringFinding(
            location=f'{callee}@{i}', format_func=callee,
            format_arg_index=fmt_idx, is_constant=is_const,
            pct_n_available=pct_n_ok, output_visible=True,
            stack_offset_estimate=offset,
            confidence='confirmed' if not is_const else 'false_positive'))

    return findings
