"""
格式串参数偏移推断器 — 从调用点反推fmt参数在栈/寄存器中的位置。

核心改进（相比基础format_string_detector.py）:
  基础版仅检测"printf(fmt)且fmt非常量→漏洞", 不量化利用难度。
  本模块推断fmt参数的确切栈偏移, 这是评估%n/$符号利用的关键信息。

x86-64调用约定:
  前6个参数: rdi, rsi, rdx, rcx, r8, r9
  第7+参数: 栈上 [rsp+8], [rsp+16], ...
  printf的第1个参数(rdi)=格式串; 后续参数从rsi开始

偏移推断方法:
  1. 前向扫描call附近的push/mov, 统计栈操作
  2. 反推fmt在参数序列中的位置 → 攻击者需要多少$Nx才能访问fmt后的数据
  3. 结合%n可用性评估: 若fmt在rdi(偏移1)且输出可见→%n高可用

修改记录:
  创建 2026-08-09
"""
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple


@dataclass
class FormatOffset:
    call_insn_idx: int
    format_func: str
    fmt_arg_position: int       # fmt在参数列表中的位置(1-based)
    total_args: int             # 调用传递的总参数估计
    stack_args_start: int       # 第一个栈参数的偏移(rsp+X)
    pct_n_feasible: bool        # %n是否可实际利用
    direct_parm_access: bool    # 攻击者能否用%1$x直接访问
    exploit_confidence: str     # high/medium/low


_FORMAT_FUNCS = {
    'printf': 0, 'fprintf': 1, 'sprintf': 1, 'snprintf': 2,
    'dprintf': 1, 'syslog': 1, 'vprintf': 0, 'vfprintf': 1,
    'vsprintf': 1, 'vsnprintf': 2,
}


def _count_push_ops(instructions: List[str], call_idx: int, window: int = 8) -> int:
    """统计call之前的push操作数"""
    count = 0
    for j in range(max(0, call_idx - window), call_idx):
        insn = instructions[j].lower()
        if insn.startswith('push') or 'push' in insn.split()[:1]:
            count += 1
    return count


def infer_fmt_offset(
    instructions: List[str],
    call_idx: int,
    func_name: str,
) -> FormatOffset:
    """
    推断格式串在调用中的参数偏移位置。

    x86-64 ABI:
      args[0]=rdi, args[1]=rsi, ..., args[5]=r9, args[6+]=stack
    """
    fmt_idx = _FORMAT_FUNCS.get(func_name, -1)
    if fmt_idx < 0:
        fmt_idx = 0

    push_count = _count_push_ops(instructions, call_idx)
    total_args = 6 + push_count  # 6 reg args + N stack args
    # fmt在参数列表中的位置: rdi=1, rsi=2, ...
    fmt_arg_position = fmt_idx + 1

    # 第一个栈参数的偏移 (跳过返回地址)
    stack_args_start = 8  # rsp+8 after call pushes return address

    # %n可行性: 非stderr/syslog输出→可用
    pct_n_ok = not any(kw in func_name.lower()
                       for kw in ('stderr', 'syslog'))

    # 直接参数访问: fmt位置 <= 6 → 用%N$x直接访问
    direct = fmt_arg_position <= 6

    # 利用置信度
    if direct and pct_n_ok:
        confidence = 'high'
    elif direct or pct_n_ok:
        confidence = 'medium'
    else:
        confidence = 'low'

    return FormatOffset(
        call_insn_idx=call_idx,
        format_func=func_name,
        fmt_arg_position=fmt_arg_position,
        total_args=total_args,
        stack_args_start=stack_args_start,
        pct_n_feasible=pct_n_ok,
        direct_parm_access=direct,
        exploit_confidence=confidence)
