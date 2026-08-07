"""
创建: 2026-07-22

格式化字符串偏移精确计算 — 基于函数栈帧结构的真实偏移推导。

当前 _compute_format_offset 在 x86_64 上保守返回 6（前6个参数在寄存器中）。
这是最坏情况假设, 导致偏移估算偏高——实际中格式化字符串通常在第1-3个
栈参数位置。本模块通过解析函数反汇编, 计算 printf 调用点相对于栈帧的
实际偏移。

方法: 解析反编译代码中的参数压栈/寄存器操作:
  1. 定位 printf 调用行
  2. 向前搜索参数准备指令
  3. 计数栈上传入参数的数量(超过6个寄存器参数后)
  4. 格式化字符串本身是第1个参数(rdi/栈顶) → 偏移 = 站在printf视角的栈参数位置

限制: 需要 r2 反汇编输出; 仅 x86_64; 假设标准 calling convention。
"""


import re
import subprocess
from typing import Dict, List, Optional, Tuple

from config import R2_PATH


def compute_precise_offset(binary_path: str, func_name: str,
                           format_func: str = 'printf') -> int:
    """通过 r2 反汇编精确计算格式化字符串的栈偏移。

    返回偏移值(整数); 若计算失败返回 -1。
    """
    try:
        proc = subprocess.run(
            [R2_PATH, '-q', '-e', 'io.color=false',
             '-c', f's {func_name}', '-c', 'pdf', binary_path],
            capture_output=True, text=True, timeout=15,
        )
        disasm = proc.stdout
    except Exception:
        return -1

    if not disasm:
        return -1

    # 定位 call printf 的位置
    lines = disasm.split('\n')
    call_line = -1
    for i, line in enumerate(lines):
        if f'call {format_func}' in line or f'call sym.{format_func}' in line:
            call_line = i
            break
    if call_line < 0:
        return -1

    # 向前搜索栈参数: push / mov [rsp+...] / 寄存器设置
    # x86_64: rdi=arg1(格式字符串), rsi=arg2, rdx=arg3, rcx=arg4,
    #         r8=arg5, r9=arg6, 之后在栈上
    # 找到格式字符串(rsi设置)后, 统计后续栈参数
    stack_args = 0
    for j in range(call_line - 1, max(0, call_line - 30), -1):
        line = lines[j]
        # push 指令 → 栈参数
        if 'push' in line and 'rbp' not in line:
            stack_args += 1
        # mov [rsp+N], val → 栈参数
        if re.search(r'mov\s+(qword\s+)?\[rsp\s*[+]\s*\w+\]', line):
            stack_args += 1

    # 偏移 = 前6个寄存器参数之后的栈参数位置
    # 格式字符串本身是第1个(通过rdi), 其他寄存器参数不占栈位
    # 实际栈偏移 = max(0, stack_args) + 1(从printf视角的第1个栈参数)
    offset = max(0, stack_args) + 1

    # 合理性检查
    if offset < 1 or offset > 50:
        return -1  # 不合理, 回退到启发式
    return offset


def batch_compute_offsets(binary_path: str,
                          findings: List[dict]) -> List[dict]:
    """对 finding 列表批量计算精确偏移。更新 finding['offset'] 和 finding['confidence']。"""
    for f in findings:
        if f.get('type') != 'format-string':
            continue
        func = f.get('function', '')
        fmt = f.get('format_func', 'printf')
        if not func:
            continue
        offset = compute_precise_offset(binary_path, func, fmt)
        if offset > 0:
            f['offset'] = offset
            f['confidence'] = min(1.0, f.get('confidence', 0.6) + 0.20)
            f['offset_method'] = 'stack-frame-analysis'
    return findings
