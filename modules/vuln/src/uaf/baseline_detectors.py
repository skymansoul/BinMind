"""DRIFT对比基线检测器 — SameReg + PatternMatch.

SameRegBaseline: free参数寄存器==use解引用寄存器 → UAF
  代表常规静态分析工具的简化方法 (无对象身份, 无CFG).
PatternMatch: free后第一个解引用 → UAF
  代表最朴素的模式匹配 (无寄存器验证).

与DRIFT的区别: 无对象身份追踪, 无堆对象区分, 无多阶段FP过滤.

创建: 2025-04-17
"""
import re
import subprocess
from typing import Dict, List


# 共享辅助

def _canon_reg(r: str) -> str:
    """寄存器名规范化为64位形式."""
    r = r.lower().strip()
    m = {'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
         'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
         'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10', 'r11d': 'r11',
         'r12d': 'r12', 'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15'}
    return m.get(r, r)


def _objdump(binary_path: str) -> List[str]:
    """反汇编二进制, 返回asm行列表."""
    proc = subprocess.run(
        ['objdump', '-d', '-M', 'intel', binary_path],
        capture_output=True, text=True, timeout=30,
        encoding='utf-8', errors='replace')
    if proc.returncode != 0:
        raise RuntimeError(f'objdump failed: {binary_path}')
    return proc.stdout.split('\n')


# 共享编译正则

_FREE_PAT = re.compile(
    r'\bcall\s+(?:[0-9a-f]+\s+<)?(free|kfree|vfree|delete|_ZdlPv|_ZdaPv)'
    r'(?:@plt)?>?\b', re.I)
_DEREF_PAT = re.compile(
    r'\b(mov|movzx|movsx|add|sub|cmp|test|and|or|xor)\s+'
    r'(\w+),\s*(?:(?:qword|dword|word|byte)(?:\s+ptr)?\s+)?'
    r'\[(\w+)([+\-]\s*(?:0x[0-9a-f]+|\d+))?\]', re.I)


def _find_free_arg(lines: List[str], idx: int) -> str:
    """向前5条指令找free参数的来源寄存器."""
    for j in range(idx - 1, max(idx - 6, -1), -1):
        line = lines[j].strip().lower()
        m = re.search(r'\bmov\s+(rdi|rcx|edi|ecx),?\s*(\w+)', line)
        if m:
            return _canon_reg(m.group(2))
    return 'rdi'


# SameRegister基线

def detect_same_reg(binary_path: str) -> dict:
    """半朴素: free→use配对必须同一寄存器.

    方法:
      1. objdump反汇编
      2. 找所有call free, 提取free参数来源寄存器
      3. 找free后第一条解引用, 只保留同一寄存器的配对
      4. 无对象身份追踪 — 所有free共享同一寄存器时无法区分
    """
    lines = _objdump(binary_path)
    findings = []
    free_indices = [
        i for i, l in enumerate(lines)
        if _FREE_PAT.search(l.strip().lower())
    ]

    for fl in free_indices:
        free_reg = _find_free_arg(lines, fl)
        for i in range(fl + 1, min(fl + 50, len(lines))):
            il = lines[i].strip()
            deref_m = _DEREF_PAT.search(il)
            if deref_m:
                reg = _canon_reg(deref_m.group(3))
                if reg in ('rip', 'rsp', 'rbp', 'rsi', 'rdi'):
                    continue
                if reg == free_reg:
                    findings.append({
                        'free_line': fl, 'use_line': i,
                        'reg': reg, 'instruction': il[:80],
                    })
                break

    return {'uaf_count': len(findings), 'df_count': 0, 'findings': findings}


# PatternMatch基线

def detect_pattern(binary_path: str) -> dict:
    """纯模式匹配: free后第一条[reg]解引用 → UAF.

    无寄存器验证, 无对象身份, 无CFG — 最大化FP率.
    作为"最naive"的对比基准.
    """
    lines = _objdump(binary_path)
    findings = []
    free_indices = [
        i for i, l in enumerate(lines)
        if _FREE_PAT.search(l.strip().lower())
    ]

    for fl in free_indices:
        for i in range(fl + 1, min(fl + 50, len(lines))):
            il = lines[i].strip()
            deref_m = _DEREF_PAT.search(il)
            if deref_m:
                reg = deref_m.group(3).lower()
                if reg in ('rip', 'rsp', 'rbp'):
                    continue  # 栈/指令指针解引用 → 跳过, 继续找
                findings.append({
                    'free_line': fl, 'use_line': i,
                    'reg': reg, 'instruction': il[:80],
                })
                break  # 找到有效的非栈解引用 → 停止

    return {'uaf_count': len(findings), 'df_count': 0, 'findings': findings}
