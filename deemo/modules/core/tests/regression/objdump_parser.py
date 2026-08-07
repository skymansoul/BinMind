#!/usr/bin/env python3
# coding: utf-8
"""
objdump 反汇编输出解析器 — 提取指令流并识别 malloc/memcpy 参数.
"""

import re
from typing import Dict, List, Optional, Tuple


def parse_objdump(output: str) -> List[Dict]:
    """将 objdump -d -M intel 输出解析为指令列表."""
    instructions = []
    addr_pattern = re.compile(
        r'^\s*([0-9a-fA-F]+):\s+((?:[0-9a-fA-F]{2}\s)+)\s+(.+)$')

    for line in output.split('\n'):
        m = addr_pattern.match(line)
        if m:
            addr = int(m.group(1), 16)
            mnemonic = m.group(3).strip().split()[0]
            comment = m.group(3).strip()
            instructions.append({
                'addr': addr, 'mnemonic': mnemonic, 'comment': comment,
            })
    return instructions


def detect_malloc_write(instructions: List[Dict]) -> Tuple[int, int]:
    """从反汇编检测 malloc(size) 和 memcpy(ptr, src, size)."""
    alloc_size = 0
    write_size = 0

    for insn in instructions:
        comment = insn.get('comment', '')
        if 'call' in insn.get('mnemonic', ''):
            if 'malloc' in comment.lower():
                alloc_size = _find_arg_immediate(
                    instructions, insn, ['ecx', 'rcx', 'edi', 'rdi'])
            elif 'memcpy' in comment.lower():
                write_size = _find_arg_immediate(
                    instructions, insn, ['r8', 'r8d', 'edx', 'rdx'])

    return alloc_size, write_size


def _find_arg_immediate(instructions: List[Dict],
                        call_insn: Dict,
                        target_regs: List[str]) -> int:
    """在 call 前搜索设置目标寄存器的立即数 (最多回溯5条指令)."""
    call_idx = None
    for i, insn in enumerate(instructions):
        if insn['addr'] == call_insn['addr']:
            call_idx = i
            break
    if call_idx is None:
        return 0

    for j in range(max(0, call_idx - 5), call_idx):
        insn = instructions[j]
        comment = insn.get('comment', '').lower()
        if 'mov' in insn.get('mnemonic', '').lower():
            for reg in target_regs:
                if reg in comment:
                    parts = comment.split(',')
                    if len(parts) >= 2:
                        imm_str = parts[-1].strip()
                        try:
                            val = int(imm_str, 0)
                            if 0 < val < 2**24:
                                return val
                        except ValueError:
                            pass
    return 0


def disassemble_sample(exe_path: str,
                       objdump_bin: str = 'objdump') -> Optional[List[Dict]]:
    """用 objdump 反汇编 → 返回解析后的指令列表."""
    import subprocess
    try:
        result = subprocess.run(
            [objdump_bin, '-d', '-M', 'intel', exe_path],
            capture_output=True, text=True, timeout=30,
        )
        if result.returncode != 0:
            return None
        return parse_objdump(result.stdout)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None
