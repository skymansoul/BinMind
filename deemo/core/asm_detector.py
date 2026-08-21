"""
汇编级回退检测: 不依赖反编译器, 用 Capstone 直接反汇编 .text 段扫描漏洞特征。
反编译失败时独立工作, 成功时作为正交证据源交叉验证。
检测模式 (x86_64): printf 前 rdi 指向栈上数据 (格式字符串)、gets/strcpy 到小缓冲区 (栈溢出)、free 后同寄存器写入 (UAF);
限制为仅支持 x86_64 ELF。
"""

from __future__ import annotations

import logging
import os
import re
import struct
from typing import Any, Dict, List, Optional

_log = logging.getLogger(__name__)

# 危险调用目标（按函数名）
_DANGER_CALLS = {
    'printf', 'fprintf', 'sprintf', 'snprintf',   # 格式字符串
    'gets', 'strcpy', 'strcat',                    # 栈溢出
    'free',                                         # UAF/double-free
    'system', 'popen',                              # 命令注入
}

def detect_from_assembly(
    binary_path: str,
    func_name: str | None = None,
) -> list[dict[str, Any]]:
    """从汇编代码检测漏洞, 反编译无关的独立检测路径。

    返回 finding 列表，格式与 format_string_detector/stack_overflow_analyzer 兼容。
    若 Capstone 不可用或文件非 ELF，返回空列表。
    """
    findings: list[dict[str, Any]] = []

    try:
        import capstone
    except ImportError:
        _log.debug("capstone unavailable, assembly detection skipped")
        return findings

    if not os.path.isfile(binary_path):
        return findings

    text_data, text_base = _extract_text_section(binary_path)
    if not text_data:
        return findings

    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True

    instructions: list[tuple[int, str, str, str]] = []
    for insn in md.disasm(text_data, text_base):
        instructions.append((insn.address, insn.mnemonic, insn.op_str,
                             _capstone_group_name(insn)))

    fmt_findings = _detect_format_string_asm(instructions, func_name)
    findings.extend(fmt_findings)

    so_findings = _detect_stack_overflow_asm(instructions, func_name)
    findings.extend(so_findings)

    uaf_findings = _detect_uaf_asm(instructions, func_name)
    findings.extend(uaf_findings)

    return findings

def _extract_text_section(binary_path: str) -> tuple[bytes | None, int]:
    """从 ELF 中提取 .text 段的内容和基址。"""
    try:
        with open(binary_path, 'rb') as f:
            header = f.read(64)
            if header[:4] != b'\x7fELF':
                return None, 0

            is_64bit = header[4] == 2
            if not is_64bit:
                return None, 0

            e_shoff = struct.unpack('<Q', header[40:48])[0]
            e_shentsize = struct.unpack('<H', header[58:60])[0]
            e_shnum = struct.unpack('<H', header[60:62])[0]
            e_shstrndx = struct.unpack('<H', header[62:64])[0]

            f.seek(e_shoff + e_shstrndx * e_shentsize)
            shstr = f.read(e_shentsize)
            shstr_offset = struct.unpack('<Q', shstr[24:32])[0]
            shstr_size = struct.unpack('<Q', shstr[32:40])[0]

            f.seek(shstr_offset)
            shstr_data = f.read(shstr_size)

            for i in range(e_shnum):
                f.seek(e_shoff + i * e_shentsize)
                sh = f.read(e_shentsize)
                sh_name = struct.unpack('<I', sh[0:4])[0]
                name = shstr_data[sh_name:shstr_data.index(b'\x00', sh_name)].decode()

                if name == '.text':
                    sh_offset = struct.unpack('<Q', sh[24:32])[0]
                    sh_size = struct.unpack('<Q', sh[32:40])[0]
                    sh_addr = struct.unpack('<Q', sh[16:24])[0]
                    f.seek(sh_offset)
                    return f.read(sh_size), sh_addr
    except Exception as e:
        _log.debug("ELF section extraction failed: %s", e)
    return None, 0

def _detect_format_string_asm(
    instructions: list[tuple[int, str, str, str]],
    func_name: str | None,
) -> list[dict[str, Any]]:
    """汇编级格式字符串检测: call printf 前 rdi 是否指向栈上数据。"""
    findings: list[dict[str, Any]] = []
    for i, (addr, mnem, op_str, group) in enumerate(instructions):
        if mnem != 'call' or 'printf' not in op_str:
            continue
        # 向前搜索 5 条指令，找 rdi 的来源
        for j in range(max(0, i - 5), i):
            prev_addr, prev_mnem, prev_op, _ = instructions[j]
            if prev_mnem == 'lea' and 'rdi' in prev_op and 'rsp' in prev_op:
                findings.append({
                    'rule_id': 'ASM-FMT',
                    'type': 'format-string',
                    'function': func_name or 'unknown',
                    'severity': 'High',
                    'call_address': addr,
                    'detection_method': 'assembly-level',
                    'description': (
                        f'printf call at 0x{addr:x}: rdi loaded from stack offset '
                        f'via {prev_mnem} {prev_op} — potential format string vuln'
                    ),
                    'cwe': 'CWE-134',
                })
                break
    return findings

def _detect_stack_overflow_asm(
    instructions: list[tuple[int, str, str, str]],
    func_name: str | None,
) -> list[dict[str, Any]]:
    """汇编级栈溢出检测: call gets/strcpy 到小缓冲区。"""
    findings: list[dict[str, Any]] = []
    for i, (addr, mnem, op_str, group) in enumerate(instructions):
        if mnem != 'call':
            continue
        callee = op_str.lower().split()[-1] if op_str else ''
        if callee not in ('gets', 'strcpy', 'strcat', 'sprintf'):
            continue
        # 向前搜索 rdi 的设置
        for j in range(max(0, i - 5), i):
            prev_addr, prev_mnem, prev_op, _ = instructions[j]
            if prev_mnem == 'lea' and 'rdi' in prev_op and 'rsp' in prev_op:
                # 尝试解析 rsp 偏移量
                offset_m = re.search(r'\[\s*rsp\s*[-+]\s*(\w+)\]', prev_op)
                if offset_m:
                    try:
                        offset = int(offset_m.group(1), 16) if offset_m.group(1).startswith('0x') else int(offset_m.group(1))
                        # 偏移量小 (<256 字节), 小缓冲区, 溢出风险高
                        if offset < 256:
                            findings.append({
                                'rule_id': 'ASM-SO',
                                'type': 'stack-overflow',
                                'function': func_name or 'unknown',
                                'severity': 'Critical',
                                'call_address': addr,
                                'detection_method': 'assembly-level',
                                'buffer_size_estimate': offset,
                                'description': (
                                    f'{callee} call at 0x{addr:x}: buffer at '
                                    f'rsp+{offset} — estimated {offset} bytes, '
                                    f'high overflow risk'
                                ),
                                'cwe': 'CWE-121',
                            })
                    except ValueError:
                        pass
                break
    return findings

def _detect_uaf_asm(
    instructions: list[tuple[int, str, str, str]],
    func_name: str | None,
) -> list[dict[str, Any]]:
    """汇编级 UAF 检测: free 后同一寄存器用于 memory write。简化版仅检测 free(X) 后 mov [X], Y 模式。"""
    findings: list[dict[str, Any]] = []
    free_regs: dict[int, str] = {}

    for addr, mnem, op_str, group in instructions:
        if mnem == 'call' and 'free' in op_str:
            # 向前找 rdi 的值来源, 通常是 mov rdi, reg
            for j in range(len(instructions)):
                if instructions[j][0] == addr:
                    for k in range(max(0, j - 3), j):
                        prev_mnem = instructions[k][1]
                        prev_op = instructions[k][2]
                        if prev_mnem == 'mov' and 'rdi' in prev_op:
                            parts = prev_op.split(',')
                            if len(parts) == 2 and parts[0].strip() == 'rdi':
                                free_reg = parts[1].strip()
                                free_regs[addr] = free_reg
                    break

        if mnem == 'mov' and '[' in op_str:
            dest_reg = op_str.split('[')[1].split(']')[0].strip()
            for free_addr, free_reg in free_regs.items():
                if free_addr < addr and dest_reg == free_reg:
                    findings.append({
                        'rule_id': 'ASM-UAF',
                        'type': 'heap-corruption',
                        'function': func_name or 'unknown',
                        'severity': 'Critical',
                        'description': (
                            f'UAF: register {free_reg} was passed to free at '
                            f'0x{free_addr:x}, then used in memory write at '
                            f'0x{addr:x} ({mnem} {op_str})'
                        ),
                        'cwe': 'CWE-416',
                        'detection_method': 'assembly-level',
                    })
                    break
    return findings

def _capstone_group_name(insn) -> str:
    try:
        if hasattr(insn, 'group_name'):
            return insn.group_name()
    except Exception:
        pass
    return ''
