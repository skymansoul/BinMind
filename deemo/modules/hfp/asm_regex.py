"""
汇编翻译器 — 指令正则与 ABI 常量表.

x86-64 指令解析所需的正则与 ABI 常量集中于此. 语义要点:
  - Intel 语法 (objdump -M intel)
  - 32 位写别名统一到 64 位 (mov ecx,imm 同时写 rcx)
  - 寄存器基址访问支持 [rax+off] 形式 (堆别名追踪)
  - 低 8 位寄存器 dl/cl 等 (字节写源)
"""

from __future__ import annotations

import re

_WIN64_ARGS = ['rcx', 'rdx', 'r8', 'r9']
_SYSV_ARGS = ['rdi', 'rsi', 'rdx', 'rcx']
_ALLOC_FUNCS = ('malloc', 'calloc', 'realloc')
_COPY_FUNCS = ('memcpy', 'memset', 'strcpy', 'strncpy', 'memmove')
_LEN_FUNCS = ('strlen',)
# 格式化字符串函数族: 检测器据此提取格式化串与参数
_FMT_FUNCS = ('printf', 'fprintf', 'sprintf', 'snprintf', 'dprintf',
              'vprintf', 'vfprintf', 'vsprintf', 'vsnprintf', 'syslog')

# 32 位写别名: 写低 32 位会清零高 32 位, 常量语义下等价全量赋值
_REG_ALIAS = {
    'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
    'esi': 'rsi', 'edi': 'rdi', 'r8d': 'r8', 'r9d': 'r9',
    'r10d': 'r10', 'r11d': 'r11', 'r12d': 'r12',
    'r13d': 'r13', 'r14d': 'r14', 'r15d': 'r15',
}

_RE_INSN = re.compile(
    r'^\s*[0-9a-fA-F]+:\s*[0-9a-fA-F ]+?\t([a-z][a-z0-9]*)\s*(.*)$',
    re.IGNORECASE)
_RE_MOV_IMM = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$',
    re.IGNORECASE)
_RE_MOV_REG = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*'
    r'(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*$',
    re.IGNORECASE)
_RE_LEA = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+)\s*,\s*\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]',
    re.IGNORECASE)
# lea 寄存器基址: lea rcx,[rax+0x7] — rax 为堆别名时指向该缓冲
_RE_LEA_REG = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+)\s*,\s*\['
    r'(r[a-z0-9]+|e[a-z0-9]+)([+-](?:0x[0-9a-fA-F]+|\d+))?\]',
    re.IGNORECASE)
_RE_MOV_MEM = re.compile(
    r'^\s*(?:qword|dword|word|byte)\s*ptr\s*\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\],\s*'
    r'(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)',
    re.IGNORECASE)
_RE_CALL = re.compile(r'^\s*call\s+([\w.@]+)', re.IGNORECASE)
_RE_LOAD_STACK = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*'
    r'(?:qword|dword|word|byte)?\s*ptr\s*\[(rbp|rsp)([+-])(0x[0-9a-fA-F]+|\d+)\]',
    re.IGNORECASE)
# 寄存器基址装载: mov rcx,[rax+0x7] — rax 为堆别名时视为字段地址
_RE_LOAD_REG_BASE = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*'
    r'(?:qword|dword|word|byte)?\s*ptr\s*\['
    r'(r[a-z0-9]+|e[a-z0-9]+)([+-](?:0x[0-9a-fA-F]+|\d+))?\]\s*$',
    re.IGNORECASE)
# 寄存器基址存储: mov BYTE PTR [rax],dl / mov [rax+0x4],rdx
_RE_STORE_REG_BASE = re.compile(
    r'^\s*(?:qword|dword|word|byte)?\s*ptr\s*\['
    r'(r[a-z0-9]+|e[a-z0-9]+)([+-](?:0x[0-9a-fA-F]+|\d+))?\],\s*'
    r'(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d|[abcd][lh])\s*$',
    re.IGNORECASE)
# 立即数存储: mov BYTE PTR [rax],0x1b
_RE_STORE_REG_IMM = re.compile(
    r'^\s*(?:qword|dword|word|byte)?\s*ptr\s*\['
    r'(r[a-z0-9]+|e[a-z0-9]+)([+-](?:0x[0-9a-fA-F]+|\d+))?\],\s*'
    r'(0x[0-9a-fA-F]+|\d+)\s*$',
    re.IGNORECASE)
_RE_ADD_IMM = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$',
    re.IGNORECASE)
_RE_ADD_REG = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*'
    r'(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*$',
    re.IGNORECASE)
_RE_SHL_IMM = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$',
    re.IGNORECASE)
_RE_LEA_SCALE = re.compile(
    r'^\s*(r[a-z0-9]+)\s*,\s*\[(r[a-z0-9]+)\*(\d+)([+-](?:0x[0-9a-fA-F]+|\d+))?\]',
    re.IGNORECASE)
# 双寄存器索引 lea: lea rdx,[rcx+rax*1] — 基址+缩放索引
_RE_LEA_INDEX = re.compile(
    r'^\s*(r[a-z0-9]+)\s*,\s*\['
    r'(r[a-z0-9]+)\+?(r[a-z0-9]+)?\*?(\d+)?\]',
    re.IGNORECASE)
_RE_CMP_IMM = re.compile(
    r'^\s*(r[a-z0-9]+|e[a-z0-9]+|r8d|r9d)\s*,\s*(0x[0-9a-fA-F]+|\d+)\s*$',
    re.IGNORECASE)
_RE_JCC_LT = re.compile(r'\b(jl|jb|jle|jbe)\b', re.IGNORECASE)
_RE_JCC_GT = re.compile(r'\b(jg|ja|jge|jae)\b', re.IGNORECASE)
_RE_JCC_EQ = re.compile(r'\b(je|jz|jne|jnz)\b', re.IGNORECASE)
_RE_FN_LABEL = re.compile(
    r'^([0-9a-fA-F]+)\s+<([^>]+)>:\s*$')

# 匹配反汇编中的 memcpy(mov rcx,[rbp+0x10] 后 call memcpy) 模式
_RE_COPY_LINE = re.compile(
    r'(memcpy|memset|strcpy|strncpy)\s*\(\s*'
    r'([^,]+),\s*([^,]+),\s*([^)]+)\)', re.IGNORECASE)


def norm_reg(reg: str) -> str:
    """寄存器名归一: 32 位写别名映射到 64 位."""
    return _REG_ALIAS.get(reg, reg)


def split_into_functions(lines, insn_re) -> list:
    """按 '<name>:' 标签把反汇编行分割为函数块.

    返回 [(fn_name, [指令行]), ...]. 标签行本身被排除。
    无标签的指令归入前一个函数; 首个函数无标签时名为空。
    """
    blocks: list = []
    cur_name = ''
    cur_lines: list = []
    for line in lines:
        m = _RE_FN_LABEL.match(line)
        if m:
            if cur_lines:
                blocks.append((cur_name, cur_lines))
            cur_name = m.group(2)
            cur_lines = []
            continue
        if insn_re.match(line):
            cur_lines.append(line)
    if cur_lines:
        blocks.append((cur_name, cur_lines))
    return blocks