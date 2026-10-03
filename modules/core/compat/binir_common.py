# -*- coding: utf-8 -*-
"""二进制前端公共定义 — 寄存器族、函数表、记号与操作数解析."""

import re
from typing import Any, Dict, List, Optional, Tuple

# -*- coding: utf-8 -*-
"""真实二进制 IR 前端 - objdump 反汇编 + 寄存器/栈槽级数据流.

将编译产物转换为检测管线所需的五类输入:
  instructions:  [{addr, mnemonic, op_str, comment}]
  ir_ops:        {addr: {op_type, dest, src, src2, callee, ...}}
  callee_names:  {addr: callee}
  def_use_chains:{addr: [src_addr, ...]}   寄存器(族) + 栈槽粒度
  trace_events:  [{event, ptr_id, size, address}]  alloc/write/free 序列

设计决策:
  - 寄存器按族归一化 (ecx/ax/cl -> rcx), 使 VCT 的 var@addr 键稳定
  - 栈槽 [rbp-0x18] 作为变量参与 def-use, 使跨指令的 size 同源可证
  - 参数大小提取取 call 前最近的支配定义地址 (而非全局 last-def),
    避免 malloc 与 memcpy 复用同一寄存器导致的伪同源
  - stripped 二进制经导入表/PLT 解析恢复调用名, 经 call 目标 + 序言
    启发式恢复函数边界 (不依赖调试信息)
"""


import os, re, subprocess

from typing import Any, Dict, List, Optional, Tuple


# 二进制前端公共定义 — 寄存器族、函数表、记号与操作数解析.

import re
from typing import Any, Dict, List, Optional, Tuple

# 寄存器族映射: 任意子寄存器 -> 64 位全寄存器名
_REG_FAMILY: Dict[str, str] = {}
for _base in ('rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
              'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'):
    _REG_FAMILY[_base] = _base
    _REG_FAMILY[_base[1:]] = _base
for _i in range(8, 16):
    _b = f'r{_i}'
    _REG_FAMILY[f'r{_i}d'] = _b
    _REG_FAMILY[f'r{_i}w'] = _b
    _REG_FAMILY[f'r{_i}b'] = _b
_REG_FAMILY['eax'] = 'rax'; _REG_FAMILY['ebx'] = 'rbx'; _REG_FAMILY['ecx'] = 'rcx'
_REG_FAMILY['edx'] = 'rdx'; _REG_FAMILY['esi'] = 'rsi'; _REG_FAMILY['edi'] = 'rdi'
_REG_FAMILY['ax'] = 'rax';  _REG_FAMILY['bx'] = 'rbx';  _REG_FAMILY['cx'] = 'rcx'
_REG_FAMILY['dx'] = 'rdx';  _REG_FAMILY['si'] = 'rsi';  _REG_FAMILY['di'] = 'rdi'
_REG_FAMILY['al'] = 'rax';  _REG_FAMILY['bl'] = 'rbx';  _REG_FAMILY['cl'] = 'rcx'
_REG_FAMILY['dl'] = 'rdx'
_REG_FAMILY['r8d'] = 'r8';  _REG_FAMILY['r9d'] = 'r9';  _REG_FAMILY['r10d'] = 'r10'
_REG_FAMILY['r11d'] = 'r11'; _REG_FAMILY['r12d'] = 'r12'; _REG_FAMILY['r13d'] = 'r13'
_REG_FAMILY['r14d'] = 'r14'; _REG_FAMILY['r15d'] = 'r15'
_REG_FAMILY['r8w'] = 'r8';  _REG_FAMILY['r9w'] = 'r9';  _REG_FAMILY['r10w'] = 'r10'
_REG_FAMILY['r8b'] = 'r8';  _REG_FAMILY['r9b'] = 'r9';  _REG_FAMILY['r10b'] = 'r10'
_REG_FAMILY['r11b'] = 'r11'; _REG_FAMILY['r12b'] = 'r12'; _REG_FAMILY['r13b'] = 'r13'
_REG_FAMILY['r14b'] = 'r14'; _REG_FAMILY['r15b'] = 'r15'

CALLER_SAVED = {'rax', 'rcx', 'rdx', 'rsi', 'rdi', 'r8', 'r9', 'r10', 'r11'}
ARG_REGS_SYSV = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
ARG_REGS_WIN64 = ['rcx', 'rdx', 'r8', 'r9', 'r10', 'r11']

_REG_TOKEN = re.compile(
    r'\b(' + '|'.join(sorted(_REG_FAMILY, key=len, reverse=True)) + r')\b', re.I)
_MEM_TOKEN = re.compile(r'\[([a-z]+[0-9a-z]*)\s*([+\-])\s*(0x[0-9a-f]+|\d+)\]', re.I)

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc', '_znwm', '_znam', '_znaj', 'kmalloc'}
_WRITE_FUNCS = {'memcpy', 'memmove', 'memset', 'strcpy', 'strncpy', 'strcat',
                'strncat', 'sprintf', 'snprintf', 'strlcpy'}
_FREE_FUNCS = {'free', '_zdl', '_zda', 'kfree'}
_INPUT_FUNCS = {'read', 'fread', 'recv', 'recvfrom', 'fgets', 'gets', 'scanf',
                'fscanf', 'getc', 'fgetc', 'readfile'}

# 公共别名 (兼容外部导入)
ALLOC_FUNCS = _ALLOC_FUNCS
WRITE_FUNCS = _WRITE_FUNCS
FREE_FUNCS = _FREE_FUNCS
INPUT_FUNCS = _INPUT_FUNCS

# 分配函数: (名称, 大小参数序号 0-based, 是否可求积)
ALLOC_SIGS = {'malloc': (0, False), 'kmalloc': (0, False),
              'realloc': (1, False), '_znwm': (0, False),
              '_znam': (0, False), '_znaj': (0, False),
              'calloc': (1, True)}
WRITE_SIGS = {'memcpy': (2,), 'memmove': (2,), 'memset': (2,),
              'strncpy': (2,), 'strncat': (2,), 'snprintf': (1,),
              'strlcpy': (2,), 'strcpy': None, 'strcat': None,
              'sprintf': None}
# 无显式长度的写入 (strcpy/strcat/sprintf): 长度取决于源字符串内容


def norm_name(name: str) -> str:
    n = name.lstrip('_')
    if n.endswith('@plt') or n.endswith('@got'):
        n = n[:n.rfind('@')]
    return n.lower()


def regs_in(op_str: str) -> List[str]:
    out = []
    for m in _REG_TOKEN.finditer(op_str):
        fam = _REG_FAMILY.get(m.group(1).lower())
        if fam and fam not in out:
            out.append(fam)
    return out


def slot_in(op_str: str) -> Optional[str]:
    m = _MEM_TOKEN.search(op_str)
    if not m:
        return None
    base, sign, disp = m.group(1).lower(), m.group(2), m.group(3)
    v = int(disp, 16) if disp.startswith(('0x', '0X')) else int(disp)
    v = v if sign == '+' else -v
    return f'{_REG_FAMILY.get(base, base)}{v:+d}'


def split_operands(op_str: str) -> List[str]:
    if not op_str:
        return []
    out, depth, cur = [], 0, ''
    for ch in op_str:
        if ch == '[':
            depth += 1
        elif ch == ']':
            depth -= 1
        if ch == ',' and depth == 0:
            out.append(cur.strip())
            cur = ''
        else:
            cur += ch
    if cur.strip():
        out.append(cur.strip())
    return out


def is_imm(op: str) -> Optional[int]:
    op = op.strip()
    if op.startswith(('0x', '0X')):
        try: return int(op, 16)
        except ValueError: return None
    if op.lstrip('-').isdigit():
        return int(op)
    return None


def imm_of_tail(src_ops: List[str]) -> Any:
    if not src_ops:
        return ''
    return is_imm(src_ops[-1]) or ''


# 二进制反汇编与函数边界恢复.

import re, subprocess
from typing import Any, Dict, List, Optional
