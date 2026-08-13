# -*- coding: utf-8 -*-
"""二进制反汇编与函数边界恢复 — stripped 场景经 call 目标 + 序言分段."""

import re, subprocess
from typing import Any, Dict, List, Optional

from modules.core.compat.binir_common import (
    ARG_REGS_SYSV, ARG_REGS_WIN64, norm_name)

_FUNC_HEAD = re.compile(r'^([0-9a-f]+)\s+<([^>]+)>:$', re.I)
_INSN_LINE = re.compile(
    r'^\s*([0-9a-f]+):\s+([0-9a-f]{2,}(?:\s[0-9a-f]{2})*)\s+(.+)$', re.I)


class BinIR:
    """单个二进制的 IR 表示."""
    def __init__(self, sample_id: str):
        self.sample_id = sample_id
        self.instructions: List[Dict] = []
        self.ir_ops: Dict[int, Dict] = {}
        self.callee_names: Dict[int, str] = {}
        self.def_use: Dict[int, List[int]] = {}
        self.trace_events: List[Dict] = []
        self.func_of: Dict[int, str] = {}
        self.candidates: List[Dict] = []
        self.arg_regs: List[str] = ARG_REGS_SYSV


def disassemble(elf_path: str, objdump_bin: str = 'objdump') -> List[Dict]:
    """objdump 反汇编, 返回函数列表 [{name, addr, insns:[...]}]."""
    try:
        r = subprocess.run([objdump_bin, '-d', '-M', 'intel', elf_path],
                           capture_output=True, text=True, timeout=60)
        if r.returncode != 0:
            return []
        text = r.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    funcs: List[Dict] = []
    cur: Optional[Dict] = None
    abi = ARG_REGS_SYSV
    func_head_count = 0
    for line in text.splitlines():
        m = _FUNC_HEAD.match(line.strip())
        if m:
            func_head_count += 1
            cur = {'name': norm_name(m.group(2)),
                   'addr': int(m.group(1), 16), 'insns': []}
            funcs.append(cur)
            continue
        m = _INSN_LINE.match(line.strip())
        if m and cur is not None:
            comment = m.group(3).strip()
            parts = comment.split(None, 1)
            mnemonic = parts[0].lower()
            op_str = parts[1].strip() if len(parts) > 1 else ''
            cur['insns'].append({
                'addr': int(m.group(1), 16),
                'mnemonic': mnemonic, 'op_str': op_str, 'comment': comment,
            })
        if 'file format pei' in line.lower():
            abi = ARG_REGS_WIN64
    # stripped: 整个 .text 合成单函数 → 启发式分段恢复边界
    if func_head_count <= 1 and funcs and len(funcs[0]['insns']) > 8:
        funcs = _segment_functions(funcs[0]['insns'])
    for f in funcs:
        f['arg_regs'] = abi
    return funcs


def _segment_functions(insns: List[Dict]) -> List[Dict]:
    """无符号二进制函数边界恢复.

    函数入口证据: (1) 直接 call 的目标地址 (2) ret/jmp/int3 之后跟随
    序言式指令 (push rbp/sub rsp/mov rbp,endbr) 的新序列.
    """
    call_targets: set = set()
    for insn in insns:
        if insn['mnemonic'] == 'call':
            tm = re.search(r'(0x[0-9a-fA-F]+)', insn.get('comment', ''))
            if tm:
                call_targets.add(int(tm.group(1), 16))

    _PROLOGUE = ('push', 'sub rsp', 'mov rbp', 'lea rbp', 'endbr',
                 'mov ebp', 'xor ebp', 'add rsp')

    segments: List[Dict] = []
    cur: List[Dict] = []
    prev_terminated = False

    def _flush(start_addr: Optional[int]):
        nonlocal cur
        if not cur:
            return
        name = f'f_{start_addr:x}' if start_addr else 'f_unknown'
        segments.append({'name': name, 'addr': start_addr or cur[0]['addr'],
                         'insns': cur})
        cur = []

    for insn in insns:
        addr = insn['addr']
        mn = insn['mnemonic']
        op_str = insn['op_str']
        is_entry = addr in call_targets
        # TODO: 序言模式表仅覆盖 x86-64; ARM/MIPS 的 prologue 需另建
        looks_prologue = any(p in f'{mn} {op_str}'.lower() for p in _PROLOGUE)
        if cur and (is_entry or (prev_terminated and looks_prologue)):
            _flush(cur[0]['addr'])
        cur.append(insn)
        prev_terminated = mn in ('ret', 'jmp', 'int3', 'hlt', 'ud2')

    _flush(cur[0]['addr'] if cur else None)
    return segments
