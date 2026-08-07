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


# 导入表 / PLT / 初始化数据指针解析 — stripped 二进制的调用名恢复.

import os, re, subprocess
from typing import Dict, List, Optional, Tuple


_IMPORT_CACHE: Dict[str, Dict[int, str]] = {}

_IMPORT_LINE = re.compile(
    r'^\s*([0-9a-f]+)\s+<none>\s+[0-9a-f]+\s+(\w+)', re.I)
_IMAGE_BASE = re.compile(r'^ImageBase\s+([0-9a-fA-F]+)\s*$', re.I)
_THUNK_JMP = re.compile(
    r'^\s*([0-9a-f]+):.*jmp\s+QWORD PTR \[rip[^\]]+\]\s*#\s*(0x[0-9a-fA-F]+)', re.I)
_SECTION_HEAD = re.compile(
    r'^\s*\d+\s+(\S+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+[0-9a-f]+\s+([0-9a-f]+)', re.I)


def parse_imports(elf_path: str, objdump_bin: str = 'objdump') -> Dict[int, str]:
    """解析 PE 导入表 / ELF PLT, 返回 {thunk_addr: 函数名}."""
    key = os.path.abspath(elf_path)
    if key in _IMPORT_CACHE:
        return _IMPORT_CACHE[key]
    thunk_map: Dict[int, str] = {}
    try:
        p = subprocess.run([objdump_bin, '-p', elf_path],
                           capture_output=True, text=True, timeout=30)
        p_out = p.stdout if p.returncode == 0 else ''
    except Exception:
        p_out = ''

    if 'file format pei' in p_out:
        base = 0
        for line in p_out.splitlines():
            m = _IMAGE_BASE.match(line.strip())
            if m:
                base = int(m.group(1), 16)
                break
        iat: Dict[int, str] = {}
        for line in p_out.splitlines():
            m = _IMPORT_LINE.match(line.strip())
            if m:
                rva = int(m.group(1), 16)
                iat[base + rva] = norm_name(m.group(2))
        for line in _disasm_text(elf_path).splitlines():
            m = _THUNK_JMP.match(line.strip())
            if m and int(m.group(2), 16) in iat:
                thunk_map[int(m.group(1), 16)] = iat[int(m.group(2), 16)]
        thunk_map.update(_resolve_data_pointers(elf_path, thunk_map))
    else:
        got_map: Dict[int, str] = {}
        if p_out:
            for line in p_out.splitlines():
                m = re.search(r'\b([0-9a-f]+)\s+R_X86_64_JUMP_SLOT\s+(\S+)', line)
                if m:
                    got_map[int(m.group(1), 16)] = norm_name(m.group(2))
        for line in _disasm_text(elf_path).splitlines():
            m = re.search(
                r'^\s*([0-9a-f]+):.*jmp\s+\*?(0x[0-9a-fA-F]+)\b', line)
            if m and int(m.group(2), 16) in got_map:
                thunk_map[int(m.group(1), 16)] = got_map[int(m.group(2), 16)]
        thunk_map.update(_resolve_data_pointers(elf_path, thunk_map))
    _IMPORT_CACHE[key] = thunk_map
    return thunk_map


def _resolve_data_pointers(elf_path: str, thunk_map: Dict[int, str],
                           objdump_bin: str = 'objdump') -> Dict[int, str]:
    """扫描初始化数据节, 将装载导入指针的数据槽地址映射到函数名."""
    try:
        h = subprocess.run([objdump_bin, '-h', elf_path],
                           capture_output=True, text=True, timeout=30)
        h_out = h.stdout if h.returncode == 0 else ''
    except Exception:
        return {}
    sections: List[Tuple[int, int, int]] = []
    for line in h_out.splitlines():
        m = _SECTION_HEAD.match(line.strip())
        if m:
            name, size_s, vma_s, off_s = m.groups()
            sections.append((int(vma_s, 16), int(size_s, 16),
                             int(off_s, 16)))
    if not sections:
        return {}
    try:
        with open(elf_path, 'rb') as f:
            raw = f.read()
    except OSError:
        return {}
    inv_thunk = {v: k for k, v in thunk_map.items()}
    result: Dict[int, str] = {}
    try:
        for vma, size, off in sections:
            for slot in range(vma, vma + size - 7, 8):
                filepos = off + (slot - vma)
                ptr = int.from_bytes(raw[filepos:filepos + 8], 'little')
                if ptr in inv_thunk:
                    result[slot] = inv_thunk[ptr]
    except (ValueError, IndexError):
        pass
    return result


def _disasm_text(elf_path: str, objdump_bin: str = 'objdump') -> str:
    try:
        r = subprocess.run([objdump_bin, '-d', '-M', 'intel', elf_path],
                           capture_output=True, text=True, timeout=60)
        return r.stdout if r.returncode == 0 else ''
    except Exception:
        return ''


# 逐函数寄存器/栈槽级数据流 — 构建 ir_ops 与 def-use 链.

import re
from typing import Any, Dict, List, Optional



class RegFlow:
    """单函数数据流 — 追踪寄存器(族)与栈槽的最近定义."""
    def __init__(self):
        self.reg_def: Dict[str, int] = {}
        self.slot_def: Dict[str, int] = {}
        self.def_use: Dict[int, List[int]] = {}
        self.reg_callee: Dict[str, str] = {}   # reg → 装载的函数符号
        self.slot_callee: Dict[str, str] = {}  # slot → 存储的函数符号

    def add_edge(self, use_addr: int, def_addr: Optional[int]):
        if def_addr is not None and def_addr != use_addr:
            self.def_use.setdefault(use_addr, []).append(def_addr)

    def resolve_reg(self, reg: str, addr: int) -> Optional[int]:
        return self.reg_def.get(reg)

    def resolve_slot(self, slot: str, addr: int) -> Optional[int]:
        return self.slot_def.get(slot)

    def kill_caller_saved(self):
        for r in CALLER_SAVED:
            self.reg_def.pop(r, None)
            self.reg_callee.pop(r, None)


def build_ir(funcs: List[Dict], import_map: Optional[Dict[int, str]] = None
             ) -> BinIR:
    """从反汇编函数构建 BinIR (含逐函数数据流)."""
    ir = BinIR(sample_id='')
    import_map = import_map or {}
    if funcs:
        ir.arg_regs = funcs[0].get('arg_regs', ARG_REGS_SYSV)
    for func in funcs:
        flow = RegFlow()
        insns = func['insns']
        arg_regs = func.get('arg_regs', ARG_REGS_SYSV)
        for insn in insns:
            addr = insn['addr']
            mn = insn['mnemonic']
            op_str = insn['op_str']
            ir.instructions.append(insn)
            ir.func_of[addr] = func['name']
            op: Dict[str, Any] = {'op_type': mn, 'mnemonic': mn}
            ops = split_operands(op_str)
            dest_op = ops[0] if ops else ''
            src_ops = ops[1:] if len(ops) > 1 else []
            dest_reg = regs_in(dest_op) if not _MEM_TOKEN.search(dest_op) else []
            dest_slot = slot_in(dest_op)
            src_slot = slot_in(op_str)
            if dest_slot is not None:
                src_regs = []
                for so in src_ops:
                    src_regs.extend(regs_in(so))
            else:
                src_regs = regs_in(op_str)
                if dest_reg and not mn.startswith('cmov'):
                    src_regs = [r for r in src_regs if r != dest_reg[0]]

            if mn.startswith('call'):
                callee = _resolve_callee(insn, flow, import_map, op_str)
                op['callee'] = callee
                ir.callee_names[addr] = callee
                for j, arg_reg in enumerate(arg_regs):
                    d = flow.resolve_reg(arg_reg, addr)
                    if d is not None:
                        flow.add_edge(addr, d)
                        op[f'arg{j}_def'] = d
                if callee in ALLOC_FUNCS:
                    ir.trace_events.append({'event': 'alloc', 'address': addr,
                                            'ptr_id': f'{func["name"]}@{addr:x}'})
                elif callee in WRITE_FUNCS or callee in FREE_FUNCS:
                    ir.trace_events.append({'event': 'write', 'address': addr,
                                            'ptr_id': f'{func["name"]}@{addr:x}'})
                flow.kill_caller_saved()
            elif mn in ('ret', 'jmp'):
                flow.kill_caller_saved()
            elif mn in ('cmp', 'test'):
                src_regs_all = regs_in(op_str)
                op['src'] = src_regs_all[0] if src_regs_all else ''
                op['src2'] = src_regs_all[1] if len(src_regs_all) > 1 else (
                    imm_of_tail(src_ops))
                for s in src_regs_all:
                    flow.add_edge(addr, flow.resolve_reg(s, addr))
            else:
                _build_alu(op, insn, flow, import_map,
                           dest_slot, dest_reg, src_slot, src_regs, src_ops)
            ir.ir_ops[addr] = op
        for addr, lst in flow.def_use.items():
            ir.def_use[addr] = list(dict.fromkeys(lst))
    return ir


def _resolve_callee(insn: Dict, flow: RegFlow, import_map: Dict[int, str],
                    op_str: str) -> str:
    """调用目标解析: <符号> 注释 → 间接 call reg → stripped 导入桩."""
    cm = re.search(r'<([^>]+)>', insn.get('comment', ''))
    if cm:
        return norm_name(cm.group(1))
    ireg = regs_in(op_str)
    if ireg and flow.reg_callee.get(ireg[0]):
        return flow.reg_callee[ireg[0]]
    tm = re.search(r'(0x[0-9a-fA-F]+)$', insn.get('comment', ''))
    if tm:
        return import_map.get(int(tm.group(1), 16), '')
    return ''


def _build_alu(op, insn, flow, import_map, dest_slot, dest_reg,
               src_slot, src_regs, src_ops):
    """非控制流指令: store/load/算术, 更新 def-use 与 callee 传播."""
    addr = insn['addr']
    mn = insn['mnemonic']
    if dest_slot is not None:
        for s in src_regs:
            flow.add_edge(addr, flow.resolve_reg(s, addr))
        if src_regs and flow.reg_callee.get(src_regs[0]):
            flow.slot_callee[dest_slot] = flow.reg_callee[src_regs[0]]
        flow.slot_def[dest_slot] = addr
        op['dest'] = dest_slot
        op['src'] = src_regs[0] if src_regs else ''
        op['is_store'] = True
        return
    if dest_reg:
        dreg = dest_reg[0]
        sym = re.search(r'<([^>]+)>', insn.get('comment', ''))
        if sym and mn in ('lea', 'mov'):
            flow.reg_callee[dreg] = norm_name(sym.group(1))
        elif mn in ('lea', 'mov') and import_map:
            tm = re.search(r'#\s*(0x[0-9a-fA-F]+)', insn.get('comment', ''))
            if tm and int(tm.group(1), 16) in import_map:
                flow.reg_callee[dreg] = import_map[int(tm.group(1), 16)]
        op['dest'] = dreg
        if src_slot is not None:
            flow.add_edge(addr, flow.resolve_slot(src_slot, addr))
            if flow.slot_callee.get(src_slot):
                flow.reg_callee[dreg] = flow.slot_callee[src_slot]
            op['src'] = src_slot
        elif src_regs:
            for s in src_regs:
                flow.add_edge(addr, flow.resolve_reg(s, addr))
            op['src'] = src_regs[0]
            op['src2'] = src_regs[1] if len(src_regs) > 1 else ''
        imm = None
        for so in src_ops:
            imm = is_imm(so)
            if imm is not None:
                break
        if imm is not None:
            op['imm'] = imm
            if not src_regs and not src_slot:
                op['src'] = hex(imm)
        flow.reg_def[dreg] = addr


# alloc→write 候选提取 — 值链大小解析 + dest 别名配对.

import re
from typing import Dict, List, Optional, Tuple



def extract_candidates(ir: BinIR) -> BinIR:
    """在同一函数内按 dest 别名配对 alloc -> write, 提取 size 变量."""
    func_insns: Dict[str, List[Dict]] = {}
    for insn in ir.instructions:
        fname = ir.func_of.get(insn['addr'], '')
        if fname:
            func_insns.setdefault(fname, []).append(insn)

    for fname, insns in func_insns.items():
        calls = [i for i in insns if i['mnemonic'] == 'call'
                 and i['addr'] in ir.callee_names]
        allocs = [c for c in calls
                  if ir.callee_names.get(c['addr'], '') in ALLOC_FUNCS]
        writes = [c for c in calls
                  if ir.callee_names.get(c['addr'], '') in WRITE_SIGS]

        write_alloc: Dict[int, Optional[int]] = {}
        for w in writes:
            dest_reg = ir.arg_regs[0]
            src_alloc = _ptr_source(insns, dest_reg, w['addr'])
            if src_alloc is not None:
                write_alloc[w['addr']] = src_alloc
            else:
                earlier = [a for a in allocs if a['addr'] < w['addr']]
                write_alloc[w['addr']] = earlier[-1]['addr'] if earlier else None

        for a in allocs:
            acallee = ir.callee_names.get(a['addr'], '')
            size_idx, _prod = ALLOC_SIGS.get(acallee, (0, False))
            size_reg = ir.arg_regs[size_idx]
            ainfo = _size_info(insns, size_reg, a['addr'])
            for w in writes:
                if w['addr'] <= a['addr']:
                    continue
                if write_alloc.get(w['addr']) != a['addr']:
                    continue
                wcallee = ir.callee_names.get(w['addr'], '')
                sig = WRITE_SIGS.get(wcallee)
                if sig is None:
                    # 无显式长度写入: 长度取决于源, 保守候选
                    winfo = (0, '', None)
                    wid = f'unknown@{w["addr"]:x}'
                    same_src = False
                else:
                    wsize_reg = ir.arg_regs[sig[0]]
                    winfo = _size_info(insns, wsize_reg, w['addr'])
                    wid = _size_id(winfo[1], winfo[2], w['addr'])
                    same_src = _same_source(
                        ainfo[1], ainfo[2], winfo[1], winfo[2], insns)
                aid = _size_id(ainfo[1], ainfo[2], a['addr'])
                ir.candidates.append({
                    'alloc_site': a['addr'], 'write_site': w['addr'],
                    'alloc_callee': acallee, 'write_callee': wcallee,
                    'alloc_size': ainfo[0], 'write_size': winfo[0],
                    'alloc_size_var': ainfo[1], 'write_size_var': winfo[1],
                    'alloc_def': ainfo[2], 'write_def': winfo[2],
                    'alloc_id': aid, 'write_id': wid,
                    'same_source': same_src,
                    'vuln_type': 'heap_overflow',
                    'func': fname,
                    'confidence': 0.5, 'exploitable': False,
                    'source_layer': 'L0_frontend',
                })
    return ir


def _size_info(insns: List[Dict], reg: str,
               call_addr: int) -> Tuple[int, str, Optional[int]]:
    """沿值链向后解析 call 前 reg 的大小: (常量, 变量名, 值定义地址)."""
    target = reg
    limit = call_addr
    const_val = 0
    var_name = reg
    value_def: Optional[int] = None

    while True:
        found: Optional[Dict] = None
        for insn in insns:
            if insn['addr'] >= limit:
                break
            ops = split_operands(insn['op_str'])
            if not ops:
                continue
            dst_regs = regs_in(ops[0]) if not _MEM_TOKEN.search(ops[0]) else []
            if target in dst_regs:
                found = insn
        if found is None:
            break
        value_def = found['addr']
        mn = found['mnemonic']
        ops = split_operands(found['op_str'])
        if not mn.startswith('mov') or len(ops) < 2:
            var_name = target
            break
        src_op = ops[-1]
        imm = is_imm(src_op)
        if imm is not None:
            const_val = imm
            var_name = target
            break
        src_slot = slot_in(src_op)
        src_reg = regs_in(src_op)
        if src_slot:
            var_name = src_slot
            store_imm = _slot_store_imm(insns, src_slot, found['addr'])
            if store_imm is not None:
                const_val = store_imm
            break
        if src_reg:
            target = src_reg[0]
            var_name = target
            limit = found['addr']
            continue
        var_name = target
        break
    return const_val, var_name, value_def


def _ptr_source(insns: List[Dict], reg: str, boundary: int) -> Optional[int]:
    """沿指针值链回溯, 若链终止于 alloc 调用则返回其地址."""
    target = reg
    limit = boundary
    for _ in range(8):
        found = _last_reg_def(insns, target, limit)
        if found is None:
            return None
        mn = found['mnemonic']
        ops = split_operands(found['op_str'])
        if mn.startswith('call'):
            cm = re.search(r'<([^>]+)>', found.get('comment', ''))
            if cm and norm_name(cm.group(1)) in ALLOC_FUNCS:
                return found['addr']
            return None
        if not mn.startswith('mov') or len(ops) < 2:
            return None
        src_op = ops[-1]
        if is_imm(src_op) is not None:
            return None
        src_slot = slot_in(src_op)
        if src_slot:
            store = _slot_last_store(insns, src_slot, found['addr'])
            if store is None:
                return None
            store_insn = next((i for i in insns if i['addr'] == store), None)
            if store_insn is None:
                return None
            sregs = regs_in(store_insn['op_str'])
            if not sregs:
                return None
            target = sregs[-1]
            limit = store
            continue
        src_regs = regs_in(src_op)
        if src_regs:
            target = src_regs[0]
            limit = found['addr']
            continue
        return None
    return None


def _same_source(a_var: str, a_def: Optional[int],
                 w_var: str, w_def: Optional[int],
                 insns: List[Dict]) -> bool:
    """判定 alloc/write 的大小值是否来自同一源 (同一槽的同一 store)."""
    if a_var == w_var and a_def == w_def and a_def is not None:
        return True
    if a_var != w_var or a_def is None or w_def is None:
        return False
    a_store = _slot_last_store(insns, a_var, a_def)
    w_store = _slot_last_store(insns, w_var, w_def)
    return a_store is not None and a_store == w_store


def _slot_last_store(insns: List[Dict], slot: str,
                     boundary: int) -> Optional[int]:
    store_addr: Optional[int] = None
    for insn in insns:
        if insn['addr'] >= boundary:
            break
        ops = split_operands(insn['op_str'])
        if not ops:
            continue
        if slot_in(ops[0]) == slot:
            store_addr = insn['addr']
    return store_addr


def _slot_store_imm(insns: List[Dict], slot: str,
                    boundary: int) -> Optional[int]:
    store = _slot_last_store(insns, slot, boundary)
    if store is None:
        return None
    for insn in insns:
        if insn['addr'] == store:
            ops = split_operands(insn['op_str'])
            if len(ops) >= 2:
                return is_imm(ops[-1])
            break
    return None


def _size_id(var: str, def_addr: Optional[int], call_addr: int) -> str:
    addr = def_addr if def_addr else call_addr
    return f'{var}@{addr:x}'


def _last_reg_def(insns: List[Dict], reg: str, limit: int) -> Optional[Dict]:
    found: Optional[Dict] = None
    for insn in insns:
        if insn['addr'] >= limit:
            break
        ops = split_operands(insn['op_str'])
        if not ops:
            continue
        dst_regs = regs_in(ops[0]) if not _MEM_TOKEN.search(ops[0]) else []
        if reg in dst_regs:
            found = insn
    return found



def analyze_binary(elf_path: str) -> BinIR:
    """对外主入口: 反汇编 -> 导入表解析 -> IR -> 候选."""
    funcs = disassemble(elf_path)
    import_map = parse_imports(elf_path)
    ir = build_ir(funcs, import_map)
    ir.sample_id = _sample_id(elf_path)
    extract_candidates(ir)
    return ir


def _sample_id(elf_path: str) -> str:
    base = os.path.basename(elf_path)
    for ext in (".exe", ".elf", ".bin"):
        if base.lower().endswith(ext):
            return base[:-len(ext)]
    return base
