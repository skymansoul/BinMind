# coding: utf-8
"""objdump指令行解析: 寄存器归一化/立即数提取/操作数分割/ABI检测.

"""
from typing import List, Optional, Tuple

_REG64 = {
'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi',
    'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8',
    'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9',
    'r10': 'r10', 'r10d': 'r10',
    'r11': 'r11', 'r11d': 'r11',
    'r12': 'r12', 'r12d': 'r12',
    'r13': 'r13', 'r13d': 'r13',
    'r14': 'r14', 'r14d': 'r14',
    'r15': 'r15', 'r15d': 'r15',
    'rbp': 'rbp', 'ebp': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp',
}

ARG_REGS_SYSV = ['rdi', 'rsi', 'rdx', 'rcx', 'r8', 'r9']
ARG_REGS_WIN64 = ['rcx', 'rdx', 'r8', 'r9']

_ALLOC_FUNCS = {'malloc', 'calloc', 'realloc'}
_WRITE_FUNCS = {
    'memcpy': 2, 'memmove': 2, 'memset': 2,
    'strncpy': 2, 'read': 2, 'recv': 2, 'fread': 2, 'recvfrom': 2,
}

_MEM_PREFIXES = (
    'dword ptr', 'qword ptr', 'word ptr',
    'byte ptr', 'xmmword ptr',
)


def normalize_reg(op: str) -> Optional[str]:
    """操作数提取规范寄存器名

    处理MinGW格式: "DWORD PTR [rbp-0x8]" → None
    "rcx" → "rcx", "ecx" → "rcx"
    """
    op = op.strip().lower()
    if not op:
        return None
    for prefix in _MEM_PREFIXES:
        if op.startswith(prefix):
            op = op[len(prefix):].strip()
    if op.startswith('0x') or op.lstrip('-').isdigit():
        return None
    if op.startswith('['):
        return None
    for sep in ('+', '-', '*'):
        if sep in op:
            op = op.split(sep)[0].strip()
    return _REG64.get(op, op if op in _REG64.values() else None)


def extract_imm(op: str) -> Optional[int]:
    """操作数提取立即数

    处理多种格式: "0x40", "64", "0xff"
    跳过 "DWORD PTR" 等前缀
    """
    op = op.strip().lower()
    for prefix in _MEM_PREFIXES:
        if op.startswith(prefix):
            op = op[len(prefix):].strip()
    if op.startswith('0x'):
        try:
            return int(op, 16)
        except ValueError:
            return None
    if op.lstrip('-').isdigit():
        return int(op)
    return None


def parse_insn(raw: str) -> Tuple[str, List[str]]:
    """解析指令行 → (mnemonic, [operands])

    输入格式: "140001772: call 140003268 <malloc>"
    → mnem="call", ops=["140003268 <malloc>"]
    """
    s = raw.strip()
    if ':' in s[:20]:
        s = s.split(':', 1)[1].strip()
    parts = s.split(None, 1)
    if not parts:
        return '', []
    mnem = parts[0].lower()
    if len(parts) < 2:
        return mnem, []
    ops_str = parts[1]
    ops = []
    depth = 0
    cur = []
    for ch in ops_str:
        if ch == '[':
            depth += 1
            cur.append(ch)
        elif ch == ']':
            depth = max(0, depth - 1)
            cur.append(ch)
        elif ch == ',' and depth == 0:
            ops.append(''.join(cur).strip())
            cur = []
        else:
            cur.append(ch)
    if cur:
        ops.append(''.join(cur).strip())
    return mnem, ops


def get_callee(raw: str) -> Optional[str]:
    """从call指令提取被调函数名

    objdump格式: "call 140003268 <malloc>"
    → 提取< >内的符号名; 无<>时取地址后的名字
    """
    mnem, ops = parse_insn(raw)
    if mnem != 'call' or not ops:
        return None
    op_str = ops[-1].strip()
    if '<' in op_str and '>' in op_str:
        start = op_str.find('<')
        end = op_str.find('>', start)
        name = op_str[start + 1:end]
    else:
        name = op_str.lstrip('*')
        for ch in '@':
            name = name.split(ch)[0]
    name = name.strip()
    if not name:
        return None
    return name.lower()


def get_addr(raw: str, base: int, idx: int) -> int:
    """从指令行提取地址"""
    s = raw.strip()
    if ':' in s[:20]:
        try:
            return int(s.split(':')[0], 16)
        except ValueError:
            pass
    return base + idx * 4


def detect_abi(insns_raw: List[str]) -> List[str]:
    """检测ABI: 统计前20条指令rcx vs rdi使用"""
    rcx_n = rdi_n = 0
    for line in insns_raw[:20]:
        l = line.lower()
        if 'rcx' in l:
            rcx_n += 1
        if 'rdi' in l:
            rdi_n += 1
    return ARG_REGS_WIN64 if rcx_n >= rdi_n else ARG_REGS_SYSV


def parse_mem_operand(op: str) -> Tuple[Optional[str], Optional[int]]:
    """解析内存操作数 → (base_reg, offset)

    格式示例:
      "QWORD PTR [rbp-0x8]" → ("rbp", -8)
      "BYTE PTR [rax]" → ("rax", 0)
    """
    op_lower = op.strip().lower()
    for prefix in ('qword ptr ', 'dword ptr ', 'word ptr ',
                   'byte ptr ', 'xmmword ptr '):
        if op_lower.startswith(prefix):
            op_lower = op_lower[len(prefix):]
            break
    if '[' not in op_lower or ']' not in op_lower:
        return None, None
    inner = op_lower[op_lower.find('[') + 1:op_lower.find(']')].strip()

    base_reg = None
    for reg_name in ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi',
                     'rbp', 'rsp', 'r8', 'r9', 'r10', 'r11',
                     'r12', 'r13', 'r14', 'r15']:
        if reg_name in inner:
            base_reg = reg_name
            break

    offset = 0
    for sep in ['+', '-']:
        if sep in inner:
            parts = inner.split(sep)
            if len(parts) >= 2:
                off_str = parts[-1].strip()
                try:
                    off = int(off_str, 16) if off_str.startswith('0x') else int(off_str)
                    offset = off if sep == '+' else -off
                except ValueError:
                    pass
            break

    return base_reg, offset


__all__ = [
    'normalize_reg', 'extract_imm', 'parse_insn', 'get_callee',
    'get_addr', 'detect_abi', 'parse_mem_operand',
    'ARG_REGS_SYSV', 'ARG_REGS_WIN64',
    '_ALLOC_FUNCS', '_WRITE_FUNCS',
]
