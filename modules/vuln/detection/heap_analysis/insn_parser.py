"""objdump反汇编文本 → 结构化指令 + 函数分组.

设计决策:
  capstone对PE/COFF和ELF都能线性扫描, 但objdump提供了符号信息和函数边界,
  这些对区分user code和libc wrapper是必要的。回退到objdump文本解析。
  函数边界信息用于后续跨函数分析(interproc_context)。

参考: Ghidra使用类似的两阶段策略(先objdump获取符号, 再反编译)。
"""
import re
import subprocess
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

# 汇编行: 地址: 操作码字节 指令文本
_ASM_LINE_RE = re.compile(
    r'^\s*([0-9a-fA-F]+):\s+'
    r'((?:[0-9a-fA-F]{2}\s)+)\s+'
    r'(.+)$')

# x86_64寄存器别名 → 规范名
_REG_ALIASES = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax', 'ah': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx', 'bh': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx', 'ch': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx', 'dh': 'rdx',
    'rsi': 'rsi', 'esi': 'rsi', 'si': 'rsi', 'sil': 'rsi',
    'rdi': 'rdi', 'edi': 'rdi', 'di': 'rdi', 'dil': 'rdi',
    'r8': 'r8', 'r8d': 'r8', 'r8w': 'r8', 'r8b': 'r8',
    'r9': 'r9', 'r9d': 'r9', 'r9w': 'r9', 'r9b': 'r9',
    'r10': 'r10', 'r10d': 'r10', 'r10w': 'r10', 'r10b': 'r10',
    'r11': 'r11', 'r11d': 'r11', 'r11w': 'r11', 'r11b': 'r11',
    'r12': 'r12', 'r12d': 'r12', 'r12w': 'r12', 'r12b': 'r12',
    'r13': 'r13', 'r13d': 'r13', 'r13w': 'r13', 'r13b': 'r13',
    'r14': 'r14', 'r14d': 'r14', 'r14w': 'r14', 'r14b': 'r14',
    'r15': 'r15', 'r15d': 'r15', 'r15w': 'r15', 'r15b': 'r15',
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp', 'bpl': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp', 'spl': 'rsp',
    'rip': 'rip', 'eip': 'rip',
}


@dataclass
class Instruction:
    """一条反汇编指令."""
    addr: int
    mnemonic: str
    operands: str
    raw: str


@dataclass
class Function:
    """一个函数的所有信息."""
    name: str
    start_addr: int
    insns: List[Instruction] = field(default_factory=list)

    @property
    def n_insns(self) -> int:
        return len(self.insns)


# CRT/系统函数排除模式 — 这些函数中的malloc+memcpy不是漏洞
_SKIP_PREFIXES = (
    '__', '_', '.', 'memset', 'memcpy', 'memmove',
    'strlen', 'strcpy', 'strcat', 'printf', 'scanf',
    'malloc', 'calloc', 'realloc', 'free', 'fflush',
    'abort', 'exit', 'atexit', 'setvbuf', 'setjmp',
    'longjmp', 'signal', 'raise', 'perror',
)
_SKIP_CONTAINS = (
    '_msvc', 'mingw_', 'DllMain', 'WinMain',
    'register_frame', 'deregister_frame',
    'duplicate_pp', 'pseudo_reloc',
    'mark_section', 'restore_modified',
    '_pei386', '__tmain', 'wcsnlen', 'strnlen',
    'wcrtomb', 'mbrtowc', 'bitstob',
    'dtoa_lock', 'dtoa_unlock',
    'init_fpreg', 'fallback_IsDBCS',
)


def is_user_function(name: str) -> bool:
    """排除CRT/系统桩函数, 只留用户代码."""
    if not name:
        return False
    if name.startswith(_SKIP_PREFIXES):
        return False
    if any(s in name for s in _SKIP_CONTAINS):
        return False
    return True


def disassemble(binary_path: str, timeout_s: int = 30) -> str:
    """objdump反汇编, 回退llvm-objdump."""
    for tool in ['objdump', 'llvm-objdump']:
        try:
            proc = subprocess.run(
                [tool, '-d', '-M', 'intel', binary_path],
                capture_output=True, text=True, timeout=timeout_s,
                encoding='utf-8', errors='replace')
            if proc.returncode == 0 and len(proc.stdout) > 100:
                return proc.stdout
        except Exception:
            continue
    return ""


def parse_instructions(asm_text: str) -> List[Function]:
    """解析objdump输出 → 按用户函数分组的指令列表."""
    functions: List[Function] = []
    fn_header_re = re.compile(r'^[0-9a-fA-F]+\s+<([^>]+)>:\s*$')
    current_fn: Optional[Function] = None

    for line in asm_text.split('\n'):
        line = line.rstrip()
        fn_match = fn_header_re.match(line)
        if fn_match:
            if current_fn and current_fn.insns and is_user_function(current_fn.name):
                functions.append(current_fn)
            fn_name = fn_match.group(1)
            current_fn = Function(name=fn_name, start_addr=0)
            continue

        m = _ASM_LINE_RE.match(line)
        if m and current_fn is not None:
            addr = int(m.group(1), 16)
            raw_insn = m.group(3).strip()
            if current_fn.start_addr == 0:
                current_fn.start_addr = addr
            parts = raw_insn.split(None, 1) if ' ' in raw_insn else [raw_insn, '']
            mnemonic = parts[0].lower()
            operands = parts[1] if len(parts) > 1 else ''
            current_fn.insns.append(Instruction(
                addr=addr, mnemonic=mnemonic, operands=operands, raw=raw_insn))

    if current_fn and current_fn.insns and is_user_function(current_fn.name):
        functions.append(current_fn)
    return functions


# 通用提取工具

def is_call_to(insn: Instruction, target: str) -> bool:
    """call目标是否含指定符号名."""
    return insn.mnemonic == 'call' and target in insn.operands.lower()


def extract_register(operand: str) -> Optional[str]:
    """提取操作数中的寄存器, 返回规范名."""
    m = re.search(
        r'\b(r[0-9a-d]+[bwd]?|[er]?[abcd]x|[er]?[sd]i|[er]?[sb]p|[er]?ip)\b',
        operand, re.IGNORECASE)
    if m:
        return _REG_ALIASES.get(m.group(1).lower(), m.group(1).lower())
    return None


def extract_constant(operand: str) -> Optional[int]:
    """提取操作数中的立即数 (hex/dec), 支持负偏移如 [rbp-0x8]."""
    # 负偏移优先: 避免正数hex正则误吞 'rbp-0x8' 中的 '0x8'
    m = re.search(r'\[[^]]*-\s*(0x[0-9a-fA-F]+|\d+)', operand)
    if m:
        try:
            return -int(m.group(1), 0)
        except ValueError:
            pass
    m = re.search(r'-\s*(0x[0-9a-fA-F]+|\d+)', operand)
    if m:
        try:
            return -int(m.group(1), 0)
        except ValueError:
            pass
    m = re.search(r'0x([0-9a-fA-F]+)', operand)
    if m:
        return int(m.group(1), 16)
    m = re.search(r'\[[^]]*[+]\s*(0x[0-9a-fA-F]+|\d+)', operand)
    if m:
        try:
            return int(m.group(1), 0)
        except ValueError:
            pass
    m = re.search(r'(?<![0-9a-fA-Fx])(\d+)(?![0-9a-fA-Fx])', operand)
    if m:
        val = int(m.group(1))
        if val < 0x100000:
            return val
    return None


def extract_mem_offset(operand: str) -> Tuple[Optional[str], Optional[int]]:
    """从 [reg+offset] 提取 (reg, offset)."""
    m = re.search(r'\[([^\]]+)\]', operand)
    if not m:
        return None, None
    inner = m.group(1).strip()
    reg = extract_register(inner)
    const = extract_constant(inner)
    if reg is None and re.match(r'^[a-z][a-z0-9]+$', inner):
        reg = _REG_ALIASES.get(inner.lower(), inner.lower())
    return reg, const


def infer_access_size(mem_operand: str, raw_insn: str) -> int:
    """从内存操作数推断访问大小 (字节)."""
    rl = raw_insn.lower()
    if 'byte ptr' in rl:
        return 1
    if 'word ptr' in rl:
        return 2
    if 'dword ptr' in rl:
        return 4
    if 'qword ptr' in rl:
        return 8
    if 'xmmword' in rl:
        return 16
    if 'movzx' in rl or 'movsx' in rl:
        if 'byte' in rl:
            return 1
        if 'word' in rl:
            return 2
    return 4


def extract_malloc_addr(val_str: str) -> Optional[int]:
    """从 'malloc@0x1400017fa' 提取十六进制地址."""
    for prefix in ('malloc@', 'calloc@', 'realloc@'):
        m = re.search(rf'{re.escape(prefix)}([0-9a-fA-F]+)', val_str)
        if m:
            return int(m.group(1), 16)
    return None
