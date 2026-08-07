"""指令解析器 — objdump反汇编文本 → 结构化指令列表.

创建: 2026-07-26
用途: 将 objdump -d -M intel 输出解析为按函数分组的 Instruction 列表,
      同时提供通用解析工具函数 (寄存器提取、常量提取、call目标匹配)。

设计决策:
  - 为什么不用 capstone 直接反汇编: capstone 对 PE/COFF (MinGW) 和 ELF
    都能线性扫描, 但 objdump 提供了符号信息和函数边界,
    这些对堆分析中区分 user code 和 libc wrapper 是必要的。
  - 用户函数过滤: 白名单之外的符号视为CRT/linker生成代码,
    不参与堆分析以减少噪声。
"""
import re
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

# 汇编行正则: 地址: 操作码字节 指令文本
_ASM_LINE_RE = re.compile(
    r'^\s*([0-9a-fA-F]+):\s+'
    r'((?:[0-9a-fA-F]{2}\s)+)\s+'
    r'(.+)$')

# x86_64寄存器别名: 变体名 → 规范名
_REG_ALIASES = {
    'rax': 'rax', 'eax': 'rax', 'ax': 'rax', 'al': 'rax',
    'rbx': 'rbx', 'ebx': 'rbx', 'bx': 'rbx', 'bl': 'rbx',
    'rcx': 'rcx', 'ecx': 'rcx', 'cx': 'rcx', 'cl': 'rcx',
    'rdx': 'rdx', 'edx': 'rdx', 'dx': 'rdx', 'dl': 'rdx',
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
    'rbp': 'rbp', 'ebp': 'rbp', 'bp': 'rbp',
    'rsp': 'rsp', 'esp': 'rsp', 'sp': 'rsp',
}


@dataclass
class Instruction:
    """一条反汇编指令."""
    addr: int
    mnemonic: str
    operands: str
    raw: str


def is_user_function(name: str, n_insns: int = 999) -> bool:
    """排除CRT/系统/IAT函数, 只分析用户代码.

    n_insns: 函数指令数, 用于过滤短小的 IAT stub (≤4条指令且模式匹配).
    """
    if not name:
        return False
    skip_prefixes = (
        '__', '_', '.', 'memset', 'memcpy', 'memmove',
        'strlen', 'strcpy', 'strcat', 'printf', 'scanf',
        'malloc', 'calloc', 'realloc', 'free', 'fflush',
        'abort', 'exit', 'atexit', 'setvbuf', 'setjmp',
        'longjmp', 'signal', 'raise', 'perror',
    )
    skip_contains = (
        '_msvc', 'mingw_', 'DllMain', 'WinMain',
        'register_frame', 'deregister_frame',
        'duplicate_pp', 'pseudo_reloc',
        'mark_section', 'restore_modified',
        '_pei386', '__tmain', 'wcsnlen', 'strnlen',
        'wcrtomb', 'mbrtowc', 'bitstob',
        'dtoa_lock', 'dtoa_unlock',
        'init_fpreg', 'fallback_IsDBCS',
        'CRTStartup', 'pei386',
        # 注: '_start' 已由 skip_prefixes('_') 覆盖,
        #      substring匹配会误杀 async_start
    )
    if name.startswith(skip_prefixes):
        return False
    if any(s in name for s in skip_contains):
        return False
    # 短函数: ≤4条指令且满足IAT stub特征 → 过滤
    if n_insns <= 4:
        if (_is_iat_stub_like(name)):
            return False
    return True


def _is_iat_stub_like(name: str) -> bool:
    """检查函数名是否像导入表桩 (Windows API/CRT wrapper)."""
    # Windows API: PascalCase with potential 'A'/'W' suffix
    if name[0].isupper() and any(c.islower() for c in name):
        return True
    # 简短小写CRT函数: 不含下划线, 不含数字后缀
    if (name.islower() and '_' not in name
            and len(name) <= 12 and name.isalpha()):
        return True
    return False


def parse_instructions(asm_text: str) -> List[Tuple[str, List[Instruction]]]:
    """解析objdump输出为按函数分组的指令列表."""
    functions: List[Tuple[str, List[Instruction]]] = []
    current_fn = ""
    current_insns: List[Instruction] = []
    fn_header_re = re.compile(r'^[0-9a-fA-F]+\s+<([^>]+)>:\s*$')

    for line in asm_text.split('\n'):
        line = line.rstrip()
        fn_match = fn_header_re.match(line)
        if fn_match:
            if current_insns and is_user_function(current_fn, len(current_insns)):
                functions.append((current_fn, current_insns))
            current_fn = fn_match.group(1)
            current_insns = []
            continue

        m = _ASM_LINE_RE.match(line)
        if m:
            addr = int(m.group(1), 16)
            raw_insn = m.group(3).strip()
            if ' ' in raw_insn:
                parts = raw_insn.split(None, 1)
                mnemonic = parts[0].lower()
                operands = parts[1] if len(parts) > 1 else ''
            else:
                mnemonic = raw_insn.lower()
                operands = ''
            current_insns.append(Instruction(
                addr=addr, mnemonic=mnemonic, operands=operands, raw=raw_insn))

    if current_insns and is_user_function(current_fn, len(current_insns)):
        functions.append((current_fn, current_insns))
    return functions


# 通用提取工具
def is_call_to(insn: Instruction, target: str) -> bool:
    """检查call目标是否含指定符号名."""
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
    """提取操作数中的立即数 (hex: 0xNNN, dec: NNN, mem: [reg+NNN])."""
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
    """从内存操作数 [reg+offset] 提取 (reg, offset)."""
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
    """从内存操作数/指令文本推断访问大小 (字节)."""
    raw_lower = raw_insn.lower()
    if 'byte ptr' in raw_lower:
        return 1
    if 'word ptr' in raw_lower:
        return 2
    if 'dword ptr' in raw_lower:
        return 4
    if 'qword ptr' in raw_lower:
        return 8
    if 'xmmword' in raw_lower:
        return 16
    if 'movzx' in raw_lower or 'movsx' in raw_lower:
        if 'byte' in raw_lower:
            return 1
        if 'word' in raw_lower:
            return 2
    return 4


def extract_malloc_addr(val_str: str) -> Optional[int]:
    """从 'malloc@0x1400017fa' 中提取十六进制地址."""
    for prefix in ('malloc@', 'calloc@', 'realloc@', 'strdup@'):
        m = re.search(rf'{re.escape(prefix)}([0-9a-fA-F]+)', val_str)
        if m:
            return int(m.group(1), 16)
    return None
