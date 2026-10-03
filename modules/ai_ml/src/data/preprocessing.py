# preprocessing.py x86汇编指令归一化
# 把变化的部分（立即数、偏移、地址）替换为占位符，
# 保留操作语义不变。受ContraBin启发但简化了寄存器抽象。
# 不抽象寄存器名，因为寄存器选择本身就是语义特征

import re

# 正则模式 编译一次复用
_HEX_IMM_RE = re.compile(r'\b0x[0-9a-fA-F]+\b')
_DEC_IMM_RE = re.compile(r'(?<![a-zA-Z_])(\d+)(?![a-zA-Z_0-9])')
_OFFSET_RE = re.compile(r'\[(?:[a-z]{3,6}:)?0x[0-9a-fA-F]+\]', re.IGNORECASE)
# 只匹配loc_/sub_前缀的标签地址，裸0x数字走<IMM>路径
# 设计权衡：call 0x401000 → <IMM>，loc_401000 → <ADDR>
_ADDR_LABEL_RE = re.compile(r'\b(?:loc_|sub_)[0-9a-fA-F]{4,16}\b', re.IGNORECASE)
_MEM_REF_RE = re.compile(r'(?:qword|dword|word|byte)\s+ptr\s+\[[^\]]+\]', re.IGNORECASE)
_PTR_REF_RE = re.compile(r'\[[^\]]+\]')
_SEGMENT_RE = re.compile(r'\b(?:cs|ds|es|fs|gs|ss):', re.IGNORECASE)
_COMMENT_RE = re.compile(r'\s*;.*$')
_MULTI_SPACE_RE = re.compile(r'\s+')

# x86通用寄存器集合 用于token判断
_X86_REGS = {
    'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
    'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15',
    'eax', 'ebx', 'ecx', 'edx', 'esi', 'edi', 'ebp', 'esp',
    'ax', 'bx', 'cx', 'dx', 'si', 'di', 'bp', 'sp',
    'al', 'ah', 'bl', 'bh', 'cl', 'ch', 'dl', 'dh',
    'r8d', 'r9d', 'r10d', 'r11d', 'r12d', 'r13d', 'r14d', 'r15d',
    'r8w', 'r9w', 'r10w', 'r11w', 'r12w', 'r13w', 'r14w', 'r15w',
    'r8b', 'r9b', 'r10b', 'r11b', 'r12b', 'r13b', 'r14b', 'r15b',
    'xmm0', 'xmm1', 'xmm2', 'xmm3', 'xmm4', 'xmm5', 'xmm6', 'xmm7',
    'xmm8', 'xmm9', 'xmm10', 'xmm11', 'xmm12', 'xmm13', 'xmm14', 'xmm15',
    'ymm0', 'ymm1', 'ymm2', 'ymm3', 'ymm4', 'ymm5', 'ymm6', 'ymm7',
    'ymm8', 'ymm9', 'ymm10', 'ymm11', 'ymm12', 'ymm13', 'ymm14', 'ymm15',
}


def clean_assembly_line(line: str) -> str:
    """Strip comments and trailing whitespace from an assembly line."""
    _v = _COMMENT_RE.sub('', line)
    _v = _v.strip()
    # 干掉行尾的注释分隔符残余
    return _MULTI_SPACE_RE.sub(' ', _v)


def normalize_instruction(insn: str) -> str:
    # 先清理注释和空白
    _s = clean_assembly_line(insn)
    if not _s:
        return ''

    # 分离操作码和操作数
    parts = _s.split(None, 1)
    mnemonic = parts[0].lower()

    if len(parts) == 1:
        return mnemonic

    operands = parts[1]

# 替换顺序：先标签地址(loc_/sub_)后立即数
    operands = _ADDR_LABEL_RE.sub('<ADDR>', operands)
    # 段前缀移除
    operands = _SEGMENT_RE.sub('', operands)
    # 内存引用 qword ptr [...] -> [<MEM>]
    operands = _MEM_REF_RE.sub('<MEM>', operands)
    # 剩余方括号内的偏移也占位
    operands = _PTR_REF_RE.sub('[<MEM>]', operands)
    # 十六进制立即数
    operands = _HEX_IMM_RE.sub('<IMM>', operands)
    # 十进制立即数（注意：在替换掉地址和hex之后做）
    _cleaned_ops = []
    for _tok in operands.split(','):
        _tok = _tok.strip()
        # 负数处理
        if _tok.startswith('-') and _tok[1:].isdigit():
            _tok = '<IMM>'
        elif _tok.isdigit():
            _tok = '<IMM>'
        _cleaned_ops.append(_tok)
    operands = ', '.join(_cleaned_ops)

    return f"{mnemonic} {operands}"


def normalize_opcode_seq(opcodes: list) -> list:
    """Normalize a sequence of opcode mnemonics (no operands)."""
    return [op.lower().strip() for op in opcodes if op.strip()]


def tokenize_instruction(insn: str) -> list:
    """Split a normalized instruction into tokens for embedding."""
    _s = clean_assembly_line(insn)
    if not _s:
        return []

    # 拆分为 mnemonic + 操作数碎片
    parts = _s.split(None, 1)
    tokens = [parts[0].lower()]

    if len(parts) > 1:
        # 操作数部分：按逗号、空格、+、*、- 拆分
        _op_str = parts[1]
        # 先保留方括号完整性，再拆其他分隔符
        _frags = re.split(r'([,\+\-\*\[\]])', _op_str)
        for _f in _frags:
            _f = _f.strip().lower()
            if _f and _f not in ('', ' ', ','):
                tokens.append(_f)

    return [_t for _t in tokens if _t and _t != ',']


def normalize_function(asm_lines: list) -> list:
    """Normalize all assembly lines in a function body.

    Returns list of (original_line, normalized_line) tuples.
    """
    _out = []
    _in_data_section = False

    for _line in asm_lines:
        if not _line or not _line.strip():
            _out.append((_line, ''))
            continue

        _cleaned = clean_assembly_line(_line)

        # 跳过纯标签行和section指令
        if _cleaned.endswith(':') and len(_cleaned.split()) == 1:
            _out.append((_line, _cleaned))
            continue

        _lower = _cleaned.lower()
        # 数据定义指令保留但标记 (db/dw/dd/dq)
        if any(_lower.startswith(_d) for _d in ('db ', 'dw ', 'dd ', 'dq ', '.byte', '.word', '.long', '.quad')):
            _in_data_section = True
            _out.append((_line, '<DATA>'))
            continue

        if _in_data_section and not any(
            _lower.startswith(_op) for _op in ('mov', 'push', 'pop', 'call', 'jmp', 'j', 'cmp', 'test',
                                                  'add', 'sub', 'xor', 'and', 'or', 'lea', 'ret', 'nop',
                                                  'inc', 'dec', 'not', 'neg', 'mul', 'div', 'shl', 'shr',
                                                  'sar', 'rol', 'ror', 'imul', 'idiv', 'int', 'syscall')
        ):
            _out.append((_line, ''))
            continue

        _in_data_section = False
        _normalized = normalize_instruction(_cleaned)
        _out.append((_line, _normalized))

    return _out


# 辅助：提取指令中的寄存器操作数
def _extract_regs(operand_str: str) -> set:
    """Pull out register names from an operand string."""
    _found = set()
    # 按非字母数字切分
    _parts = re.split(r'[^a-zA-Z0-9]', operand_str)
    for _p in _parts:
        _lp = _p.lower()
        if _lp in _X86_REGS:
            _found.add(_lp)
    return _found
