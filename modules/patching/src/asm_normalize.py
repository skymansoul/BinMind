# 汇编行规范化层 — 消除反汇编格式/ABI差异对检测逻辑的扰动
"""objdump输出存在两类格式差异，导致既有正则无法匹配:
  1. MinGW x64:  call   <addr> <func>  (带地址与尖括号)
     SysV ELF:   call   func@plt        (无地址)
  2. 内存操作数大小写与逗号: QWORD PTR [rbp-0x10],rax
     vs 经lower+replace后:  qword ptr [rbp-0x10] rax

设计决策:
  - 规范化在检测流水线入口执行一次，后续模块按SysV紧凑格式解析
  - call行统一折叠为 "call <func>"，去除地址与尖括号
  - 操作数大小写统一小写，逗号保留供依赖逗号正则的模块使用
  - 不改变指令语义，仅统一文本形态
"""

import re

# call行: 提取被调用函数名
_CALL_FUNC = re.compile(
    r'\bcall\s+(?:(?:0x)?[0-9a-f]+\s+<)?\s*'
    r'([a-zA-Z_][\w.@]*?)'
    r'(?:@plt|@PLT|@IAT|@GOT)?\s*>?\s*$', re.I)


def normalize_call(line: str) -> str:
    """将 call 行折叠为 "call <func>" 紧凑形态。
    保留 call rax / call [rbp-8] 等间接调用原样。
    """
    m = _CALL_FUNC.search(line.strip())
    if m:
        return f'call {m.group(1)}'
    return line


def normalize_operands(line: str) -> str:
    """统一操作数形态: 小写 + 保留逗号。
    QWORD PTR → qword ptr; 去除多余空白。
    """
    line = re.sub(r'\b(qword|dword|word|byte)\s+ptr\b', r'\1 ptr', line, flags=re.I)
    line = re.sub(r'\s+', ' ', line.strip())
    return line


def normalize_asm_lines(lines) -> list:
    """对整个反汇编行列表执行规范化。
    返回新列表，不改动原列表。
    """
    out = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            out.append(line)
            continue
        if re.match(r'^\s*[0-9a-f]+\s+<', stripped) and stripped.endswith(':'):
            # 函数标签行: 1400014f0 <duplicate_ppstrings>:
            out.append(normalize_operands(line))
            continue
        low = stripped.lower()
        if low.startswith('call ') or re.search(r'\bcall\s+[0-9a-f]+\s*<', low):
            out.append(normalize_call(stripped))
            continue
        out.append(normalize_operands(line))
    return out
