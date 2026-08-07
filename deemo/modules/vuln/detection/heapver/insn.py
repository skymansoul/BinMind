# coding: utf-8
# 创建: 2026-07-15  |  反汇编文本解析——从 objdump 输出构建指令模型
#
"""
objdump 文本解析器。

输入为 `objdump -d -M intel` 的输出, 支持 ELF 与 PE (MinGW) 两种格式。
输出为按函数分组的指令列表, 每条指令包含:
  addr   线性地址
  mnem   助记符 (小写)
  ops    操作数字符串列表
  raw    原始文本

兼容性要点:
  - PE 反汇编中 `mov QWORD PTR [rbp+0x10],rcx` 的操作数含类型前缀
  - 函数边界以 `^00000000....... <name>:` 开头 (无缩进)
  - 文件头/段信息行跳过
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

_FUNC_HEADER = re.compile(r"^([0-9a-fA-F]{8,16}) <(.*)>:$")
_INSN_LINE = re.compile(r"^\s+([0-9a-fA-F]{8,16}):\t")

# 寄存器类别——用于操作数解析
_X86_64_REGS = frozenset({
    "rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
    "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
    "eax", "ebx", "ecx", "edx", "esi", "edi", "ebp", "esp",
    "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d",
    "ax", "bx", "cx", "dx", "si", "di", "r8w", "r9w",
    "al", "bl", "cl", "dl", "sil", "dil", "r8b", "r9b",
    "rip",
})

# 寄存器别名映射 (32位/64位统一到64位族)
_REG_ALIAS = {
    "eax": "rax", "ebx": "rbx", "ecx": "rcx", "edx": "rdx",
    "esi": "rsi", "edi": "rdi", "ebp": "rbp", "esp": "rsp",
    "r8d": "r8", "r9d": "r9", "r10d": "r10", "r11d": "r11",
    "r12d": "r12", "r13d": "r13", "r14d": "r14", "r15d": "r15",
}


def normalize_reg(name: str) -> str:
    """寄存器名归一化: 32位映射到64位族 (用于定值链解析)."""
    return _REG_ALIAS.get(name, name)


@dataclass
class Instruction:
    """单条指令."""
    addr: int
    mnem: str
    ops: List[str] = field(default_factory=list)
    raw: str = ""
    bytes: str = ""

    @property
    def is_call(self) -> bool:
        return self.mnem == "call"

    @property
    def is_jump(self) -> bool:
        return self.mnem.startswith("j")

    def op(self, i: int) -> str:
        return self.ops[i] if i < len(self.ops) else ""

    def __repr__(self) -> str:
        return f"{self.addr:#x}: {self.mnem} {', '.join(self.ops)}"


@dataclass
class Function:
    """一个函数的指令序列."""
    name: str
    start: int
    insns: List[Instruction] = field(default_factory=list)

    @property
    def n(self) -> int:
        return len(self.insns)


def _split_ops(ops_text: str) -> List[str]:
    """拆分逗号分隔的操作数, 忽略方括号内的逗号 (少见)."""
    if not ops_text:
        return []
    parts: List[str] = []
    depth = 0
    cur = ""
    for ch in ops_text:
        if ch == "[":
            depth += 1
        elif ch == "]":
            depth -= 1
        if ch == "," and depth == 0:
            parts.append(cur.strip())
            cur = ""
        else:
            cur += ch
    if cur.strip():
        parts.append(cur.strip())
    return parts


def _parse_insn(line: str) -> Optional[Instruction]:
    """解析单条指令行:
        140001000:	55             	push   rbp
        140001000:	48 89 4d 10    	mov    QWORD PTR [rbp+0x10],rcx
    """
    m = _INSN_LINE.match(line)
    if not m:
        return None
    addr = int(m.group(1), 16)
    rest = line[m.end():]
    fields = rest.split("\t")
    if len(fields) < 2:
        return None
    byte_field = fields[0].strip()
    text = fields[-1].strip()
    # text 形如 "mov    QWORD PTR [rbp+0x10],rcx" 或 "jmp    140001789 <main+0x29>"
    parts = text.split(None, 1)
    mnem = parts[0].lower()
    ops_text = parts[1] if len(parts) > 1 else ""
    # 去掉尾随注释 "# 1400053e0"
    if "#" in ops_text:
        ops_text = ops_text.split("#", 1)[0].strip()
    ops = _split_ops(ops_text)
    return Instruction(addr=addr, mnem=mnem, ops=ops, raw=line.strip(),
                       bytes=byte_field)


def parse_disasm(text: str) -> List[Function]:
    """解析整个反汇编文本, 返回函数列表."""
    functions: List[Function] = []
    cur: Optional[Function] = None
    for line in text.splitlines():
        stripped = line.rstrip()
        m = _FUNC_HEADER.match(stripped)
        if m:
            cur = Function(name=m.group(2), start=int(m.group(1), 16))
            functions.append(cur)
            continue
        if cur is None:
            continue
        insn = _parse_insn(stripped)
        if insn is not None:
            cur.insns.append(insn)
    return [f for f in functions if f.insns]


def callee_name(insn: Instruction) -> str:
    """提取 call 指令的目标名: `<malloc>` -> malloc; `rax` -> rax."""
    if not insn.is_call:
        return ""
    tgt = insn.op(0).strip()
    m = re.search(r"<([^>]*)>", tgt)
    if m:
        name = m.group(1)
    else:
        name = tgt.lstrip("*").strip()
    return name.split("@")[0].split(".")[0]


def is_relative_jump(insn: Instruction) -> bool:
    """条件/无条件跳转 (排除 call 与 ret)."""
    return insn.mnem.startswith("j") and insn.mnem != "jmp" \
        or insn.mnem == "jmp"


__all__ = [
    "Instruction", "Function", "parse_disasm", "callee_name",
    "normalize_reg", "_X86_64_REGS",
]
