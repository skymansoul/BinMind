"""objdump 反汇编指令解析器 — Intel 语法 → 结构化指令列表.

输入: objdump -d -M intel 的文本输出
输出: List[ParsedInstruction]

设计决策:
  - 使用正则而非完整反汇编库: 避免对 capstone/keystone 的依赖,
    在最小环境下也能工作 (仅需 objdump).
  - 保守解析: 无法解析的行跳过, 不抛异常.
"""

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class ParsedInstruction:
    """objdump 解析后的单条指令."""
    address: int
    mnemonic: str
    operands: List[str]
    raw_line: str = ""


class InstructionParser:
    """objdump 输出解析器."""

    _LINE_RE = re.compile(
        r'^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2}\s+)+\s*(.+)$')

    # 规范化: 32-bit → 64-bit 寄存器
    REG_ALIASES = {
        'eax': 'rax', 'ebx': 'rbx', 'ecx': 'rcx', 'edx': 'rdx',
        'esi': 'rsi', 'edi': 'rdi', 'ebp': 'rbp', 'esp': 'rsp',
        'r8d': 'r8', 'r9d': 'r9', 'r10d': 'r10',
    }

    KNOWN_REGS = {'rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rbp', 'rsp',
                  'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'}

    # 导入表兜底: call 目标地址 → 函数名 (剥离二进制的符号恢复)
    # 由 plt_resolver.build_import_map 填充; 空映射时行为与旧版一致
    _IMPORT_MAP: Dict[int, str] = {}

    @classmethod
    def set_import_map(cls, mapping: Dict[int, str]):
        cls._IMPORT_MAP = mapping

    @classmethod
    def parse(cls, objdump_output: str) -> List[ParsedInstruction]:
        instructions = []
        for line in objdump_output.split("\n"):
            m = cls._LINE_RE.match(line)
            if not m:
                continue
            try:
                addr = int(m.group(1), 16)
            except ValueError:
                continue
            rest = m.group(2).strip()
            parts = rest.split(None, 1)
            if not parts:
                continue
            mnemonic = parts[0].strip()
            ops_str = parts[1].strip() if len(parts) > 1 else ""
            operands = cls._split_operands(ops_str) if ops_str else []
            instructions.append(ParsedInstruction(
                address=addr, mnemonic=mnemonic,
                operands=operands, raw_line=line.strip()))
        return instructions

    @classmethod
    def normalize_reg(cls, op: str) -> Optional[str]:
        """规范化寄存器名 → 64位形式. 非寄存器返回 None."""
        op = op.strip().lower()
        if '[' in op or ']' in op:
            return None
        for kw in ['qword', 'dword', 'word', 'byte', 'ptr']:
            op = op.replace(kw, '').strip()
        if op in cls.REG_ALIASES:
            return cls.REG_ALIASES[op]
        if op in cls.KNOWN_REGS:
            return op
        return None

    @classmethod
    def is_immediate(cls, op: str) -> bool:
        op = op.strip().lower()
        return op.startswith('0x') or op.lstrip('-').isdigit()

    @classmethod
    def extract_callee(cls, ins: ParsedInstruction) -> str:
        """从 call 指令提取函数名."""
        if not ins.operands:
            return ""
        target = ins.operands[0]
        m = re.search(r'<(.+?)>', target)
        if m:
            name = m.group(1)
            if '@' in name:
                name = name.split('@')[0]
            return name
        # 裸地址 → 导入表兜底 (剥离二进制)
        addr_part = target.split()[0] if target else ""
        try:
            addr = int(addr_part, 16)
        except ValueError:
            return target.strip()
        return cls._IMPORT_MAP.get(addr, target.strip())

    @classmethod
    def parse_memory_operand(cls, op: str) -> Tuple[Optional[str], int]:
        """解析内存操作数 [reg+offset] → (reg_name, offset)."""
        base, idx, scale, offset = cls.parse_memory_operand_full(op)
        return (idx or base, offset)

    @classmethod
    def parse_memory_operand_full(cls, op: str) -> Tuple[
        Optional[str], Optional[str], int, int]:
        """解析内存操作数 → (base_reg, index_reg, scale, offset).
        e.g. [rax+rdx*4+0x10] → (rax, rdx, 4, 16)
             [rbp-0x18]       → (rbp, None, 1, -24)
        """
        op = op.strip().lower()
        m = re.match(r'(?:qword|dword|word|byte)\s+(?:ptr\s+)?\[(.+)\]', op)
        inner = m.group(1) if m else (
            op[1:-1] if op.startswith('[') and op.endswith(']') else None)
        if inner is None:
            return None, None, 1, 0

        offset = 0
        base_reg = None
        index_reg = None
        scale = 1
        for part in inner.replace('-', '+-').split('+'):
            part = part.strip()
            if not part:
                continue
            # 尝试解析为立即数 (0x10 或 -0x18 或 24 或 -24)
            val = cls._try_parse_int(part)
            if val is not None:
                offset += val
                continue
            # 尝试解析为 reg*scale
            if '*' in part:
                subparts = part.split('*')
                if len(subparts) == 2:
                    r = cls.normalize_reg(subparts[0].strip())
                    try:
                        s = int(subparts[1].strip(), 0)
                    except ValueError:
                        s = 1
                    if r:
                        index_reg = r
                        scale = s
                continue
            # 寄存器
            r = cls.normalize_reg(part)
            if r:
                base_reg = r
        return base_reg, index_reg, scale, offset

    @staticmethod
    def _try_parse_int(s: str) -> Optional[int]:
        """尝试将字符串解析为整数 (支持 0x, 0X, 负号). 失败返回 None."""
        s = s.strip()
        if not s:
            return None
        # 负数处理
        sign = 1
        if s.startswith('-'):
            sign = -1
            s = s[1:]
        if s.startswith('0x') or s.startswith('0X'):
            try:
                return sign * int(s, 16)
            except ValueError:
                return None
        elif s.isdigit():
            return sign * int(s)
        return None

    @classmethod
    def infer_access_size(cls, ins: ParsedInstruction) -> int:
        """推断内存访问的字节大小."""
        raw = ins.raw_line.lower()
        if 'qword' in raw:
            return 8
        if 'dword' in raw:
            return 4
        if 'word' in raw:
            return 2
        if 'byte' in raw:
            return 1
        if ins.operands:
            dst = ins.operands[0].strip().lower()
            if dst.startswith('r') and dst not in ('rip',):
                return 8
            if dst.startswith('e'):
                return 4
        return 8

    # objdump 函数标记: 0000000140001760 <main>:
    _FUNC_RE = re.compile(r'^\s*([0-9a-f]+)\s+<(.+?)>:\s*$')

    @classmethod
    def parse_functions(cls, objdump_output: str) -> Dict[int, str]:
        """解析 objdump 输出中的函数边界 → {addr: name}.
        返回按地址排序的字典. 函数结束于下一个函数的 start-1.
        """
        funcs = {}
        for line in objdump_output.split("\n"):
            m = cls._FUNC_RE.match(line)
            if m:
                addr = int(m.group(1), 16)
                name = m.group(2).strip()
                funcs[addr] = name
        return dict(sorted(funcs.items()))

    @classmethod
    def filter_user_instructions(cls, insns: List[ParsedInstruction],
                                  funcs: Dict[int, str]) -> List[ParsedInstruction]:
        """过滤指令列表, 仅保留用户函数内的指令.
        用户函数: main + 不以 __ . _ 开头的函数.
        """
        func_addrs = sorted(funcs.keys())
        user_ranges = []
        for i, start_addr in enumerate(func_addrs):
            name = funcs[start_addr]
            # 跳过 CRT/运行时函数 及 MinGW 启动代码
            if (name.startswith('__') or name.startswith('.')
                or name.startswith('_')
                or name in ('duplicate_ppstrings', 'WinMainCRTStartup',
                            'mainCRTStartup', 'check_managed_app',
                            'do_pseudo_reloc', 'mark_section_writable',
                            'restore_modified_sections', '_pei386_runtime_relocator',
                            'safe_flush', 'atexit')):
                continue
            # 计算函数结束地址
            end_addr = func_addrs[i + 1] if i + 1 < len(func_addrs) else 0xFFFFFFFFFFFFFFFF
            user_ranges.append((start_addr, end_addr))
        if not user_ranges:
            return insns  # 无用户函数 → 返回全部
        filtered = []
        for ins in insns:
            for start, end in user_ranges:
                if start <= ins.address < end:
                    filtered.append(ins)
                    break
        return filtered

    @staticmethod
    def _split_operands(ops_str: str) -> List[str]:
        """按逗号分隔操作数, 处理方括号嵌套."""
        result = []
        depth = 0
        current = []
        for ch in ops_str:
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
            if ch == ',' and depth == 0:
                result.append(''.join(current).strip())
                current = []
            else:
                current.append(ch)
        if current:
            result.append(''.join(current).strip())
        return result

    @classmethod
    def resolve_function(cls, addr: int,
                         funcs: Dict[int, str]) -> Optional[str]:
        """查地址属于哪个函数 → 函数名."""
        sorted_addrs = sorted(funcs.keys())
        for i, start in enumerate(sorted_addrs):
            end = (sorted_addrs[i + 1]
                   if i + 1 < len(sorted_addrs) else 0xFFFFFFFFFFFFFFFF)
            if start <= addr < end:
                return funcs[start]
        return None
