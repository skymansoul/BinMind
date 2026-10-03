# 逆向切片深度自限: 回溯 <=32 条指令, 超出部分保守标记为 UNKNOWN
# 污点源分类: INPUT_BYTE/FILE_CONTENTS/NETWORK_DATA/HEAP_SPRAY/UNKNOWN

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, FrozenSet, List, Optional, Set, Tuple


# 污点源与数据流节点

class TaintSource(Enum):
    INPUT_BYTE = auto()        # 来自程序输入缓冲区 (argv, stdin, file)
    FILE_CONTENTS = auto()     # 来自文件读取 (fread, mmap 文件)
    NETWORK_DATA = auto()      # 来自网络 (recv, recvfrom, read on socket)
    HEAP_SPRAY = auto()        # 匹配已知堆喷射模式
    REGISTER_LEAK = auto()     # 来自信息泄漏 (如 /proc/self/maps)
    CONSTANT = auto()          # 常数值--非攻击者可控
    UNKNOWN = auto()           # 无法确定


@dataclass
class TaintTag:
    source: TaintSource = TaintSource.UNKNOWN
    distance: int = 999          # 从污染源到当前值的指令距离 (越小越直接)
    confidence: float = 0.0      # [0,1] 控制置信度
    # 追溯链: 每一步的 (地址, 指令) -> 用于审计和解释
    trace: List[Tuple[int, str]] = field(default_factory=list)


@dataclass
class ControlAssessment:
    # 通用寄存器 -> 污点标记
    registers: Dict[str, TaintTag] = field(default_factory=dict)
    # 内存地址 -> 污点标记 (仅追踪崩溃指令访问的地址)
    memory_locations: Dict[int, TaintTag] = field(default_factory=dict)
    # 指令指针是否可控
    pc_controlled: bool = False
    pc_control_confidence: float = 0.0
    # 栈指针是否可控
    sp_controlled: bool = False
    sp_control_confidence: float = 0.0
    # 总体评估
    overall_control_score: float = 0.0  # [0, 1] - 0=不可控, 1=完全可控


# 轻量级数据流追踪器

# x86_64 调用约定的返回值寄存器 (按优先级)
_RETURN_REGS = ['rax', 'eax', 'ax', 'al']

# 已知的输入源函数及其对应的污点源
_INPUT_SOURCE_FUNCTIONS = {
    'read':   (TaintSource.FILE_CONTENTS, 0),
    'fread':  (TaintSource.FILE_CONTENTS, 0),
    'recv':   (TaintSource.NETWORK_DATA, 0),
    'recvfrom': (TaintSource.NETWORK_DATA, 0),
    'recvmsg':  (TaintSource.NETWORK_DATA, 0),
    'scanf':  (TaintSource.INPUT_BYTE, 0),
    'fscanf': (TaintSource.INPUT_BYTE, 0),
    'fgets':  (TaintSource.INPUT_BYTE, 0),
    'getc':   (TaintSource.INPUT_BYTE, 0),
    'getchar': (TaintSource.INPUT_BYTE, 0),
    'mmap':   (TaintSource.FILE_CONTENTS, 0),
}


class CrashPrimitiveSlicer:

    _MAX_BACKTRACE = 32

    # 寄存器别名组--组内任一寄存器被污染 -> 全组标记
    _REG_ALIASES = {
        'rax': {'rax', 'eax', 'ax', 'al', 'ah'},
        'rbx': {'rbx', 'ebx', 'bx', 'bl', 'bh'},
        'rcx': {'rcx', 'ecx', 'cx', 'cl', 'ch'},
        'rdx': {'rdx', 'edx', 'dx', 'dl', 'dh'},
        'rsi': {'rsi', 'esi', 'si', 'sil'},
        'rdi': {'rdi', 'edi', 'di', 'dil'},
        'rbp': {'rbp', 'ebp', 'bp', 'bpl'},
        'rsp': {'rsp', 'esp', 'sp', 'spl'},
        'r8':  {'r8', 'r8d', 'r8w', 'r8b'},
        'r9':  {'r9', 'r9d', 'r9w', 'r9b'},
        'r10': {'r10', 'r10d', 'r10w', 'r10b'},
        'r11': {'r11', 'r11d', 'r11w', 'r11b'},
        'r12': {'r12', 'r12d', 'r12w', 'r12b'},
        'r13': {'r13', 'r13d', 'r13w', 'r13b'},
        'r14': {'r14', 'r14d', 'r14w', 'r14b'},
        'r15': {'r15', 'r15d', 'r15w', 'r15b'},
    }

    def __init__(self):
        self._taint: Dict[str, TaintTag] = {}

    def analyze(
        self,
        crash_registers: Dict[str, int],
        instruction_trace: List[Tuple[int, str]],
        crash_insn: Optional[Tuple[int, str]] = None,
    ) -> ControlAssessment:
        self._taint.clear()

        # 初始化: 所有崩溃时的寄存器值标记为 UNKNOWN
        for reg, val in crash_registers.items():
            self._taint[reg.lower()] = TaintTag(
                source=TaintSource.UNKNOWN,
                distance=0,
                confidence=0.0,
            )

        # 沿指令迹逆向传播污点
        trace_slice = instruction_trace[-self._MAX_BACKTRACE:]
        for addr, insn_text in reversed(trace_slice):
            self._propagate_backward(addr, insn_text)

        # 构建评估
        return self._build_assessment(crash_registers, crash_insn)

    def _propagate_backward(self, addr: int, insn_text: str) -> None:
        """逆向传播一条指令的数据流

        分析指令的 def-use 关系:
        - 若 dst 被污染且 src 是常量 -> dst 污染来自外部 (可能来自此指令前的操作)
        - 若 dst 被污染且 src 也被污染 -> dst 的污点来自 src, 合并污点信息
        - 若 dst 未被污染但 src 被污染 -> dst 继承 src 的污点 (正向传播的反向)
        """
        text = insn_text.strip().lower()
        parts = text.split()
        if not parts:
            return

        mnemonic = parts[0]
        operands = ' '.join(parts[1:]) if len(parts) > 1 else ''

        # 检测 call 指令--检查是否调用了已知的输入源函数
        if mnemonic == 'call':
            self._handle_call_taint(operands)
            return

        # 提取目标寄存器 (def) 和源寄存器 (use)
        dst_regs = self._extract_dst_registers(mnemonic, operands)
        src_regs = self._extract_src_registers(mnemonic, operands)

        # 逆向传播规则: 若 dst 有污点, 将污点传播给 src
        for dst in dst_regs:
            dst_tag = self._get_tag(dst)
            if dst_tag.source == TaintSource.UNKNOWN:
                continue  # dst 无污点信息, 无传播

            # dst 有污点 -> 污点可能来自 src -> 反向传播
            for src in src_regs:
                src_tag = self._get_tag(src)
                if dst_tag.distance < src_tag.distance:
                    # dst 的污点距离更近 -> src 的污点应继承 dst
                    new_tag = TaintTag(
                        source=dst_tag.source,
                        distance=dst_tag.distance + 1,
                        confidence=max(0.0, dst_tag.confidence - 0.03),
                        trace=dst_tag.trace + [(addr, insn_text)],
                    )
                    self._set_tag(src, new_tag)

        # 检测常量操作数--若 dst 被标记且 src 包含已知模式
        self._check_constant_patterns(dst_regs, operands)

    def _handle_call_taint(self, operands: str) -> None:
        target = operands.strip()
        # 去除间接调用语法: call [rax], call *rax
        target_clean = target.lstrip('*[').rstrip(']').strip()
        func_name = target_clean.split('+')[0].split('@')[0]

        if func_name in _INPUT_SOURCE_FUNCTIONS:
            src_type, base_dist = _INPUT_SOURCE_FUNCTIONS[func_name]
            for ret_reg in _RETURN_REGS:
                self._set_tag(ret_reg, TaintTag(
                    source=src_type,
                    distance=base_dist,
                    confidence=0.95,
                    trace=[(0, f'call {func_name}')],
                ))

    def _check_constant_patterns(
        self, dst_regs: List[str], operands: str
    ) -> None:
        # 0x41414141 ('AAAA'), 0x90909090 (NOP sled) -> 输入缓冲区溢出
        hex_vals = re.findall(r'(0x[0-9a-f]{8,16})', operands, re.I)
        for hv in hex_vals:
            val = int(hv, 16)
            val_bytes = val.to_bytes(8, 'little')
            # 检查是否为可打印 ASCII 模式 (常见于缓冲区溢出)
            if all(0x20 <= b <= 0x7e for b in val_bytes[:4]):
                for dst in dst_regs:
                    self._set_tag(dst, TaintTag(
                        source=TaintSource.INPUT_BYTE,
                        distance=1,
                        confidence=0.80,
                        trace=[(0, f'const_pattern 0x{val:016x}')],
                    ))

# 寄存器提取
    _REG_PATTERN = re.compile(
        r'\b(r(?:ax|bx|cx|dx|si|di|bp|sp|8|9|1[0-5])'
        r'|e(?:ax|bx|cx|dx|si|di|bp|sp)'
        r'|[abcd]x|[abcd][lh]|si|di|bp|sp'
        r'|r(?:8|9|1[0-5])[dwb]?)\b', re.I
    )

    def _extract_dst_registers(self, mnemonic: str, operands: str) -> List[str]:
        if mnemonic in ('cmp', 'test', 'jmp', 'je', 'jne', 'jz', 'jnz',
                        'jb', 'jae', 'ja', 'jbe', 'jl', 'jg', 'jle', 'jge',
                        'js', 'jns', 'jo', 'jno', 'call', 'ret', 'nop'):
            return []
        # 大部分指令的 dst 是第一个操作数
        parts = operands.split(',')
        if not parts:
            return []
        first_op = parts[0].strip()
        found = self._REG_PATTERN.findall(first_op)
        return [r.lower() for r in found]

    def _extract_src_registers(self, mnemonic: str, operands: str) -> List[str]:
        parts = operands.split(',')
        src_parts = parts[1:] if len(parts) > 1 else []
        # 对单操作数指令 (push, pop, inc, dec), 操作数既是 src 也是 dst
        if mnemonic in ('push', 'pop', 'inc', 'dec', 'not', 'neg', 'mul', 'div'):
            src_parts = parts
        found = []
        for p in src_parts:
            found.extend(self._REG_PATTERN.findall(p.strip()))
        return [r.lower() for r in found]

# 污点访问
    def _get_tag(self, reg: str) -> TaintTag:
        r = reg.lower()
        for canonical, aliases in self._REG_ALIASES.items():
            if r in aliases:
                return (self._taint.get(canonical)
                        or self._taint.get(r)
                        or TaintTag())
        return self._taint.get(r, TaintTag())

    def _set_tag(self, reg: str, tag: TaintTag) -> None:
        r = reg.lower()
        for canonical, aliases in self._REG_ALIASES.items():
            if r in aliases:
                existing = self._taint.get(canonical)
                if existing is None or tag.confidence > existing.confidence:
                    self._taint[canonical] = tag
                return
        # 未知寄存器--直接设置
        existing = self._taint.get(r)
        if existing is None or tag.confidence > existing.confidence:
            self._taint[r] = tag

    def _build_assessment(
        self,
        crash_registers: Dict[str, int],
        crash_insn: Optional[Tuple[int, str]],
    ) -> ControlAssessment:
        assessment = ControlAssessment()

        for reg, val in crash_registers.items():
            tag = self._get_tag(reg)
            assessment.registers[reg.lower()] = tag

        # 检测 PC 控制
        pc_tag = self._get_tag('rip')
        if pc_tag.source not in (TaintSource.UNKNOWN, TaintSource.CONSTANT):
            assessment.pc_controlled = True
            assessment.pc_control_confidence = pc_tag.confidence

        # 检测 SP 控制
        sp_tag = self._get_tag('rsp')
        if sp_tag.source not in (TaintSource.UNKNOWN, TaintSource.CONSTANT):
            assessment.sp_controlled = True
            assessment.sp_control_confidence = sp_tag.confidence

        # 计算总体控制度: 非 UNKNOWN 寄存器比例
        tracked = 0
        controlled = 0
        for reg, tag in assessment.registers.items():
            if reg in ('rip', 'rflags'):
                continue
            tracked += 1
            if tag.source not in (TaintSource.UNKNOWN, TaintSource.CONSTANT):
                controlled += 1

        if tracked > 0:
            assessment.overall_control_score = controlled / tracked

        return assessment
