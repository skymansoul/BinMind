import logging
from dataclasses import dataclass, field
from typing import Dict, List, Any, Optional, Tuple, Set

try:
    from loguru import logger as loguru_logger
    LOGURU_AVAILABLE = True
except ImportError:
    LOGURU_AVAILABLE = False

from core.plugin_manager import BaseAnalyzer, AnalyzerMetadata, AnalyzerType

from abc import ABC


class InstructionSet:
    ARM = "arm"
    THUMB = "thumb"
    THUMB2 = "thumb2"
    UNKNOWN = "unknown"


class ThumbMode:
    THUMB_16 = "thumb_16"
    THUMB_32 = "thumb_32"


@dataclass
class ARMInstruction:
    address: int = 0
    opcode: int = 0
    mnemonic: str = ""
    operands: list = field(default_factory=list)
    instruction_set: str = InstructionSet.UNKNOWN
    is_thumb32: bool = False
    condition: str = ""


@dataclass
class FunctionBoundary:
    start_address: int = 0
    end_address: int = 0
    instruction_set: str = InstructionSet.UNKNOWN
    is_entry_point: bool = False
    function_name: str = ""


@dataclass
class ModeTransition:
    address: int = 0
    from_mode: str = ""
    to_mode: str = ""
    transition_type: str = ""


# Thumb16解码表: opcode高位分组匹配, O(1)查表
# 查找表替代条件链, 批量解码吞吐优先
_THUMB16_DECODE = {
    # (mask, value) → (mnemonic, operand_parser)
    (0xF800, 0x4800): ("LDR", lambda w, a: ['R0', f'[PC, #{(w & 0x07FF) << 2}]']),
    (0xFF00, 0x4700): ("BX", lambda w, a: [f'R{w & 0x0F}']),
    (0xFF00, 0x4600): ("MOV", lambda w, a: [f'R{(w >> 3) & 0x07}', f'R{w & 0x07}']),
    (0xFE00, 0x1800): ("ADD", lambda w, a: [f'R{w & 0x07}', f'R{(w >> 3) & 0x07}', f'R{(w >> 6) & 0x07}']),
    (0xFE00, 0x1A00): ("SUB", lambda w, a: [f'R{w & 0x07}', f'R{(w >> 3) & 0x07}', f'R{(w >> 6) & 0x07}']),
    (0xFE00, 0x2000): ("MOVS", lambda w, a: [f'R{(w >> 8) & 0x07}', f'#{w & 0xFF}']),
    (0xFE00, 0x5000): ("STR", lambda w, a: [f'R{w & 0x07}', f'[R{(w >> 3) & 0x07}, #{(w >> 6) & 0x1F}]']),
    (0xFE00, 0x6800): ("LDR", lambda w, a: [f'R{w & 0x07}', f'[R{(w >> 3) & 0x07}, #{(w >> 6) & 0x1F}]']),
    (0xF000, 0xD000): ("BEQ", lambda w, a: [f'#{w & 0xFF}']),
    (0xFFFF, 0xBE00): ("BKPT", lambda w, a: [f'#{w & 0xFF}']),
    (0xFF00, 0xDF00): ("SVC", lambda w, a: [f'#{w & 0xFF}']),
    (0xFE00, 0xBC00): ("POP", lambda w, a: [f'{{{_decode_reglist(w)}}}']),
    (0xFE00, 0xB400): ("PUSH", lambda w, a: [f'{{{_decode_reglist(w)}}}']),
}

# Thumb32 BL/BLX/DSB/DMB/ISB 编码表
_THUMB32_DECODE = {
    (0xF800, 0xF000, 0xC000, 0x8000): "BL",
    (0xF800, 0xF000, 0xD000, 0x8000): "BLX",
    (0xFFF0, 0xF3BF, 0x8F00, 0x8F00): "DSB",
    (0xFFF0, 0xF3BF, 0x8F00, 0x8F40): "DMB",
    (0xFFF0, 0xF3BF, 0x8F00, 0x8F50): "ISB",
}


def _decode_reglist(word: int) -> str:
    """将16-bit指令中的寄存器位掩码解码为R0-R7列表字符串。"""
    regs = []
    for r in range(8):
        if word & (1 << r):
            regs.append(f"R{r}")
    return ", ".join(regs)


class ThumbInstructionDecoder:
    """Thumb/Thumb2 指令解码器。

    设计约束：
      - 查找表驱动，避免条件分支，批量吞吐优先
      - Thumb32: 高/低16位双重掩码匹配，确认指令类型
      - 未知指令返回None，不抛异常；调用方降级兜底
    """

    def __init__(self):
        self.instructions: List[ARMInstruction] = []

    def decode_thumb16(self, opcode: int, address: int) -> Optional[ARMInstruction]:
        for (mask, val), (mnem, parser) in _THUMB16_DECODE.items():
            if (opcode & mask) == val:
                return ARMInstruction(
                    address=address,
                    opcode=opcode,
                    mnemonic=mnem,
                    operands=parser(opcode, address),
                    instruction_set=InstructionSet.THUMB)
        return None

    def decode_thumb32(self, opcode16_1: int, opcode16_2: int, address: int) -> Optional[ARMInstruction]:
        combined = (opcode16_1 << 16) | opcode16_2
        for (m1, v1, m2, v2), mnem in _THUMB32_DECODE.items():
            if (opcode16_1 & m1) == v1 and (opcode16_2 & m2) == v2:
                if mnem in ("BL", "BLX"):
                    # S型立即数编码：拼接I1/I2后符号扩展
                    s_bit = (opcode16_1 >> 10) & 1
                    i1 = (opcode16_2 >> 13) & 1
                    i2 = (opcode16_2 >> 11) & 1
                    j1 = (~(i1 ^ s_bit)) & 1 if s_bit else i1
                    j2 = (~(i2 ^ s_bit)) & 1 if s_bit else i2
                    imm10 = opcode16_1 & 0x3FF
                    imm11 = opcode16_2 & 0x7FF
                    offset = (s_bit << 24) | (j1 << 23) | (j2 << 22) | (imm10 << 12) | (imm11 << 1)
                    if offset & 0x01000000:
                        offset |= 0xFE000000
                    return ARMInstruction(
                        address=address,
                        opcode=combined,
                        mnemonic=mnem,
                        operands=[f'#{offset}'],
                        instruction_set=InstructionSet.THUMB2,
                        is_thumb32=True)
                return ARMInstruction(
                    address=address,
                    opcode=combined,
                    mnemonic=mnem,
                    operands=[],
                    instruction_set=InstructionSet.THUMB2,
                    is_thumb32=True)
        return None

    def decode(self, raw_bytes: bytes, start_address: int = 0) -> List[ARMInstruction]:
        instructions = []
        offset = 0
        n = len(raw_bytes)
        while offset < n:
            if offset + 2 > n:
                break
            opcode16 = int.from_bytes(raw_bytes[offset:offset + 2], 'little')
            # Thumb32指示位：高5位为11101/11110/11111
            is_thumb32_candidate = (opcode16 & 0xF800) in (0xE800, 0xF000, 0xF800)
            if is_thumb32_candidate and offset + 4 <= n:
                opcode16_2 = int.from_bytes(raw_bytes[offset + 2:offset + 4], 'little')
                instr = self.decode_thumb32(opcode16, opcode16_2, start_address + offset)
                if instr:
                    instructions.append(instr)
                    offset += 4
                    continue
            instr = self.decode_thumb16(opcode16, start_address + offset)
            if instr:
                instructions.append(instr)
            offset += 2
        self.instructions = instructions
        return instructions


class ThumbAnalyzer(BaseAnalyzer, ABC):
    """ARM Thumb/Thumb2 指令集分析。

    识别 ARM-Thumb 模式切换点、Thumb16/32 混合比例、
    间接跳转目标、函数边界推断。
    """

    def __init__(self, config=None):
        self._config = config or {}

    def analyze(self, **kwargs) -> dict:
        raw_code = kwargs.get('raw_code')
        if not raw_code:
            return {'success': False, 'error': 'raw_code required'}

        decoder = ThumbInstructionDecoder()
        instructions = decoder.decode(raw_code, kwargs.get('start_address', 0))

        # 指令集分类计数
        arm_count = 0
        thumb_count = 0
        thumb2_count = 0
        bx_insns: List[ARMInstruction] = []  # BX = ARM↔Thumb模式切换
        bl_insns: List[ARMInstruction] = []  # BL/BLX = 函数调用点

        for i in instructions:
            iset = i.instruction_set
            if iset == InstructionSet.ARM:
                arm_count += 1
            elif iset == InstructionSet.THUMB2:
                thumb2_count += 1
            else:
                thumb_count += 1
            if i.mnemonic == "BX":
                bx_insns.append(i)
            if i.mnemonic in ("BL", "BLX"):
                bl_insns.append(i)

        # 解码覆盖率: 未知比例过高 → 非Thumb代码区域
        total = len(instructions)
        decoded_ratio = total / max(1, len(raw_code) // 2)
        # 函数边界推断: BL目标地址 → 自然边界
        inferred_boundaries = [i.operands[0] if i.operands else ""
                               for i in bl_insns[:20]]

        return {
            'success': True,
            'report': {
                'total_instructions': total,
                'arm_instructions': arm_count,
                'thumb_instructions': thumb_count,
                'thumb2_instructions': thumb2_count,
                'mode_switches': len(bx_insns),
                'function_calls': len(bl_insns),
                'decode_coverage': round(decoded_ratio, 3),
                'inferred_boundaries': inferred_boundaries,
            }
        }

    @classmethod
    def get_metadata(cls) -> AnalyzerMetadata:
        return AnalyzerMetadata(
            name="ThumbAnalyzer",
            type=AnalyzerType.STATIC_ANALYZER,
            version="1.1.0",
            description="ARM Thumb/Thumb2 instruction decoder with mode-switch detection",
            author="BinaryAnalysisPlatform",
            dependencies=[],
            supported_platforms=["arm", "thumb"],
        )
