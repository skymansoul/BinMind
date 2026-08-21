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
    address: int
    opcode: int
    mnemonic: str
    operands: str
    instruction_set: str
    is_thumb32 = False
    condition = None

@dataclass
class FunctionBoundary:
    start_address: int
    end_address = None
    instruction_set = InstructionSet.UNKNOWN
    is_entry_point = False
    function_name = None

@dataclass
class ModeTransition:
    address: int
    from_mode: str
    to_mode: str
    transition_type: str

class ThumbInstructionDecoder:
    def __init__(self):
        self.instructions = []

    def decode_thumb16(self, opcode, address):
        if opcode & 0xF800 == 0x4800:
            return ARMInstruction(
                address=address,
                opcode=opcode,
                mnemonic='LDR',
                operands=['R0', '[PC, #{0}]'.format((opcode & 0x07FF) << 2)],
                instruction_set=InstructionSet.THUMB)

        elif opcode & 0xFF00 == 0x4700:
            return ARMInstruction(
                address=address,
                opcode=opcode,
                mnemonic='BX',
                operands=['R{0}'.format(opcode & 0x0F)],
                instruction_set=InstructionSet.THUMB)


        return None

    def decode_thumb32(self, opcode16_1, opcode16_2, address):
        combined = (opcode16_1 << 16) | opcode16_2
        if opcode16_1 & 0xF800 == 0xF000:
            return ARMInstruction(
                address=address,
                opcode=combined,
                mnemonic='BL',
                operands=['#{0}'.format(((combined >> 1) & 0x3FFFFFF) - 0x2000000)],
                instruction_set=InstructionSet.THUMB2,
                is_thumb32=True)


        return None

    def decode(self, raw_bytes, start_address=0):
        instructions = []
        offset = 0
        while offset < len(raw_bytes):
            if offset + 2 > len(raw_bytes):
                break
            opcode16 = int.from_bytes(raw_bytes[offset:offset+2], 'little')
            if opcode16 & 0xE000 == 0xE000:
                if offset + 4 <= len(raw_bytes):
                    opcode16_2 = int.from_bytes(raw_bytes[offset+2:offset+4], 'little')
                    instr = self.decode_thumb32(opcode16, opcode16_2, start_address + offset)
                    if instr:
                        instructions.append(instr)
                    offset += 4
                else:
                    instr = self.decode_thumb16(opcode16, start_address + offset)
                    if instr:
                        instructions.append(instr)
                    offset += 2
            else:
                instr = self.decode_thumb16(opcode16, start_address + offset)
                if instr:
                    instructions.append(instr)
                offset += 2
        self.instructions = instructions
        return instructions

class ThumbAnalyzer(BaseAnalyzer, ABC):
    def __init__(self, config=None):
        self._config = config or {}

    def analyze(self, **kwargs):
        raw_code = kwargs.get('raw_code')
        if not raw_code:
            return {'success': False, 'error': 'raw_code required'}

        decoder = ThumbInstructionDecoder()
        decoder.decode(raw_code, kwargs.get('start_address', 0))

        arm_count = sum(1 for i in decoder.instructions if i.instruction_set == InstructionSet.ARM)
        thumb_count = sum(1 for i in decoder.instructions if i.instruction_set == InstructionSet.THUMB)
        thumb2_count = sum(1 for i in decoder.instructions if i.instruction_set == InstructionSet.THUMB2)

        return {
            'success': True,
            'report': {
                'total_instructions': len(decoder.instructions),
                'arm_instructions': arm_count,
                'thumb_instructions': thumb_count,
                'thumb2_instructions': thumb2_count
            }
        }

