# EVM字节码解析器 - 操作码流 → 结构化表示

from dataclasses import dataclass, field
from typing import List, Optional, Tuple
from .opcodes import OPCODES, PUSH_OPCODES

@dataclass
class EVMOp:
    """单条 EVM 操作 — pc, opcode, name, push_data。"""
    pc: int
    opcode: int
    name: str
    push_data: bytes = b''
    gas: int = 0

    @property
    def is_push(self) -> bool: return self.opcode in PUSH_OPCODES
    @property
    def is_jumpdest(self) -> bool: return self.opcode == 0x5b


class EVMBytecodeParser:
    """EVM 字节码解析 - 返回 op 列表 + 自动 PUSH data 提取。"""

    def __init__(self, bytecode: bytes):
        self.raw = bytecode
        self.ops: List[EVMOp] = []
        self._jumpdest_positions: set = set()

    def parse(self) -> List[EVMOp]:
        pc = 0
        blen = len(self.raw)
        while pc < blen:
            opcode = self.raw[pc]
            if opcode in OPCODES:
                name, stack_in, stack_out, _family, gas = OPCODES[opcode]
            else:
                name, _si, _so, _f, gas = "INVALID", 0, 0, None, 0

            push_data = b''
            if opcode in PUSH_OPCODES:
                push_len = opcode - 0x5f
                end = min(pc + 1 + push_len, blen)
                push_data = self.raw[pc + 1:end]
                pc = end
            else:
                pc += 1

            op = EVMOp(pc=pc, opcode=opcode, name=name, push_data=push_data, gas=gas)
            self.ops.append(op)
            if op.is_jumpdest:
                self._jumpdest_positions.add(op.pc)
        return self.ops

    @property
    def jumpdest_positions(self) -> set:
        if not self._jumpdest_positions:
            for op in self.ops:
                if op.is_jumpdest:
                    self._jumpdest_positions.add(op.pc)
        return self._jumpdest_positions

    def get_basic_blocks(self) -> List[Tuple[int, List[EVMOp]]]:
        """按 JUMPDEST 切分基本块。"""
        blocks = []
        current = []
        start = 0
        for op in self.ops:
            if op.is_jumpdest and current:
                blocks.append((start, current))
                current = []
                start = op.pc
            current.append(op)
            if op.name in ('JUMP', 'JUMPI', 'RETURN', 'REVERT', 'STOP', 'INVALID', 'SELFDESTRUCT'):
                blocks.append((start, current))
                current = []
                start = op.pc + 1
        if current:
            blocks.append((start, current))
        return blocks
