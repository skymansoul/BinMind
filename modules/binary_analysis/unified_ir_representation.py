import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional, Tuple

logger = logging.getLogger(__name__)


class IROpcode:
    LOAD = "load"
    STORE = "store"
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    AND = "and"
    OR = "or"
    XOR = "xor"
    SHL = "shl"
    SHR = "shr"
    CMP = "cmp"
    JMP = "jmp"
    CJMP = "cjmp"
    CALL = "call"
    RETURN = "ret"

class IRInstruction:
    __slots__ = ('id', 'opcode', 'operands', 'original_addr', 'original_arch',)

    def __init__(self, id, opcode, operands=None, original_addr=0, original_arch="x86_64"):
        self.id = id
        self.opcode = opcode
        self.operands = operands if operands is not None else []
        self.original_addr = original_addr
        self.original_arch = original_arch

    def to_dict(self) -> Dict[str, Any]:
        return {
            'id': self.id, 'opcode': self.opcode.value,
            'operands': self.operands,
            'original_addr': hex(self.original_addr),
            'arch': self.original_arch
        }

class UnifiedIRRepresentation:

    ARCH_REGISTERS = {
        'x86_64': ['rax', 'rbx', 'rcx', 'rdx', 'rsi', 'rdi', 'rsp', 'rbp',
                   'r8', 'r9', 'r10', 'r11', 'r12', 'r13', 'r14', 'r15'],
        'arm64': ['x0', 'x1', 'x2', 'x3', 'x4', 'x5', 'x6', 'x7',
                  'x8', 'x9', 'x10', 'x11', 'x12', 'x13', 'x14', 'x15',
                  'sp', 'lr', 'pc'],
        'arm32': ['r0', 'r1', 'r2', 'r3', 'r4', 'r5', 'r6', 'r7',
                  'r8', 'r9', 'r10', 'r11', 'r12', 'sp', 'lr', 'pc'],
    }

    def __init__(self):
        self._ir: List[IRInstruction] = []
        self._counter = 0

    def _next_id(self) -> int:
        self._counter += 1
        return self._counter

    def map_register(self, reg: str, arch: str) -> str:
        # 将architecture寄存器映射到虚拟寄存器
        regs = self.ARCH_REGISTERS.get(arch, [])
        if reg in regs:
            return f"vreg_{arch}_{reg}"
        return f"vreg_{arch}_{reg}"

    def translate_basic_block(self, instructions: List[Tuple[int, str]],
                              arch: str = "x86_64") -> List[IRInstruction]:
        # 将basic block指令翻译为 IR
        ir_instrs = []
        for addr, instr in instructions:
            mnemonic = instr.split()[0].lower()
            ops = instr.split()[1:] if len(instr.split()) > 1 else []

            # 映射到 IR
            if mnemonic in ('mov', 'ldr', 'ldrb'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.LOAD,
                    operands=ops[:2], original_addr=addr, original_arch=arch))
            elif mnemonic in ('str', 'strb'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.STORE,
                    operands=ops[:2], original_addr=addr, original_arch=arch))
            elif mnemonic in ('add', 'adds'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.ADD,
                    operands=ops[:3], original_addr=addr, original_arch=arch))
            elif mnemonic in ('sub', 'subs'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.SUB,
                    operands=ops[:3], original_addr=addr, original_arch=arch))
            elif mnemonic in ('jmp', 'b', 'br'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.JMP,
                    operands=ops[:1], original_addr=addr, original_arch=arch))
            elif any(mnemonic.startswith(p) for p in ('j', 'b.')):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.CJMP,
                    operands=ops[:1], original_addr=addr, original_arch=arch))
            elif mnemonic in ('call', 'blr'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.CALL,
                    operands=ops[:1], original_addr=addr, original_arch=arch))
            elif mnemonic in ('ret', 'retn'):
                ir_instrs.append(IRInstruction(
                    id=self._next_id(), opcode=IROpcode.RETURN,
                    operands=[], original_addr=addr, original_arch=arch))

        self._ir.extend(ir_instrs)
        return ir_instrs

    def analyze(self, code_blocks: Optional[List[Dict[str, Any]]] = None,
                **kwargs) -> Dict[str, Any]:
        if code_blocks:
            for block in code_blocks:
                self.translate_basic_block(
                    block.get('instructions', []),
                    block.get('arch', 'x86_64'))

        return {
            'success': True,
            'total_ir_instructions': len(self._ir),
            'ir_by_opcode': {op.value: sum(1 for i in self._ir
                                          if i.opcode == op)
                            for op in IROpcode},
            'supported_archs': list(self.ARCH_REGISTERS.keys()),
            'ir_sample': [i.to_dict() for i in self._ir[:30]]
        }

def unify_ir_representation(code_blocks: List[Dict[str, Any]],
                             **kwargs) -> Dict[str, Any]:
    engine = UnifiedIRRepresentation()
    return engine.analyze(code_blocks=code_blocks)

