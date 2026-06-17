import logging
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)


class Architecture(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    RISCV = "riscv"
    MIPS = "mips"


class IROpcode(Enum):
    ADD = "add"
    SUB = "sub"
    MUL = "mul"
    DIV = "div"
    AND = "and"
    OR = "or"
    XOR = "xor"
    LOAD = "load"
    STORE = "store"
    BRANCH = "branch"
    CALL = "call"
    RET = "ret"
    NOP = "nop"


@dataclass
class IRInstruction:
    opcode: IROpcode
    operands: List[str]
    comment: Optional[str] = None
    address: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            'opcode': self.opcode.value,
            'operands': self.operands,
            'comment': self.comment,
            'address': hex(self.address)
        }


@dataclass
class IRFunction:
    name: str
    address: int
    instructions: List[IRInstruction]
    arguments: List[str] = field(default_factory=list)
    return_type: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {
            'name': self.name,
            'address': hex(self.address),
            'instructions': [i.to_dict() for i in self.instructions],
            'arguments': self.arguments,
            'return_type': self.return_type
        }


@dataclass
class IRModule:
    architecture: Architecture
    functions: List[IRFunction]
    global_vars: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            'architecture': self.architecture.value,
            'functions': [f.to_dict() for f in self.functions],
            'global_vars': self.global_vars,
            'metadata': self.metadata
        }


class UnifiedIRConverter:
    
    def __init__(self, target_arch: Architecture = Architecture.X86_64):
        self.target_arch = target_arch
        self.register_mapping = {
            Architecture.X86: {
                'eax': 'r0', 'ebx': 'r1', 'ecx': 'r2', 'edx': 'r3',
                'esi': 'r4', 'edi': 'r5', 'ebp': 'r6', 'esp': 'r7'
            },
            Architecture.X86_64: {
                'rax': 'r0', 'rbx': 'r1', 'rcx': 'r2', 'rdx': 'r3',
                'rsi': 'r4', 'rdi': 'r5', 'rbp': 'r6', 'rsp': 'r7',
                'r8': 'r8', 'r9': 'r9', 'r10': 'r10', 'r11': 'r11',
                'r12': 'r12', 'r13': 'r13', 'r14': 'r14', 'r15': 'r15'
            },
            Architecture.ARM: {
                'r0': 'r0', 'r1': 'r1', 'r2': 'r2', 'r3': 'r3',
                'r4': 'r4', 'r5': 'r5', 'r6': 'r6', 'r7': 'r7',
                'r8': 'r8', 'r9': 'r9', 'r10': 'r10', 'r11': 'r11',
                'r12': 'r12', 'sp': 'r13', 'lr': 'r14', 'pc': 'r15'
            },
            Architecture.ARM64: {
                'x0': 'r0', 'x1': 'r1', 'x2': 'r2', 'x3': 'r3',
                'x4': 'r4', 'x5': 'r5', 'x6': 'r6', 'x7': 'r7',
                'x8': 'r8', 'x9': 'r9', 'x10': 'r10', 'x11': 'r11',
                'x12': 'r12', 'x13': 'r13', 'x14': 'r14', 'x15': 'r15'
            }
        }
    
    def convert(self, assembly_code: str, arch: Optional[Architecture] = None) -> IRModule:
        target_arch = arch or self.target_arch
        functions = []
        
        lines = assembly_code.strip().split('\n')
        
        current_function = None
        current_instructions = []
        
        for line in lines:
            line = line.strip()
            
            if not line or line.startswith(';'):
                continue
            
            if line.startswith('.text'):
                continue
            
            if ':' in line and not line.startswith('.'):
                func_name = line.split(':')[0].strip()
                if current_function:
                    functions.append(IRFunction(
                        name=current_function,
                        address=0,
                        instructions=current_instructions
                    

                
                current_function = func_name
                current_instructions = []
                continue
            
            if current_function:
                ir_instr = self._convert_instruction(line, target_arch)
                if ir_instr:
                    current_instructions.append(ir_instr)
        
        if current_function:
            functions.append(IRFunction(
                name=current_function,
                address=0,
                instructions=current_instructions
            

        
        return IRModule(
            architecture=target_arch,
            functions=functions)
        

    
    def _convert_instruction(self, asm_line: str, arch: Architecture) -> Optional[IRInstruction]:
        parts = asm_line.split()
        
        if not parts:
            return None
        
        mnemonic = parts[0].lower()
        
        opcode_map = {
            'add': IROpcode.ADD,
            'sub': IROpcode.SUB,
            'mul': IROpcode.MUL,
            'div': IROpcode.DIV,
            'and': IROpcode.AND,
            'or': IROpcode.OR,
            'xor': IROpcode.XOR,
            'mov': IROpcode.LOAD,
            'push': IROpcode.STORE,
            'pop': IROpcode.LOAD,
            'jmp': IROpcode.BRANCH,
            'call': IROpcode.CALL,
            'ret': IROpcode.RET,
            'nop': IROpcode.NOP
        }
        
        opcode = opcode_map.get(mnemonic)
        
        if not opcode:
            logger.debug(f"未识别的指令: {mnemonic}")
            return None
        
        operands = []
        
        for operand in parts[1:]:
            if ',' in operand:
                ops = operand.split(',')
                for op in ops:
                    op = op.strip()
                    if op.startswith('%'):
                        reg = op[1:]
                        mapped_reg = self.register_mapping.get(arch, {}).get(reg, reg)
                        operands.append(f'%{mapped_reg}')
                    else:
                        operands.append(op)
            else:
                operands.append(operand)
        
        return IRInstruction(
            opcode=opcode,
            operands=operands,
            comment=None)
        

    
    def convert_binary(self, binary_data: bytes, arch: Architecture) -> IRModule:
        try:
            import capstone
            
            md = capstone.Cs(self._get_capstone_arch(arch), self._get_capstone_mode(arch

            md.detail = True
            
            functions = []
            
            for insn in md.disasm(binary_data, 0x1000):
                ir_instr = self._convert_capstone_insn(insn)
                
                if ir_instr:
                    functions.append(IRFunction(
                        name=f'sub_{hex(insn.address)}',
                        address=insn.address,
                        instructions=[ir_instr]
                    

            
            return IRModule(
                architecture=arch,
                functions=functions)
            

        except ImportError:
            logger.warning("capstone 未安装")
            return IRModule(architecture=arch, functions=[])
    
    def _get_capstone_arch(self, arch: Architecture):
        import capstone
        arch_map = {
            Architecture.X86: capstone.CS_ARCH_X86,
            Architecture.X86_64: capstone.CS_ARCH_X86,
            Architecture.ARM: capstone.CS_ARCH_ARM,
            Architecture.ARM64: capstone.CS_ARCH_ARM64,
            Architecture.RISCV: capstone.CS_ARCH_RISCV,
            Architecture.MIPS: capstone.CS_ARCH_MIPS
        }
        return arch_map.get(arch, capstone.CS_ARCH_X86)
    
    def _get_capstone_mode(self, arch: Architecture):
        import capstone
        mode_map = {
            Architecture.X86: capstone.CS_MODE_32,
            Architecture.X86_64: capstone.CS_MODE_64,
            Architecture.ARM: capstone.CS_MODE_ARM,
            Architecture.ARM64: capstone.CS_MODE_ARM,
            Architecture.RISCV: capstone.CS_MODE_RISCV64,
            Architecture.MIPS: capstone.CS_MODE_MIPS32
        }
        return mode_map.get(arch, capstone.CS_MODE_64)
    
    def _convert_capstone_insn(self, insn) -> Optional[IRInstruction]:
        opcode_map = {
            'ADD': IROpcode.ADD,
            'SUB': IROpcode.SUB,
            'MUL': IROpcode.MUL,
            'DIV': IROpcode.DIV,
            'AND': IROpcode.AND,
            'OR': IROpcode.OR,
            'XOR': IROpcode.XOR,
            'MOV': IROpcode.LOAD,
            'PUSH': IROpcode.STORE,
            'POP': IROpcode.LOAD,
            'JMP': IROpcode.BRANCH,
            'CALL': IROpcode.CALL,
            'RET': IROpcode.RET,
            'NOP': IROpcode.NOP
        }
        
        opcode = opcode_map.get(insn.mnemonic.upper(

        
        if not opcode:
            return None
        
        operands = []
        
        for op in insn.operands:
            if op.type == 1:
                reg_name = insn.reg_name(op.reg)
                operands.append(f'%{reg_name}')
            elif op.type == 2:
                operands.append(hex(op.imm

            elif op.type == 3:
                operands.append(f'{hex(op.mem.base)} + {hex(op.mem.disp)}')
        
        return IRInstruction(
            opcode=opcode,
            operands=operands,
            address=insn.address)
        



def convert_to_ir(assembly_code: str, architecture: str = 'x86_64') -> IRModule:
    arch = Architecture[architecture.upper()]
    converter = UnifiedIRConverter()
    return converter.convert(assembly_code, arch)))))))))))))