"""
动态流敏感反汇编模块

功能：
1. 随执行路径纠正静态反汇编错误
2. 用Unicorn追踪跳转目标
3. 提高反汇编准确性

核心组件：
- FlowSensitiveDisassembler: 流敏感反汇编器
- ExecutionTracer: 执行追踪器
- DisasmResult: 反汇编结果
"""

import os
import logging
from typing import Dict, Any, Optional, List, Callable, Tuple, Set
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger(__name__)

try:
    import unicorn
    import capstone
    UNICORN_AVAILABLE = True
    CAPSTONE_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False
    CAPSTONE_AVAILABLE = False
    logger.warning("unicorn or capstone not available")


class Architecture(Enum):
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    PPC = "ppc"


class DisasmMode(Enum):
    STATIC = "static"
    DYNAMIC = "dynamic"
    HYBRID = "hybrid"


@dataclass
class Instruction:
    address: int
    mnemonic: str
    operands: str
    bytes: bytes
    is_conditional: bool = False
    is_indirect: bool = False
    targets: List[int] = field(default_factory=list)


@dataclass
class DisasmResult:
    instructions: List[Instruction]
    functions: Dict[int, List[int]] = field(default_factory=dict)
    unresolved_jumps: List[int] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)


class FlowSensitiveDisassembler:

    def __init__(self, arch: Architecture = Architecture.X86_64):
        self._arch = arch
        self._cs = None
        self._uc = None
        self._memory_map: Dict[int, Tuple[int, bytes]] = {}
        self._trace: List[Tuple[int, int]] = []
        self._resolved_targets: Dict[int, List[int]] = {}
        
        if CAPSTONE_AVAILABLE:
            self._init_capstone()
        
        if UNICORN_AVAILABLE:
            self._init_unicorn()

    def _init_capstone(self):
        if self._arch == Architecture.X86:
            self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_32)
        elif self._arch == Architecture.X86_64:
            self._cs = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
        elif self._arch == Architecture.ARM:
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM, capstone.CS_MODE_ARM)
        elif self._arch == Architecture.ARM64:
            self._cs = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_ARM64)
        
        if self._cs:
            self._cs.detail = True

    def _init_unicorn(self):
        if self._arch == Architecture.X86:
            self._uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_32)
        elif self._arch == Architecture.X86_64:
            self._uc = unicorn.Uc(unicorn.UC_ARCH_X86, unicorn.UC_MODE_64)
        elif self._arch == Architecture.ARM:
            self._uc = unicorn.Uc(unicorn.UC_ARCH_ARM, unicorn.UC_MODE_ARM)
        elif self._arch == Architecture.ARM64:
            self._uc = unicorn.Uc(unicorn.UC_ARCH_ARM64, unicorn.UC_MODE_ARM64)

    def map_memory(self, address: int, size: int, data: Optional[bytes] = None):
        if not self._uc:
            return
        
        if data is None:
            data = b'\x00' * size
        
        self._uc.mem_map(address, size, unicorn.UC_PROT_ALL)
        self._uc.mem_write(address, data)
        self._memory_map[address] = (size, data)

    def set_register(self, reg: str, value: int):
        if not self._uc:
            return
        
        reg_map = {
            'rax': unicorn.x86_const.UC_X86_REG_RAX,
            'rbx': unicorn.x86_const.UC_X86_REG_RBX,
            'rcx': unicorn.x86_const.UC_X86_REG_RCX,
            'rdx': unicorn.x86_const.UC_X86_REG_RDX,
            'rsp': unicorn.x86_const.UC_X86_REG_RSP,
            'rbp': unicorn.x86_const.UC_X86_REG_RBP,
            'rip': unicorn.x86_const.UC_X86_REG_RIP,
        }
        
        if reg.lower() in reg_map:
            self._uc.reg_write(reg_map[reg.lower()], value)

    def _trace_instruction(self, uc, address, size, user_data):
        instruction = uc.mem_read(address, size)
        self._trace.append((address, size

        
        if self._cs:
            for insn in self._cs.disasm(instruction, address):
                if self._is_control_flow(insn):
                    targets = self._get_targets(uc, insn)
                    if address not in self._resolved_targets:
                        self._resolved_targets[address] = []
                    self._resolved_targets[address].extend(targets)

    def _is_control_flow(self, insn) -> bool:
        cf_groups = (
            capstone.CS_GRP_CALL,
            capstone.CS_GRP_JUMP,
            capstone.CS_GRP_RET,
            capstone.CS_GRP_IRET
        
        return any(insn.group(g) for g in cf_groups)

    def _get_targets(self, uc, insn) -> List[int]:
        targets = []
        
        if insn.id in (capstone.x86.X86_INS_JMP, capstone.x86.X86_INS_JMPD):
            if insn.op_str.startswith('0x'):
                try:
                    targets.append(int(insn.op_str, 16

                except ValueError:
                    pass
            elif insn.op_str.startswith('*'):
                try:
                    addr = self._evaluate_expression(uc, insn.op_str[1:])
                    if addr:
                        targets.append(addr)
                except Exception:
                    pass
        
        elif insn.id in (capstone.x86.X86_INS_CALL, capstone.x86.X86_INS_CALLD):
            if insn.op_str.startswith('0x'):
                try:
                    targets.append(int(insn.op_str, 16

                except ValueError:
                    pass
        
        elif insn.id in (capstone.x86.X86_INS_JZ, capstone.x86.X86_INS_JNZ)
                        capstone.x86.X86_INS_JE, capstone.x86.X86_INS_JNE,
                        capstone.x86.X86_INS_JS, capstone.x86.X86_INS_JNS,
                        capstone.x86.X86_INS_JB, capstone.x86.X86_INS_JNB,
                        capstone.x86.X86_INS_JL, capstone.x86.X86_INS_JGE,
                        capstone.x86.X86_INS_JLE, capstone.x86.X86_INS_JG):
            if insn.op_str.startswith('0x'):
                try:
                    targets.append(int(insn.op_str, 16

                except ValueError:
                    pass
            targets.append(insn.address + insn.size)
        
        return targets

    def _evaluate_expression(self, uc, expr: str) -> Optional[int]:
        try:
            expr = expr.replace('rax', str(uc.reg_read(unicorn.x86_const.UC_X86_REG_RAX

            expr = expr.replace('rbx', str(uc.reg_read(unicorn.x86_const.UC_X86_REG_RBX

            expr = expr.replace('rcx', str(uc.reg_read(unicorn.x86_const.UC_X86_REG_RCX

            expr = expr.replace('rdx', str(uc.reg_read(unicorn.x86_const.UC_X86_REG_RDX

            expr = expr.replace('rsi', str(uc.reg_read(unicorn.x86_const.UC_X86_REG_RSI

            expr = expr.replace('rdi', str(uc.reg_read(unicorn.x86_const.UC_X86_REG_RDI

            expr = expr.replace('[', '('
            expr = expr.replace(']', ')'
            return eval(expr)
        except Exception:
            return None

    def run(self, start_address: int, end_address: Optional[int] = None, max_instructions: int = 10000):
        if not self._uc:
            logger.error("Unicorn not available")
            return
        
        self._uc.hook_add(unicorn.UC_HOOK_CODE, self._trace_instruction)
        
        try:
            if end_address:
                self._uc.emu_start(start_address, end_address, count=max_instructions)
            else:
                self._uc.emu_start(start_address, 0, count=max_instructions)
        except unicorn.UcError as e:
            logger.warning(f"Emulation stopped: {e}")

    def disassemble(self, data: bytes, address: int = 0, mode: DisasmMode = DisasmMode.HYBRID) -> DisasmResult:
        instructions = []
        unresolved_jumps = []
        warnings = []
        
        if mode in (DisasmMode.STATIC, DisasmMode.HYBRID):
            static_result = self._static_disassemble(data, address)
            instructions.extend(static_result.instructions)
            unresolved_jumps.extend(static_result.unresolved_jumps)
        
        if mode in (DisasmMode.DYNAMIC, DisasmMode.HYBRID) and UNICORN_AVAILABLE:
            self._run_dynamic_analysis(data, address)
            instructions = self._merge_results(instructions)
        
        return DisasmResult(
            instructions=instructions,
            unresolved_jumps=unresolved_jumps,
            warnings=warnings)
        


    def _static_disassemble(self, data: bytes, address: int) -> DisasmResult:
        instructions = []
        unresolved_jumps = []
        
        if not self._cs:
            return DisasmResult(instructions=[], unresolved_jumps=[])
        
        for insn in self._cs.disasm(data, address):
            is_conditional = any([)
                insn.group(capstone.CS_GRP_JUMP) and not insn.group(capstone.CS_GRP_CALL),
                insn.id in (capstone.x86.X86_INS_JZ, capstone.x86.X86_INS_JNZ)
                           capstone.x86.X86_INS_JE, capstone.x86.X86_INS_JNE
            ]
            
            is_indirect = insn.op_str.startswith('*') or \
                        ('[' in insn.op_str and '+' in insn.op_str)
            
            instruction = Instruction()
                address=insn.address,
                mnemonic=insn.mnemonic,
                operands=insn.op_str,
                bytes=insn.bytes,
                is_conditional=is_conditional,
                is_indirect=is_indirect
            
            
            if is_indirect and insn.group(capstone.CS_GRP_JUMP):
                unresolved_jumps.append(insn.address)
            
            instructions.append(instruction)
        
        return DisasmResult(
            instructions=instructions,
            unresolved_jumps=unresolved_jumps)
        


    def _run_dynamic_analysis(self, data: bytes, address: int):
        page_size = 0x1000
        aligned_addr = address & ~(page_size - 1)
        offset = address - aligned_addr
        
        self.map_memory(aligned_addr, page_size * 2, data)
        self.set_register('rip', address)
        self.set_register('rsp', 0x7fffffff000)
        
        self.run(address, max_instructions=1000)

    def _merge_results(self, instructions: List[Instruction]) -> List[Instruction]:
        for insn in instructions:
            if insn.address in self._resolved_targets:
                insn.targets = self._resolved_targets[insn.address]
                if insn.is_indirect:
                    logger.info(f"Resolved indirect jump at 0x{insn.address:x}: {insn.targets}")
        
        return instructions

    def get_trace(self) -> List[Tuple[int, int]]:
        return self._trace

    def get_resolved_targets(self) -> Dict[int, List[int]]:
        return self._resolved_targets


def create_disassembler(arch: str = "x86_64") -> FlowSensitiveDisassembler:
    arch_enum = Architecture[arch.upper()]
    return FlowSensitiveDisassembler(arch_enum)


def disassemble(data: bytes, address: int = 0, arch: str = "x86_64", mode: str = "hybrid") -> DisasmResult:
    disassembler = create_disassembler(arch)
    mode_enum = DisasmMode[mode.upper()]
    return disassembler.disassemble(data, address, mode_enum)))))))))))))))))))))))))