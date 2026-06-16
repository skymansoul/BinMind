"""
多类型 Gadget 自动发现与组合

支持 ROP、JOP、COP、SROP、DOP 的 Gadget 自动分类与链合成。
提供模板编程接口："把 X 赋值给 RDI，然后调用 system"，引擎自动搜索并组合序列。
"""

import logging
import re
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any, Tuple, Set, Union, Callable
from enum import Enum
from pathlib import Path

import capstone as cs

logger = logging.getLogger(__name__)


class GadgetType(Enum):
    """Gadget类型枚举"""
    ROP = "rop"           # Return-Oriented Programming
    JOP = "jop"           # Jump-Oriented Programming
    COP = "cop"           # Call-Oriented Programming
    SROP = "srop"         # Sigreturn-Oriented Programming
    DOP = "dop"           # Data-Oriented Programming
    XCHG = "xchg"         # Register exchange
    MOV = "mov"           # Register move
    ADD = "add"           # Addition
    SUB = "sub"           # Subtraction
    POP = "pop"           # Pop from stack
    PUSH = "push"         # Push to stack
    RET = "ret"           # Return
    SYSCALL = "syscall"   # System call
    INT = "int"           # Interrupt
    LEAVE = "leave"       # Leave frame
    NOP = "nop"           # No operation


class Architecture(Enum):
    """架构枚举"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"


@dataclass
class Gadget:
    """Gadget数据类"""
    address: int
    type: GadgetType
    instructions: List[str]
    bytes: bytes
    registers_read: Set[str]
    registers_written: Set[str]
    stack_effect: int  # 栈变化量 (positive = stack grows, negative = shrinks)
    description: str = ""
    
    def __repr__(self):
        return f"Gadget(0x{self.address:x}, {self.type.name}, '{self.description}')"


@dataclass
class GadgetChain:
    """Gadget链数据类"""
    gadgets: List[Gadget]
    purpose: str
    expected_effect: str
    chain_bytes: bytes = b""
    success_probability: float = 0.0


class GadgetPattern(ABC):
    """Gadget模式基类"""
    
    @abstractmethod
    def match(self, instructions: List[str]) -> bool:
        """匹配指令序列"""
        pass
    
    @abstractmethod
    def get_gadget_type(self) -> GadgetType:
        """获取Gadget类型"""
        pass


class PopRdiRetPattern(GadgetPattern):
    """pop rdi; ret 模式"""
    
    def match(self, instructions: List[str]) -> bool:
        return len(instructions) >= 2 and \
               'pop rdi' in instructions[-2].lower() and \
               'ret' in instructions[-1].lower()
    
    def get_gadget_type(self) -> GadgetType:
        return GadgetType.ROP


class PopRsiRetPattern(GadgetPattern):
    """pop rsi; ret 模式"""
    
    def match(self, instructions: List[str]) -> bool:
        return len(instructions) >= 2 and \
               'pop rsi' in instructions[-2].lower() and \
               'ret' in instructions[-1].lower()
    
    def get_gadget_type(self) -> GadgetType:
        return GadgetType.ROP


class SyscallPattern(GadgetPattern):
    """syscall 模式"""
    
    def match(self, instructions: List[str]) -> bool:
        return any('syscall' in instr.lower() for instr in instructions)
    
    def get_gadget_type(self) -> GadgetType:
        return GadgetType.SYSCALL


class LeaveRetPattern(GadgetPattern):
    """leave; ret 模式"""
    
    def match(self, instructions: List[str]) -> bool:
        return len(instructions) >= 2 and \
               'leave' in instructions[-2].lower() and \
               'ret' in instructions[-1].lower()
    
    def get_gadget_type(self) -> GadgetType:
        return GadgetType.ROP


class XchgRaxRspPattern(GadgetPattern):
    """xchg rax, rsp; ret 模式"""
    
    def match(self, instructions: List[str]) -> bool:
        return len(instructions) >= 2 and \
               ('xchg rax, rsp' in instructions[-2].lower() or 'xchg rsp, rax' in instructions[-2].lower()) and \
               'ret' in instructions[-1].lower()
    
    def get_gadget_type(self) -> GadgetType:
        return GadgetType.XCHG


class GadgetScanner:
    """Gadget扫描器"""
    
    def __init__(self, architecture: Architecture = Architecture.X86_64):
        """
        初始化Gadget扫描器
        
        Args:
            architecture: 目标架构
        """
        self.architecture = architecture
        self.md = self._create_disassembler()
        self.patterns: List[GadgetPattern] = [
            PopRdiRetPattern(),
            PopRsiRetPattern(),
            SyscallPattern(),
            LeaveRetPattern(),
            XchgRaxRspPattern(),
        ]
    
    def _create_disassembler(self) -> cs.Cs:
        """创建反汇编器"""
        if self.architecture == Architecture.X86_64:
            return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_64)
        elif self.architecture == Architecture.X86:
            return cs.Cs(cs.CS_ARCH_X86, cs.CS_MODE_32)
        elif self.architecture == Architecture.ARM:
            return cs.Cs(cs.CS_ARCH_ARM, cs.CS_MODE_ARM)
        elif self.architecture == Architecture.ARM64:
            return cs.Cs(cs.CS_ARCH_ARM64, cs.CS_MODE_ARM)
        else:
            raise ValueError(f"不支持的架构: {self.architecture}")
    
    def scan_memory(self, memory: bytes, base_address: int = 0, max_gadget_length: int = 15) -> List[Gadget]:
        """
        扫描内存中的Gadget
        
        Args:
            memory: 内存数据
            base_address: 基地址
            max_gadget_length: 最大Gadget长度（字节）
            
        Returns:
            Gadget列表
        """
        gadgets = []
        
        for offset in range(len(memory)):
            if offset + 1 > len(memory):
                break
            
            end_offset = min(offset + max_gadget_length, len(memory))
            gadget_bytes = memory[offset:end_offset]
            
            try:
                instructions = []
                regs_read = set()
                regs_written = set()
                stack_effect = 0
                
                for instr in self.md.disasm(gadget_bytes, base_address + offset):
                    instructions.append(f"{instr.mnemonic} {instr.op_str}")
                    
                    # 分析寄存器影响
                    self._analyze_instruction(instr, regs_read, regs_written, stack_effect)
                
                if instructions and instructions[-1].startswith('ret'):
                    gadget_type = self._classify_gadget(instructions)
                    description = self._generate_description(gadget_type, instructions)
                    
                    gadgets.append(Gadget(
                        address=base_address + offset,
                        type=gadget_type,
                        instructions=instructions,
                        bytes=gadget_bytes[:len(b''.join(i.bytes for i in self.md.disasm(gadget_bytes, 0)))],
                        registers_read=regs_read,
                        registers_written=regs_written,
                        stack_effect=stack_effect,
                        description=description
                    ))
            except Exception:
                continue
        
        logger.info(f"扫描完成，发现 {len(gadgets)} 个Gadget")
        return gadgets
    
    def _analyze_instruction(self, instr, regs_read: Set[str], regs_written: Set[str], stack_effect: int):
        """分析指令对寄存器和栈的影响"""
        mnemonic = instr.mnemonic.lower()
        
        if mnemonic == 'pop':
            regs_written.add(instr.op_str.split(',')[0].strip())
            stack_effect += 8  # x86_64
        elif mnemonic == 'push':
            regs_read.add(instr.op_str.split(',')[0].strip())
            stack_effect -= 8
        elif mnemonic in ('mov', 'add', 'sub', 'xor', 'and', 'or'):
            dest = instr.op_str.split(',')[0].strip()
            src = instr.op_str.split(',')[1].strip() if ',' in instr.op_str else ''
            regs_written.add(dest)
            if src and src.isalpha():
                regs_read.add(src)
    
    def _classify_gadget(self, instructions: List[str]) -> GadgetType:
        """分类Gadget类型"""
        for pattern in self.patterns:
            if pattern.match(instructions):
                return pattern.get_gadget_type()
        
        if any('ret' in instr.lower() for instr in instructions):
            return GadgetType.ROP
        if any('jmp' in instr.lower() for instr in instructions):
            return GadgetType.JOP
        if any('call' in instr.lower() for instr in instructions):
            return GadgetType.COP
        
        return GadgetType.ROP
    
    def _generate_description(self, gadget_type: GadgetType, instructions: List[str]) -> str:
        """生成Gadget描述"""
        if gadget_type == GadgetType.ROP:
            if len(instructions) >= 2:
                return f"{instructions[-2]}; {instructions[-1]}"
        return "; ".join(instructions)


class GadgetComposer:
    """
    Gadget组合器
    
    提供模板编程接口，自动搜索并组合Gadget序列。
    """
    
    def __init__(self, gadgets: List[Gadget]):
        """
        初始化组合器
        
        Args:
            gadgets: Gadget列表
        """
        self.gadgets = gadgets
        self.gadget_index: Dict[str, List[Gadget]] = self._build_index()
    
    def _build_index(self) -> Dict[str, List[Gadget]]:
        """构建Gadget索引"""
        index = {}
        
        for gadget in self.gadgets:
            # 按类型索引
            type_key = gadget.type.name.lower()
            if type_key not in index:
                index[type_key] = []
            index[type_key].append(gadget)
            
            # 按描述关键字索引
            for word in gadget.description.split():
                if word not in index:
                    index[word] = []
                index[word].append(gadget)
        
        return index
    
    def find_gadget(self, **kwargs) -> Optional[Gadget]:
        """
        查找满足条件的Gadget
        
        Args:
            kwargs: 搜索条件
                - type: Gadget类型
                - description_contains: 描述包含的关键字
                - registers_written: 需要写入的寄存器
                - registers_read: 需要读取的寄存器
        
        Returns:
            匹配的Gadget，或None
        """
        candidates = self.gadgets
        
        if 'type' in kwargs:
            candidates = [g for g in candidates if g.type == kwargs['type']]
        
        if 'description_contains' in kwargs:
            keyword = kwargs['description_contains']
            candidates = [g for g in candidates if keyword.lower() in g.description.lower()]
        
        if 'registers_written' in kwargs:
            required_writes = set(kwargs['registers_written'])
            candidates = [g for g in candidates if required_writes.issubset(g.registers_written)]
        
        if 'registers_read' in kwargs:
            required_reads = set(kwargs['registers_read'])
            candidates = [g for g in candidates if required_reads.issubset(g.registers_read)]
        
        return candidates[0] if candidates else None
    
    def compose_chain(self, template: str) -> Optional[GadgetChain]:
        """
        根据模板组合Gadget链
        
        Args:
            template: 模板字符串，如 "把 X 赋值给 RDI，然后调用 system"
        
        Returns:
            GadgetChain对象，或None
        """
        logger.info(f"尝试根据模板组合Gadget链: {template}")
        
        chain = []
        expected_effect = template
        
        # 解析模板并构建链
        if '赋值给 RDI' in template or 'mov rdi' in template.lower():
            pop_rdi = self.find_gadget(type=GadgetType.ROP, description_contains='pop rdi')
            if pop_rdi:
                chain.append(pop_rdi)
        
        if '调用 system' in template or 'call system' in template.lower():
            # 查找包含call的gadget或准备syscall
            call_gadget = self.find_gadget(type=GadgetType.COP, description_contains='call')
            if call_gadget:
                chain.append(call_gadget)
            else:
                # 尝试查找syscall gadget
                syscall_gadget = self.find_gadget(type=GadgetType.SYSCALL)
                if syscall_gadget:
                    chain.append(syscall_gadget)
        
        if '赋值给 RSI' in template or 'mov rsi' in template.lower():
            pop_rsi = self.find_gadget(type=GadgetType.ROP, description_contains='pop rsi')
            if pop_rsi:
                chain.append(pop_rsi)
        
        if '赋值给 RDX' in template or 'mov rdx' in template.lower():
            pop_rdx = self.find_gadget(type=GadgetType.ROP, description_contains='pop rdx')
            if pop_rdx:
                chain.append(pop_rdx)
        
        if chain:
            chain_bytes = self._assemble_chain(chain)
            return GadgetChain(
                gadgets=chain,
                purpose=template,
                expected_effect=expected_effect,
                chain_bytes=chain_bytes,
                success_probability=self._calculate_probability(chain)
            )
        
        logger.warning(f"无法根据模板找到足够的Gadget: {template}")
        return None
    
    def _assemble_chain(self, gadgets: List[Gadget]) -> bytes:
        """组装Gadget链为字节序列"""
        chain_bytes = b""
        
        for gadget in gadgets:
            # 添加gadget地址
            chain_bytes += gadget.address.to_bytes(8, byteorder='little')
        
        return chain_bytes
    
    def _calculate_probability(self, gadgets: List[Gadget]) -> float:
        """计算链成功概率"""
        if not gadgets:
            return 0.0
        
        # 每个gadget贡献一定的概率
        base_prob = 0.95  # 假设每个gadget基础成功率
        return base_prob ** len(gadgets)
    
    def find_srop_chain(self, sigreturn_address: int) -> Optional[GadgetChain]:
        """
        构建SROP链
        
        Args:
            sigreturn_address: sigreturn系统调用号对应的地址
        
        Returns:
            SROP GadgetChain
        """
        # 查找xchg rax, rsp; ret gadget
        xchg_gadget = self.find_gadget(type=GadgetType.XCHG, description_contains='xchg')
        syscall_gadget = self.find_gadget(type=GadgetType.SYSCALL)
        
        if xchg_gadget and syscall_gadget:
            chain = [xchg_gadget, syscall_gadget]
            chain_bytes = self._assemble_chain(chain)
            
            return GadgetChain(
                gadgets=chain,
                purpose="SROP链",
                expected_effect="通过sigreturn控制寄存器",
                chain_bytes=chain_bytes,
                success_probability=self._calculate_probability(chain)
            )
        
        return None
    
    def generate_shellcode_chain(self, shellcode_address: int) -> Optional[GadgetChain]:
        """
        生成跳转到shellcode的Gadget链
        
        Args:
            shellcode_address: shellcode地址
        
        Returns:
            GadgetChain对象
        """
        # 查找jmp rax或类似的gadget
        jmp_rax = self.find_gadget(description_contains='jmp rax')
        
        if jmp_rax:
            return GadgetChain(
                gadgets=[jmp_rax],
                purpose=f"跳转到shellcode 0x{shellcode_address:x}",
                expected_effect="执行shellcode",
                chain_bytes=shellcode_address.to_bytes(8, byteorder='little') + jmp_rax.address.to_bytes(8, byteorder='little'),
                success_probability=0.9
            )
        
        # 尝试查找pop rax; ret + jmp rax组合
        pop_rax = self.find_gadget(description_contains='pop rax')
        jmp_rax = self.find_gadget(description_contains='jmp')
        
        if pop_rax and jmp_rax:
            chain = [pop_rax, jmp_rax]
            chain_bytes = shellcode_address.to_bytes(8, byteorder='little') + self._assemble_chain(chain)
            
            return GadgetChain(
                gadgets=chain,
                purpose=f"设置RAX并跳转到shellcode 0x{shellcode_address:x}",
                expected_effect="执行shellcode",
                chain_bytes=chain_bytes,
                success_probability=self._calculate_probability(chain)
            )
        
        return None


class GadgetComposerPlugin:
    """Gadget组合器插件"""
    
    NAME = "gadget_composer"
    DESCRIPTION = "多类型Gadget自动发现与组合"
    
    @classmethod
    def get_metadata(cls):
        """获取插件元数据"""
        return {
            'name': cls.NAME,
            'description': cls.DESCRIPTION,
            'version': '1.0.0',
            'dependencies': ['capstone'],
            'supported_platforms': ['linux', 'windows', 'macos']
        }


def scan_gadgets(binary_data: bytes, base_address: int = 0, architecture: str = 'x86_64') -> List[Gadget]:
    """
    扫描二进制数据中的Gadget
    
    Args:
        binary_data: 二进制数据
        base_address: 基地址
        architecture: 架构
        
    Returns:
        Gadget列表
    """
    arch_enum = Architecture(architecture.lower())
    scanner = GadgetScanner(arch_enum)
    return scanner.scan_memory(binary_data, base_address)


def create_gadget_chain(gadgets: List[Gadget], template: str) -> Optional[GadgetChain]:
    """
    根据模板创建Gadget链
    
    Args:
        gadgets: Gadget列表
        template: 模板字符串
        
    Returns:
        GadgetChain对象
    """
    composer = GadgetComposer(gadgets)
    return composer.compose_chain(template)