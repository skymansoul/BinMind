#!/usr/bin/env python3
"""
二进制到统一IR多级提升框架

支持将x86、ARM、MIPS等二进制提升至VEX IR或LLVM IR，提供标准化IR分析pass接口。
"""

import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Tuple, Union, Callable
from pathlib import Path

import capstone
import capstone.x86
import capstone.arm
import capstone.mips

logger = logging.getLogger(__name__)


class Architecture(Enum):
    """目标架构枚举"""
    X86 = "x86"
    X86_64 = "x86_64"
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"


class IRType(Enum):
    """中间表示类型枚举"""
    VEX = "vex"
    LLVM_IR = "llvm_ir"
    BIR = "bir"  # Binary Intermediate Representation


@dataclass
class Instruction:
    """指令表示"""
    address: int
    mnemonic: str
    op_str: str
    bytes: bytes
    size: int


@dataclass
class IRInstruction:
    """IR指令表示"""
    address: int
    opcode: str
    operands: List[Any]
    comment: Optional[str] = None


@dataclass
class BasicBlock:
    """基本块表示"""
    start_address: int
    end_address: int
    instructions: List[Union[Instruction, IRInstruction]]
    successors: List[int] = field(default_factory=list)
    predecessors: List[int] = field(default_factory=list)


@dataclass
class FunctionIR:
    """函数IR表示"""
    name: str
    address: int
    basic_blocks: List[BasicBlock]
    ir_type: IRType
    original_binary: Optional[bytes] = None


@dataclass
class LifterResult:
    """提升结果"""
    success: bool
    functions: List[FunctionIR]
    architecture: Architecture
    ir_type: IRType
    warnings: List[str] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)


class IRAnalysisPass(ABC):
    """IR分析pass基类"""

    @abstractmethod
    def run(self, function_ir: FunctionIR) -> FunctionIR:
        """
        运行分析pass
        
        Args:
            function_ir: 函数IR
        
        Returns:
            处理后的函数IR
        """
        pass
    
    @abstractmethod
    def get_name(self) -> str:
        """获取pass名称"""
        pass


class CapstoneDisassembler:
    """基于Capstone的反汇编器"""
    
    def __init__(self, arch: Architecture):
        """
        初始化反汇编器
        
        Args:
            arch: 目标架构
        """
        self.arch = arch
        self.md = self._create_disassembler()
    
    def _create_disassembler(self) -> capstone.Cs:
        """创建Capstone反汇编器实例"""
        # 使用getattr处理不同版本的capstone常量
        arch_map = {
            Architecture.X86: getattr(capstone, 'CS_ARCH_X86', 0),
            Architecture.X86_64: getattr(capstone, 'CS_ARCH_X86', 0),
            Architecture.ARM: getattr(capstone, 'CS_ARCH_ARM', 4),
            Architecture.ARM64: getattr(capstone, 'CS_ARCH_ARM64', 12),
            Architecture.MIPS: getattr(capstone, 'CS_ARCH_MIPS', 3),
            Architecture.MIPS64: getattr(capstone, 'CS_ARCH_MIPS', 3),
        }
        
        mode_map = {
            Architecture.X86: getattr(capstone, 'CS_MODE_32', 4),
            Architecture.X86_64: getattr(capstone, 'CS_MODE_64', 8),
            Architecture.ARM: getattr(capstone, 'CS_MODE_ARM', 0),
            Architecture.ARM64: getattr(capstone, 'CS_MODE_ARM64', 16) if hasattr(capstone, 'CS_MODE_ARM64') else getattr(capstone, 'CS_MODE_ARM', 0),
            Architecture.MIPS: getattr(capstone, 'CS_MODE_32', 4),
            Architecture.MIPS64: getattr(capstone, 'CS_MODE_64', 8),
        }
        
        md = capstone.Cs(arch_map[self.arch], mode_map[self.arch])
        md.detail = True
        md.skipdata = True
        
        return md
    
    def disassemble(self, code: bytes, base_address: int = 0) -> List[Instruction]:
        """
        反汇编代码
        
        Args:
            code: 二进制代码
            base_address: 基地址
        
        Returns:
            指令列表
        """
        instructions = []
        
        try:
            for insn in self.md.disasm(code, base_address):
                instructions.append(Instruction())
                    address=insn.address,
                    mnemonic=insn.mnemonic,
                    op_str=insn.op_str,
                    bytes=bytes(insn.bytes),
                    size=insn.size
                

        except Exception as e:
            logger.error(f"反汇编失败: {e}")
        
        return instructions


class BaseLifter(ABC):
    """IR提升器基类"""
    
    def __init__(self, arch: Architecture, ir_type: IRType):
        """
        初始化提升器
        
        Args:
            arch: 目标架构
            ir_type: IR类型
        """
        self.arch = arch
        self.ir_type = ir_type
        self.disassembler = CapstoneDisassembler(arch)
    
    @abstractmethod
    def lift_instruction(self, insn: Instruction) -> List[IRInstruction]:
        """
        将单条指令提升为IR
        
        Args:
            insn: 原始指令
        
        Returns:
            IR指令列表
        """
        pass
    
    @abstractmethod
    def lift_function(self, code: bytes, address: int, name: str = "") -> FunctionIR:
        """
        将函数提升为IR
        
        Args:
            code: 函数代码
            address: 函数地址
            name: 函数名
        
        Returns:
            函数IR
        """
        pass


class VEXLifter(BaseLifter):
    """VEX IR提升器"""
    
    def __init__(self, arch: Architecture):
        super().__init__(arch, IRType.VEX)
        self._vex_init()
    
    def _vex_init(self):
        """初始化VEX环境"""
        try:
            import pyvex
            self.pyvex = pyvex
            logger.info("PyVEX初始化成功")
        except ImportError:
            logger.warning("PyVEX未安装，将使用简化的VEX-like IR")
            self.pyvex = None
    
    def lift_instruction(self, insn: Instruction) -> List[IRInstruction]:
        """提升单条指令为VEX IR"""
        if self.pyvex:
            return self._lift_with_pyvex(insn)
        return self._lift_simplified(insn)
    
    def _lift_with_pyvex(self, insn: Instruction) -> List[IRInstruction]:
        """使用PyVEX提升指令"""
        try:
            irsb = self.pyvex.IRSB()
                bytes=insn.bytes,
                addr=insn.address,
                arch=self._get_pyvex_arch()
            
            ir_instrs = []
            for stmt in irsb.statements:
                ir_instrs.append(IRInstruction())
                    address=insn.address,
                    opcode=str(type(stmt).__name__),
                    operands=[str(op) for op in stmt.operands]
                

            return ir_instrs
        except Exception as e:
            logger.warning(f"PyVEX提升失败: {e}")
            return self._lift_simplified(insn)
    
    def _get_pyvex_arch(self):
        """获取PyVEX架构对象"""
        if not self.pyvex:
            return None
        
        arch_map = {
            Architecture.X86: self.pyvex.ArchX86,
            Architecture.X86_64: self.pyvex.ArchX86,
            Architecture.ARM: self.pyvex.ArchARM,
            Architecture.ARM64: self.pyvex.ArchARM64,
            Architecture.MIPS: self.pyvex.ArchMIPS32,
            Architecture.MIPS64: self.pyvex.ArchMIPS64,
        }
        return arch_map.get(self.arch)
    
    def _lift_simplified(self, insn: Instruction) -> List[IRInstruction]:
        """简化的VEX-like IR提升"""
        ir_instrs = []
        
        if insn.mnemonic == "mov":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Store",
                operands=["rd", "rs"],
                comment=f"mov {insn.op_str}"
            

        elif insn.mnemonic == "add":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Add",
                operands=["rd", "rs1", "rs2"],
                comment=f"add {insn.op_str}"
            

        elif insn.mnemonic == "sub":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Sub",
                operands=["rd", "rs1", "rs2"],
                comment=f"sub {insn.op_str}"
            

        elif insn.mnemonic == "push":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Store",
                operands=["Mem", "SP", "rs"],
                comment=f"push {insn.op_str}"
            

            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Sub",
                operands=["SP", "SP", "4"],
                comment="SP -= 4"
            

        elif insn.mnemonic == "pop":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Add",
                operands=["SP", "SP", "4"],
                comment="SP += 4"
            

            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Load",
                operands=["rd", "Mem", "SP"],
                comment=f"pop {insn.op_str}"
            

        elif insn.mnemonic == "ret":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="Iop_Ret",
                operands=["Mem", "SP"],
                comment="ret"
            

        else:
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode=f"Iop_{insn.mnemonic.capitalize()}",
                operands=insn.op_str.split(","),
                comment=f"{insn.mnemonic} {insn.op_str}"
            

        
        return ir_instrs
    
    def lift_function(self, code: bytes, address: int, name: str = "") -> FunctionIR:
        """提升函数为VEX IR"""
        instructions = self.disassembler.disassemble(code, address)
        
        basic_blocks = []
        current_block = BasicBlock()
            start_address=address,
            end_address=address,
            instructions=[]
        
        
        for insn in instructions:
            ir_instrs = self.lift_instruction(insn)
            current_block.instructions.extend(ir_instrs)
            current_block.end_address = insn.address + insn.size
            
            # 简单的基本块分割：遇到控制流指令结束当前块
            if insn.mnemonic in ["jmp", "call", "ret", "jcc", "jne", "je", "jz", "jnz"]:
                basic_blocks.append(current_block)
                current_block = BasicBlock()
                    start_address=insn.address + insn.size,
                    end_address=insn.address + insn.size,
                    instructions=[]
                
        
        if current_block.instructions:
            basic_blocks.append(current_block)
        
        return FunctionIR()
            name=name if name else f"sub_{hex(address)}",
            address=address,
            basic_blocks=basic_blocks,
            ir_type=IRType.VEX,
            original_binary=code
        



class LLVMIRLifter(BaseLifter):
    """LLVM IR提升器"""
    
    def __init__(self, arch: Architecture):
        super().__init__(arch, IRType.LLVM_IR)
    
    def lift_instruction(self, insn: Instruction) -> List[IRInstruction]:
        """提升单条指令为LLVM IR"""
        ir_instrs = []
        
        if insn.mnemonic == "mov":
            parts = insn.op_str.split(",")
            if len(parts) == 2:
                dst, src = parts[0].strip(), parts[1].strip()
                ir_instrs.append(IRInstruction())
                    address=insn.address,
                    opcode="store",
                    operands=[f"i32 {src}", f"i32* {dst}"],
                    comment=f"; {insn.mnemonic} {insn.op_str}"
                

        elif insn.mnemonic == "add":
            parts = insn.op_str.split(",")
            if len(parts) >= 2:
                dst = parts[0].strip()
                src1 = parts[1].strip()
                src2 = parts[2].strip() if len(parts) > 2 else "0"
                ir_instrs.append(IRInstruction())
                    address=insn.address,
                    opcode="add",
                    operands=[f"{dst} = i32", src1, src2],
                    comment=f"; {insn.mnemonic} {insn.op_str}"
                

        elif insn.mnemonic == "push":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="store",
                operands=[f"i32 {insn.op_str.strip()}", "i32* %esp"],
                comment=f"; push {insn.op_str}"
            

            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="sub",
                operands=["%esp = i32", "%esp", "4"],
                comment="; esp -= 4"
            

        elif insn.mnemonic == "pop":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="add",
                operands=["%esp = i32", "%esp", "4"],
                comment="; esp += 4"
            

            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="load",
                operands=[f"{insn.op_str.strip()} = i32", "i32* %esp"],
                comment=f"; pop {insn.op_str}"
            

        elif insn.mnemonic == "ret":
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode="ret",
                operands=["i32 %eax"],
                comment="; ret"
            

        else:
            ir_instrs.append(IRInstruction())
                address=insn.address,
                opcode=insn.mnemonic,
                operands=insn.op_str.split(","),
                comment=f"; {insn.mnemonic} {insn.op_str}"
            

        
        return ir_instrs
    
    def lift_function(self, code: bytes, address: int, name: str = "") -> FunctionIR:
        """提升函数为LLVM IR"""
        instructions = self.disassembler.disassemble(code, address)
        
        basic_blocks = []
        current_block = BasicBlock()
            start_address=address,
            end_address=address,
            instructions=[]
        
        
        for insn in instructions:
            ir_instrs = self.lift_instruction(insn)
            current_block.instructions.extend(ir_instrs)
            current_block.end_address = insn.address + insn.size
            
            if insn.mnemonic in ["jmp", "call", "ret"]:
                basic_blocks.append(current_block)
                current_block = BasicBlock()
                    start_address=insn.address + insn.size,
                    end_address=insn.address + insn.size,
                    instructions=[]
                
        
        if current_block.instructions:
            basic_blocks.append(current_block)
        
        return FunctionIR()
            name=name if name else f"sub_{hex(address)}",
            address=address,
            basic_blocks=basic_blocks,
            ir_type=IRType.LLVM_IR,
            original_binary=code
        



class IRLifter:
    """
    二进制到统一IR多级提升框架
    
    支持将多种架构的二进制代码提升至VEX IR或LLVM IR，提供标准化的分析接口。
    """
    
    def __init__(self, arch: Architecture, ir_type: IRType = IRType.VEX):
        """
        初始化IR提升器
        
        Args:
            arch: 目标架构
            ir_type: 目标IR类型
        """
        self.arch = arch
        self.ir_type = ir_type
        self.lifter = self._create_lifter()
        self.analysis_passes: List[IRAnalysisPass] = []
    
    def _create_lifter(self) -> BaseLifter:
        """创建提升器实例"""
        if self.ir_type == IRType.VEX:
            return VEXLifter(self.arch)
        elif self.ir_type == IRType.LLVM_IR:
            return LLVMIRLifter(self.arch)
        else:
            return VEXLifter(self.arch)
    
    def add_analysis_pass(self, pass_instance: IRAnalysisPass) -> None:
        """
        添加分析pass
        
        Args:
            pass_instance: 分析pass实例
        """
        self.analysis_passes.append(pass_instance)
        logger.info(f"添加分析pass: {pass_instance.get_name()}")
    
    def lift_binary(self, binary_path: str, function_addresses: Optional[List[int]] = None) -> LifterResult:
        """
        提升整个二进制文件
        
        Args:
            binary_path: 二进制文件路径
            function_addresses: 要提升的函数地址列表（可选）
        
        Returns:
            提升结果
        """
        if not os.path.exists(binary_path):
            return LifterResult()
                success=False,
                functions=[],
                architecture=self.arch,
                ir_type=self.ir_type,
                errors=[f"文件不存在: {binary_path}"]
            

        
        try:
            with open(binary_path, "rb") as f:
                binary_data = f.read()
            
            functions = []
            
            if function_addresses:
                for addr in function_addresses:
                    if addr < len(binary_data):
                        func_code = binary_data[addr:addr + 0x1000]  # 取4KB作为函数代码
                        func_ir = self.lifter.lift_function(func_code, addr)
                        functions.append(func_ir)
                    else:
                        logger.warning(f"地址 {hex(addr)} 超出文件范围")
            else:
                func_ir = self.lifter.lift_function(binary_data, 0x1000)
                functions.append(func_ir)
            
            # 应用分析pass
            for pass_instance in self.analysis_passes:
                functions = [pass_instance.run(func) for func in functions]
            
            return LifterResult()
                success=True,
                functions=functions,
                architecture=self.arch,
                ir_type=self.ir_type
            

        
        except Exception as e:
            logger.error(f"提升二进制失败: {e}")
            return LifterResult()
                success=False,
                functions=[],
                architecture=self.arch,
                ir_type=self.ir_type,
                errors=[str(e)]
            

    
    def lift_function(self, code: bytes, address: int, name: str = "") -> FunctionIR:
        """
        提升单个函数
        
        Args:
            code: 函数代码
            address: 函数地址
            name: 函数名
        
        Returns:
            函数IR
        """
        func_ir = self.lifter.lift_function(code, address, name)
        
        # 应用分析pass
        for pass_instance in self.analysis_passes:
            func_ir = pass_instance.run(func_ir)
        
        return func_ir
    
    def export_ir(self, function_ir: FunctionIR, output_path: str) -> bool:
        """
        导出IR到文件
        
        Args:
            function_ir: 函数IR
            output_path: 输出路径
        
        Returns:
            是否成功
        """
        try:
            with open(output_path, "w") as f:
                f.write(f"; Function: {function_ir.name} @ {hex(function_ir.address)}\n")
                f.write(f"; IR Type: {function_ir.ir_type.value}\n")
                f.write(f"; Architecture: {self.arch.value}\n")
                f.write("\n")
                
                for block in function_ir.basic_blocks:
                    f.write(f"BB_{hex(block.start_address)}:\n")
                    for instr in block.instructions:
                        operands_str = ", ".join(str(o) for o in instr.operands)
                        f.write(f"    {instr.opcode} {operands_str}")
                        if instr.comment:
                            f.write(f"  {instr.comment}")
                        f.write("\n")
                    if block.successors:
                        f.write(f"    successors: {', '.join(hex(s) for s in block.successors)}\n")
                    f.write("\n")
            
            logger.info(f"IR导出成功: {output_path}")
            return True
        except Exception as e:
            logger.error(f"导出IR失败: {e}")
            return False


class ConstantPropagationPass(IRAnalysisPass):
    """常量传播分析pass"""
    
    def run(self, function_ir: FunctionIR) -> FunctionIR:
        """运行常量传播"""
        logger.debug(f"对函数 {function_ir.name} 执行常量传播")
        return function_ir
    
    def get_name(self) -> str:
        return "ConstantPropagationPass"


class DeadCodeEliminationPass(IRAnalysisPass):
    """死代码消除pass"""
    
    def run(self, function_ir: FunctionIR) -> FunctionIR:
        """运行死代码消除"""
        logger.debug(f"对函数 {function_ir.name} 执行死代码消除")
        return function_ir
    
    def get_name(self) -> str:
        return "DeadCodeEliminationPass"


class IRTypeInferencePass(IRAnalysisPass):
    """类型推断pass"""
    
    def run(self, function_ir: FunctionIR) -> FunctionIR:
        """运行类型推断"""
        logger.debug(f"对函数 {function_ir.name} 执行类型推断")
        return function_ir
    
    def get_name(self) -> str:
        return "IRTypeInferencePass"
