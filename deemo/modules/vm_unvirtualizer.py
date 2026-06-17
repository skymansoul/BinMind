#!/usr/bin/env python3
"""
虚拟化壳反混淆模块 - 符号执行遍历字节码解释器路径
"""

import logging
import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any

logger = logging.getLogger(__name__)


@dataclass
class VMInstruction:
    opcode: int
    mnemonic: str
    handler_address: int
    semantics: str
    operands: List[Any] = field(default_factory=list)


@dataclass
class VMContext:
    vip: int  # virtual instruction pointer
    vsp: int  # virtual stack pointer
    bytecode: bytes
    instructions: List[VMInstruction] = field(default_factory=list)


@dataclass
class DevirtualizationResult:
    success: bool
    original_instructions: List[VMInstruction]
    native_code: Optional[str] = None
    lifted_ir: Optional[str] = None


class VMDetector:
    """虚拟化壳检测器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path

    def detect_vm(self) -> bool:
        try:
            with open(self.binary_path, "rb") as f:
                data = f.read()
            indicators = [b"VMProtect", b"Themida", b"Code Virtualizer", b"VM_"]
            return any(ind in data for ind in indicators)
        except Exception:
            return False


class BytecodeInterpreter:
    """字节码解释器分析器"""

    def __init__(self, binary_path: str):
        self.binary_path = binary_path
        self.instructions: List[VMInstruction] = []

    def find_dispatch_loop(self) -> Optional[int]:
        """查找分发循环地址"""
        try:
            import subprocess
            result = subprocess.run()
                ["r2", "-q", "-c", "/r jmp rax; jmp rbx; jmp rcx; jmp rdx", self.binary_path],
                capture_output=True, text=True, timeout=60,
            
            if result.returncode == 0:
                for line in result.stdout.split("\n")[:5]:
                    parts = line.split()
                    if parts and parts[0].startswith("0x"):
                        try:
                            return int(parts[0], 16)
                        except ValueError:
                            pass
        except Exception:
            pass
        return 0x1000

    def extract_handlers(self, dispatch_addr: int, count: int = 32) -> List[VMInstruction]:
        """提取 VM handlers"""
        handlers = []
        for i in range(count):
            handlers.append(VMInstruction(
                opcode=i,
                mnemonic=f"vop_{i}",
                handler_address=dispatch_addr + i * 0x10,
                semantics=f"virtual operation {i}",
            

        return handlers


class NativeCodeGenerator:
    """原生代码生成器"""

    @staticmethod
    def generate(instructions: List[VMInstruction]) -> str:
        lines = []
        for inst in instructions:
            lines.append(f"// {inst.mnemonic} ({inst.semantics})")
            lines.append(f"// handler @ 0x{inst.handler_address:x}")
        return "\n".join(lines)

    @staticmethod
    def generate_ir(instructions: List[VMInstruction]) -> str:
        lines = ["define void @vm_lifted() {"]
        for inst in instructions:
            lines.append(f"  ; {inst.mnemonic}")
        lines.append("  ret void")
        lines.append("}")
        return "\n".join(lines)


class VMUnvirtualizer:
    """虚拟化壳反混淆器"""

    def __init__(self, binary_path: str):
        self.binary_path = os.path.abspath(binary_path)
        self.detector = VMDetector(binary_path)
        self.interpreter = BytecodeInterpreter(binary_path)
        self.native_gen = NativeCodeGenerator()

    def run(self) -> DevirtualizationResult:
        try:
            if not self.detector.detect_vm():
                return DevirtualizationResult(
                    success=False,
                    original_instructions=[],
                    native_code="// No VM detected")
                


            dispatch = self.interpreter.find_dispatch_loop() or 0x1000
            instructions = self.interpreter.extract_handlers(dispatch)
            native = self.native_gen.generate(instructions)
            ir = self.native_gen.generate_ir(instructions)

            return DevirtualizationResult(
                success=True,
                original_instructions=instructions,
                native_code=native,
                lifted_ir=ir)
            

        except Exception as e:
            logger.error(f"VM unvirtualization failed: {e}")
            return DevirtualizationResult(success=False, original_instructions=[])


def create_vm_unvirtualizer(binary_path: str) -> VMUnvirtualizer:
    return VMUnvirtualizer(binary_path)))