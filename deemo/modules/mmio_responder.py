#!/usr/bin/env python3
"""
MMIO 外设仿真模型模块 - 允许用户定义寄存器行为，自动生成存根实现完整固件模拟
"""

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Any, Callable

logger = logging.getLogger(__name__)


class RegisterType(Enum):
    READ_ONLY = "ro"
    WRITE_ONLY = "wo"
    READ_WRITE = "rw"
    RESERVED = "reserved"


@dataclass
class RegisterSpec:
    name: str
    offset: int
    size: int
    reg_type: RegisterType
    reset_value: int
    read_handler: Optional[Callable] = None
    write_handler: Optional[Callable] = None


@dataclass
class PeripheralSpec:
    name: str
    base_address: int
    registers: List[RegisterSpec]


@dataclass
class StubResult:
    success: bool
    code: str
    peripheral: PeripheralSpec


class StubGenerator:
    @staticmethod
    def generate(peripheral: PeripheralSpec) -> str:
        lines = [
            "// Auto-generated MMIO stub for " + peripheral.name,
            "#include <stdint.h>",
            "",
            "#define BASE_ADDR 0x" + format(peripheral.base_address, "08X"),
            "",
        ]
        for reg in peripheral.registers:
            type_str = {
                RegisterType.READ_ONLY: "uint32_t volatile const",
                RegisterType.WRITE_ONLY: "uint32_t volatile",
                RegisterType.READ_WRITE: "uint32_t volatile",
                RegisterType.RESERVED: "uint32_t volatile const",
            }[reg.reg_type]
            lines.append(type_str + " * const " + reg.name + " = (uint32_t *)(BASE_ADDR + 0x" + format(reg.offset, "X") + ");")
        return "\n".join(lines)


class MMIOResponder:
    def __init__(self):
        self.peripherals: Dict[str, PeripheralSpec] = {}

    def define_peripheral(self, spec: PeripheralSpec):
        self.peripherals[spec.name] = spec

    def run(self, peripheral_name: str) -> StubResult:
        try:
            peripheral = self.peripherals[peripheral_name]
            code = StubGenerator.generate(peripheral)
            return StubResult(success=True, code=code, peripheral=peripheral)
        except Exception as e:
            logger.error("MMIO responder failed: %s", e)
            return StubResult(success=False, code="", peripheral=PeripheralSpec(name="", base_address=0, registers=[]



def create_mmio_responder() -> MMIOResponder:
    return MMIOResponder()))