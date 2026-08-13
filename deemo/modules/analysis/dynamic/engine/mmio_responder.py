"""
MMIO 仿真 responder。按外设寄存器映射生成 C 语言访问存根，
供固件仿真与硬件抽象层代码复用。
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional


class RegisterType(Enum):
    READ_ONLY = "ro"
    WRITE_ONLY = "wo"
    READ_WRITE = "rw"
    RESERVED = "reserved"


@dataclass
class RegisterSpec:
    """单个 MMIO 寄存器定义。"""
    name: str = ""
    offset: int = 0
    size: int = 4
    reg_type: RegisterType = RegisterType.READ_WRITE
    reset_value: int = 0
    read_handler: Optional[callable] = None
    write_handler: Optional[callable] = None

    def __repr__(self):
        return f"RegisterSpec({self.name}, offset=0x{self.offset:x}, size={self.size})"


@dataclass
class PeripheralSpec:
    """外设设备规格 — 寄存器映射与基址。"""
    name: str = ""
    base_address: int = 0
    registers: List[RegisterSpec] = field(default_factory=list)

    @property
    def base_addr(self) -> int:
        return self.base_address

    def register_by_name(self, name: str) -> Optional[RegisterSpec]:
        for r in self.registers:
            if r.name == name:
                return r
        return None


@dataclass
class StubResult:
    """存根生成结果。"""
    success: bool = False
    code: str = ""
    peripheral: Optional[PeripheralSpec] = None


class StubGenerator:
    """按外设规格生成 C 语言访问存根。

    输出包含寄存器偏移宏、读写辅助函数与复位初始化，
    可直接嵌入硬件抽象层代码。
    """

    @staticmethod
    def generate(peripheral: PeripheralSpec) -> str:
        lines = [
            f"/* MMIO stub for {peripheral.name} */",
            "#include <stdint.h>",
            "",
            f"#define {peripheral.name}_BASE_ADDR 0x{peripheral.base_address:x}",
            "",
        ]
        for reg in peripheral.registers:
            macro = f"{peripheral.name}_{reg.name}_OFFSET"
            lines.append(f"#define {macro} 0x{reg.offset:x}")
        lines.append("")

        if peripheral.registers:
            lines.append(f"static void {peripheral.name}_reset(void) {{")
            for reg in peripheral.registers:
                if reg.reg_type == RegisterType.RESERVED:
                    continue
                lines.append(
                    f"    *(volatile uint32_t *)({peripheral.name}_BASE_ADDR + "
                    f"{peripheral.name}_{reg.name}_OFFSET) = 0x{reg.reset_value:x};"
                )
            lines.append("}")
            lines.append("")

        lines.append(f"static uint32_t {peripheral.name}_read(uint32_t offset) {{")
        lines.append(f"    return *(volatile uint32_t *)({peripheral.name}_BASE_ADDR + offset);")
        lines.append("}")
        lines.append("")

        lines.append(f"static void {peripheral.name}_write(uint32_t offset, uint32_t value) {{")
        lines.append(f"    *(volatile uint32_t *)({peripheral.name}_BASE_ADDR + offset) = value;")
        lines.append("}")
        lines.append("")
        return "\n".join(lines)


class MMIOResponder:
    """Stateful MMIO device 仿真器 钩子-based 读取/写入 handling"""

    def __init__(self):
        self.peripherals: Dict[str, PeripheralSpec] = {}

    def define_peripheral(self, spec: PeripheralSpec) -> None:
        """注册一个外设规格。"""
        self.peripherals[spec.name] = spec

    def run(self, name: str) -> StubResult:
        """为指定外设生成 C 存根。"""
        spec = self.peripherals.get(name)
        if spec is None:
            return StubResult(success=False, code="", peripheral=None)
        code = StubGenerator.generate(spec)
        return StubResult(success=True, code=code, peripheral=spec)


def create_mmio_responder(registers: Optional[List[dict]] = None,
                          base: int = 0x40000000) -> MMIOResponder:
    """便捷工厂：构造带默认外设的 responder。"""
    responder = MMIOResponder()
    regs = []
    if registers:
        for r in registers:
            regs.append(RegisterSpec(
                name=r.get("name", "UNK"),
                offset=r.get("offset", 0),
                size=r.get("size", 4),
                reg_type=r.get("type", RegisterType.READ_WRITE),
                reset_value=r.get("reset", 0)))
    spec = PeripheralSpec(name="custom", base_address=base, registers=regs)
    responder.define_peripheral(spec)
    return responder
