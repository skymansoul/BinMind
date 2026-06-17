"""
自定义指令集模拟器插件接口模块

功能:
    1. 提供标准插件接口, 允许用户为专有架构 (DSP/MCU) 实现 Unicorn CPU 绑定和外设模型
    2. 无需修改核心代码即可扩展裸机固件模拟能力

核心技术:
    - 抽象基类: CustomCPUBackend, PeripheralModel
    - 注册表 (Registry) 模式
    - 动态加载: importlib
    - 协议: step() / map_memory() / interrupt()
"""

import logging
import os
import json
import importlib
import importlib.util
import threading
from typing import Dict, Any, List, Optional, Callable, Set
from dataclasses import dataclass, field
from enum import Enum
from abc import ABC, abstractmethod
from collections import defaultdict

logger = logging.getLogger(__name__)

try:
    from unicorn import Uc, UC_ARCH_ARM, UC_ARCH_MIPS, UC_ARCH_RISCV, UC_ARCH_X86
    from unicorn.arm_const import UC_MODE_ARM, UC_MODE_THUMB
    from unicorn.x86_const import UC_MODE_32, UC_MODE_64
    UNICORN_AVAILABLE = True
except ImportError:
    UNICORN_AVAILABLE = False


class CPUArch(Enum):
    ARM = "arm"
    ARM64 = "arm64"
    MIPS = "mips"
    MIPS64 = "mips64"
    RISCV32 = "riscv32"
    RISCV64 = "riscv64"
    X86 = "x86"
    X86_64 = "x86_64"
    CUSTOM = "custom"


@dataclass
class PeripheralSpec:
    """外设规格"""
    name: str
    base_addr: int
    size: int
    description: str = ""
    registers: Dict[str, int] = field(default_factory=dict)
    interrupt_lines: List[int] = field(default_factory=list)


class CustomCPUBackend(ABC):
    """自定义 CPU 后端抽象基类"""

    NAME = "custom"
    ARCH = CPUArch.CUSTOM

    @abstractmethod
    def step(self, uc: Any, count: int = 1) -> int:
        """执行 count 条指令"""
        ...

    @abstractmethod
    def map_memory(self, uc: Any, base: int, size: int) -> None:
        """映射内存"""
        ...

    @abstractmethod
    def get_register_file(self) -> Dict[str, int]:
        """获取寄存器组"""
        ...


class CustomPeripheral(ABC):
    """自定义外设抽象基类"""

    @abstractmethod
    def name(self) -> str:
        ...

    @abstractmethod
    def base_addr(self) -> int:
        ...

    @abstractmethod
    def size(self) -> int:
        ...

    @abstractmethod
    def read(self, offset: int, size: int) -> int:
        ...

    @abstractmethod
    def write(self, offset: int, size: int, value: int) -> None:
        ...

    def tick(self, cycles: int) -> List[int]:
        """外设时钟 tick, 返回需要触发的 IRQ 列表"""
        return []


class ARMCortexMBackend(CustomCPUBackend):
    """ARM Cortex-M 后端 (参考实现)"""

    NAME = "arm_cortex_m"
    ARCH = CPUArch.ARM

    def __init__(self):
        self.regs: Dict[str, int] = {f"r{i}": 0 for i in range(13)}
        self.regs.update({"sp": 0, "lr": 0, "pc": 0, "xpsr": 0})

    def step(self, uc, count: int = 1) -> int:
        if not UNICORN_AVAILABLE or uc is None:
            return 0
        try:
            uc.emu_start(self.regs["pc"], 0, count=count)
            self.regs["pc"] = uc.reg_read(UC_MIPS_PC) if False else self.regs["pc"]
        except Exception as e:
            logger.warning(f"ARM 步进失败: {e}")
            return 0
        return count

    def map_memory(self, uc, base: int, size: int) -> None:
        if not UNICORN_AVAILABLE or uc is None:
            return
        try:
            uc.mem_map(base, size)
        except Exception as e:
            logger.warning(f"映射失败: {e}")

    def get_register_file(self) -> Dict[str, int]:
        return dict(self.regs)


class GPIOEmulator(CustomPeripheral):
    """GPIO 外设模拟器 (参考实现)"""

    def __init__(self, base: int = 0x40020000, size: int = 0x400):
        self._base = base
        self._size = size
        self._regs: Dict[int, int] = {
            0x00: 0,    # MODER
            0x04: 0,    # OTYPER
            0x08: 0,    # OSPEEDR
            0x0C: 0,    # PUPDR
            0x10: 0,    # IDR
            0x14: 0,    # ODR
        }
        self._irqs: List[int] = []

    def name(self) -> str:
        return "GPIO"

    def base_addr(self) -> int:
        return self._base

    def size(self) -> int:
        return self._size

    def read(self, offset: int, size: int) -> int:
        return self._regs.get(offset, 0)

    def write(self, offset: int, size: int, value: int) -> None:
        self._regs[offset] = value & ((1 << (size * 8)) - 1)
        # 简化: 写入 ODR 时检测外部中断
        if offset == 0x14 and (value & 0x1):
            self._irqs.append(5)  # EXTI0

    def tick(self, cycles: int) -> List[int]:
        irqs = list(self._irqs)
        self._irqs.clear()
        return irqs


class PluginRegistry:
    """插件注册表"""

    def __init__(self):
        self.cpu_backends: Dict[str, type] = {}
        self.peripherals: Dict[str, type] = {}
        self._lock = threading.Lock()

    def register_cpu(self, name: str, cls: type):
        with self._lock:
            self.cpu_backends[name] = cls
        logger.info(f"[isa] 注册 CPU 后端: {name}")

    def register_peripheral(self, name: str, cls: type):
        with self._lock:
            self.peripherals[name] = cls
        logger.info(f"[isa] 注册外设: {name}")

    def get_cpu(self, name: str) -> Optional[type]:
        return self.cpu_backends.get(name)

    def get_peripheral(self, name: str) -> Optional[type]:
        return self.peripherals.get(name)

    def list_cpu(self) -> List[str]:
        return list(self.cpu_backends.keys())

    def list_peripheral(self) -> List[str]:
        return list(self.peripherals.keys())


GLOBAL_REGISTRY = PluginRegistry()


def register_cpu(name: str, cls: type):
    GLOBAL_REGISTRY.register_cpu(name, cls)


def register_peripheral(name: str, cls: type):
    GLOBAL_REGISTRY.register_peripheral(name, cls)


def load_plugin_module(path: str) -> List[str]:
    """从 .py 文件加载插件, 返回注册的名称列表"""
    names: List[str] = []
    try:
        spec = importlib.util.spec_from_file_location(
            f"isa_plugin_{os.path.basename(path)}", path
        )
        if not spec or not spec.loader:
            return names
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        # 约定: 模块提供 register(registry) 函数
        if hasattr(module, "register"):
            module.register(GLOBAL_REGISTRY)
        # 或模块顶层直接调用 register_cpu/register_peripheral
        names = list(GLOBAL_REGISTRY.cpu_backends.keys()) + \
                list(GLOBAL_REGISTRY.peripherals.keys())
    except Exception as e:
        logger.warning(f"加载 ISA 插件失败 {path}: {e}")
    return names


def build_emulator(arch: str, cpu_name: Optional[str] = None,
                   peripherals: Optional[List[str]] = None) -> Dict[str, Any]:
    """构建模拟器实例"""
    cpu_cls = GLOBAL_REGISTRY.get_cpu(cpu_name or arch)
    if cpu_cls is None:
        return {'error': f'cpu {cpu_name or arch} not found',
                'available_cpus': GLOBAL_REGISTRY.list_cpu()}

    backend = cpu_cls()
    periph_instances: List[CustomPeripheral] = []
    for p in (peripherals or []):
        pcls = GLOBAL_REGISTRY.get_peripheral(p)
        if pcls:
            periph_instances.append(pcls())
    return {
        'success': True,
        'cpu_backend': backend.NAME,
        'arch': backend.ARCH.value,
        'peripherals': [p.name() for p in periph_instances]
    }


# ============= 默认注册 =============
register_cpu("arm_cortex_m", ARMCortexMBackend)
register_peripheral("gpio", GPIOEmulator)
